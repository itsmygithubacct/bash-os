#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Time the rsync builtin against stock rsync on fixed push workloads.

Each case resets its destination before every pass and runs the same
arguments through the builtin and through stock rsync (absolute path) from
one bash-os shell with an empty PATH. Before any timing, a validation phase
drives every pass from a persistent shell and compares the complete
destination tree (type, mode, size, SHA-256, mtime) with the expected one
after each pass; a case whose builtin or reference output differs gets no
timing. Timed batches then check every pass's exit status, have each reset
assert the previous pass left the expected entry type, and compare the
final tree once more.

The binary needs the rsync, rm and mkdir builtins (resets use them).

Usage: bench/opus-rsync.py --binary out/bash-NAME --output report.json
       [--runs 7] [--passes N] [--cpu N] [--only CASE,...]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
STOCK = shutil.which('rsync', path='/usr/bin:/bin')
TEXT = 423000
MTIME = 1_000_000_000


def cases():
    rows = []

    def add(label, args, reset, check, expect, work, passes=11):
        rows.append(dict(id=label, args=args, reset=reset, check=check,
                         expect=expect, work=work, passes=passes))

    # The historical case, unchanged: trailing-slash DEST into a recreated dir.
    add('rsync-rsh-shim', ['-a', '-e', './rshshim', 'text', ':rdest/'],
        'rm -rf rdest; mkdir rdest', '[[ -f rdest/text ]]', {'rdest': 'd', 'rdest/text': 'text'},
        'one 423000 B file through the rsh shim into a freshly emptied directory, DEST written with a trailing slash')
    add('rsync-rsh-file-to-dir', ['-a', '-e', './rshshim', 'text', ':rdest'],
        'rm -rf rdest; mkdir rdest', '[[ -f rdest/text ]]', {'rdest': 'd', 'rdest/text': 'text'},
        'one 423000 B file through the rsh shim into an existing, freshly emptied directory named without a slash (the builtin probes DEST)')
    add('rsync-rsh-file-to-file', ['-a', '-e', './rshshim', 'text', ':rout'],
        'rm -rf rout', '[[ -f rout ]]', {'rout': 'text'},
        'one 423000 B file through the rsh shim to a nonexistent DEST, which becomes a file')
    add('rsync-local-file-to-file', ['-a', 'text', 'lout'],
        'rm -rf lout', '[[ -f lout ]]', {'lout': 'text'},
        'one 423000 B local copy to a nonexistent DEST, which becomes a file')
    add('rsync-local-file-to-dir', ['-a', 'text', 'ldest'],
        'rm -rf ldest; mkdir ldest', '[[ -f ldest/text ]]', {'ldest': 'd', 'ldest/text': 'text'},
        'one 423000 B local copy into an existing, freshly emptied directory')
    add('rsync-local-big-file-to-file', ['-a', 'big', 'lbig'],
        'rm -rf lbig', '[[ -f lbig ]]', {'lbig': 'big'},
        'one 16777216 B local copy to a nonexistent DEST, which becomes a file')
    add('rsync-local-tree', ['-a', 'tree/', 'ltree'],
        'rm -rf ltree', '[[ -f ltree/d7/f24 ]]', None,
        'a local -a copy of 200 files of 2048 B in 8 directories (+ the top directory) into a nonexistent DEST')
    return rows


def fixtures(root):
    rng = hashlib.sha256(b'opus-rsync-bench')
    text = b''.join(b'line %06d %s\n' % (i, rng.hexdigest()[:i % 40].encode()) for i in range(20000))
    text = (text * (TEXT // len(text) + 1))[:TEXT]
    (root/'text').write_bytes(text)
    block = bytes(range(256)) * 4096
    (root/'big').write_bytes(block * 16)
    for d in range(8):
        for f in range(25):
            p = root/'tree'/('d%d' % d)/('f%02d' % f)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(hashlib.sha256(b'%d/%d' % (d, f)).digest() * 64)
            os.utime(p, (MTIME + d * 100 + f,) * 2)
    for d in range(8):
        os.utime(root/'tree'/('d%d' % d), (MTIME + 5000 + d,) * 2)
    os.utime(root/'tree', (MTIME + 6000,) * 2)
    for name in ('text', 'big'):
        os.chmod(root/name, 0o644)
        os.utime(root/name, (MTIME,) * 2)
    sh = shutil.which('sh', path='/usr/bin:/bin')
    (root/'rshshim').write_text('#!%s\nexec %s -c "PATH=/usr/bin:/bin; $*"\n' % (sh, sh))
    os.chmod(root/'rshshim', 0o755)
    return {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('text', 'big', 'rshshim')}


def tree(root, top):
    out = {}
    base = root/top
    if not base.exists() and not base.is_symlink():
        return None
    entries = [base] + sorted(base.rglob('*')) if base.is_dir() else [base]
    for p in entries:
        st = os.lstat(p)
        rel = str(p.relative_to(root))
        if p.is_dir():
            out[rel] = ('d', oct(st.st_mode & 0o7777), int(st.st_mtime) if rel != top else None)
        else:
            out[rel] = ('f', oct(st.st_mode & 0o7777), st.st_size,
                        hashlib.sha256(p.read_bytes()).hexdigest(), int(st.st_mtime))
    return out


def expected_tree(root, case):
    top = case['args'][-1].lstrip(':').rstrip('/')
    if case['expect'] is None:
        src = tree(root, 'tree')
        return top, {top + k[len('tree'):]: v for k, v in src.items()} | {top: ('d', oct(0o755), None)}
    out = {}
    for rel, kind in case['expect'].items():
        if kind == 'd':
            out[rel] = ('d', oct(0o755), None)
        else:
            st = os.stat(root/kind)
            out[rel] = ('f', oct(st.st_mode & 0o7777), st.st_size,
                        hashlib.sha256((root/kind).read_bytes()).hexdigest(), int(st.st_mtime))
    return top, out


def normalize_top(t, top, case):
    # The top directory's own mtime is the pass's wall time for a recreated
    # destination, except for SRC/ copies, which give it the source's.
    if t and top in t and case['expect'] is None:
        t[top] = ('d', t[top][1], None)
    return t


class Shell:
    def __init__(self, binary, root, env):
        self.p = subprocess.Popen([str(binary), '--norc', '--noprofile'], cwd=root, env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def run(self, line):
        self.p.stdin.write(('%s; echo "__RC__ $?"\n' % line).encode())
        self.p.stdin.flush()
        while True:
            s = self.p.stdout.readline().decode()
            if not s:
                raise RuntimeError('shell exited')
            if s.startswith('__RC__ '):
                return int(s.split()[1])

    def close(self):
        self.p.stdin.close()
        self.p.wait()
        return self.p.stderr.read().decode(errors='replace')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--runs', type=int, default=7)
    ap.add_argument('--passes', type=int)
    ap.add_argument('--cpu', type=int)
    ap.add_argument('--only')
    ap.add_argument('--load', type=Path, help='enable -f this rsync object first (e.g. a baseline build)')
    a = ap.parse_args()
    binary = a.binary.resolve(strict=True)
    if a.cpu is not None:
        os.sched_setaffinity(0, {a.cpu})
    env = {'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}
    load = a.load.resolve(strict=True) if a.load else None
    prelude = 'enable -f %s rsync || exit 93; ' % shlex.quote(str(load)) if load else ''
    inventory = cases()
    if a.only:
        wanted = set(a.only.split(','))
        inventory = [c for c in inventory if c['id'] in wanted]
    report = {
        'schema': 1, 'harness': 'bench/opus-rsync.py',
        'date': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--', 'loadables/rsync.c'],
                                                     cwd=ROOT, text=True).strip()),
        'rsync_c_sha256': hashlib.sha256((ROOT/'loadables/rsync.c').read_bytes()).hexdigest(),
        'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'load': str(load) if load else None,
        'load_sha256': hashlib.sha256(load.read_bytes()).hexdigest() if load else None,
        'stock': STOCK, 'stock_version': subprocess.check_output([STOCK, '--version'], text=True).splitlines()[0],
        'kernel': platform.release(), 'architecture': platform.machine(),
        'cpus': sorted(os.sched_getaffinity(0)), 'load_average_start': os.getloadavg(),
        'runs': a.runs, 'umask': '022',
        'method': ('one bash-os shell per batch, PATH empty, builtin vs absolute stock rsync; reset before '
                   'every pass inside the timed loop; wall time of the whole batch; warm cache'),
        'cases': [],
    }
    for line in Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('model name'):
            report['cpu_model'] = line.split(':', 1)[1].strip()
            break
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix='opus-rsync-bench.') as directory:
        root = Path(directory)
        report['fixtures'] = fixtures(root)
        for case in inventory:
            row = {k: case[k] for k in ('id', 'args', 'reset', 'work')}
            top, want = expected_tree(root, case)
            commands = {'bashos': 'rsync', 'external': STOCK}
            results = {}
            # validation: every pass checked, in one persistent shell
            for label, prog in commands.items():
                sh = Shell(binary, root, env)
                if prelude:
                    sh.run(prelude.rstrip('; '))
                bad = None
                for i in range(case['passes']):
                    rc = sh.run('{ %s; } && %s %s' % (case['reset'], prog, ' '.join(shlex.quote(x) for x in case['args'])))
                    got = normalize_top(tree(root, top), top, case)
                    if rc != 0 or got != want:
                        bad = {'status': 'mismatch', 'pass': i, 'returncode': rc,
                               'expected': want if len(json.dumps(want)) < 4000 else 'large',
                               'actual': got if len(json.dumps(got)) < 4000 else 'large'}
                        break
                err = sh.close()
                results[label] = bad or {'status': 'validated', 'validated_passes': case['passes']}
                if err:
                    results[label]['stderr'] = err[:1000]
            row['results'] = results
            accepted = [l for l, r in results.items() if r['status'] == 'validated']
            passes = a.passes or case['passes']
            row['passes'] = passes
            samples = {l: [] for l in accepted}
            for r in range(a.runs + 1):            # round 0 is the warm-up
                order = accepted if r % 2 == 0 else accepted[::-1]
                for label in order:
                    step = ('{ %s; } || exit 90; %s %s || exit 91; %s || exit 92'
                            % (case['reset'], commands[label], ' '.join(shlex.quote(x) for x in case['args']),
                               case['check']))
                    script = prelude + 'for ((i=0;i<%d;i++)); do %s; done' % (passes, step)
                    start = time.perf_counter_ns()
                    p = subprocess.run([str(binary), '--norc', '--noprofile', '-c', script], cwd=root,
                                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
                    ms = (time.perf_counter_ns() - start) / 1e6
                    got = normalize_top(tree(root, top), top, case)
                    if p.returncode or got != want:
                        results[label] = {'status': 'timed-mismatch', 'returncode': p.returncode,
                                          'stderr': p.stderr.decode(errors='replace')[:1000]}
                        accepted = [x for x in accepted if x != label]
                        samples.pop(label, None)
                        continue
                    if r:
                        samples[label].append(round(ms, 3))
            for label, values in samples.items():
                if len(values) == a.runs:
                    results[label] = {'status': 'ok', 'validated_passes': case['passes'],
                                      'median_ms': round(statistics.median(values), 3),
                                      'min_ms': min(values), 'max_ms': max(values), 'runs_ms': values,
                                      'per_pass_ms': round(statistics.median(values) / passes, 3)}
            if all(results.get(l, {}).get('status') == 'ok' for l in commands):
                row['bashos_over_external'] = round(results['bashos']['median_ms'] / results['external']['median_ms'], 3)
            report['cases'].append(row)
            a.output.write_text(json.dumps(report, indent=2) + '\n')
            print(case['id'], {l: r.get('median_ms', r['status']) for l, r in results.items()},
                  row.get('bashos_over_external'), flush=True)
    report['load_average_end'] = os.getloadavg()
    a.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
