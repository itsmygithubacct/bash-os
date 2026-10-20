#!/usr/bin/env python3
"""Validated zstd streaming timings. Run builds separately, then use the bench gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
REF = '/usr/bin/zstd'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--historical', action='store_true')
    p.add_argument('--source', type=Path, default=ROOT/'loadables/zstd.c')
    p.add_argument('--rusage-bin', type=Path, default=ROOT/'out/sol-zstd-rusage')
    a = p.parse_args()
    binary = a.binary.resolve(strict=True)
    rusage = a.rusage_bin.resolve(strict=True)
    env = dict(PATH='', LC_ALL='C', TZ='UTC')
    report = dict(binary_sha256=digest(binary), source_sha256=digest(a.source),
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                  working_tree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'])),
                  source_snapshot=a.source.name, benchmark_sha256=digest(Path(__file__)),
                  affinity=sorted(os.sched_getaffinity(0)), kernel=platform.release(),
                  cpu=next(x.split(':', 1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
                  date=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  load_start=os.getloadavg(), environment=env, samples=7,
                  method='Warm cache; same bash shell with empty PATH; each pass writes a separate output, validated after timing; one warmup batch. Native launcher wait4 peak RSS is maximum command/descendant RSS, not aggregate simultaneous RSS. The launcher execs before forking the measured shell and reports the child usage, excluding its own inherited fixture-generator RSS high-water mark. Wall includes shell startup and redirections; named output includes metadata/atomic publication. No fsync/cold-cache claim.',
                  versions={}, fixtures={}, cases=[])
    for name, cmd in [('bash', [str(binary), '--version']), ('zstd', [REF, '--version']), ('cc', ['cc', '--version'])]:
        report['versions'][name] = subprocess.check_output(cmd, text=True).splitlines()[0]
    report['linked_libraries'] = subprocess.check_output(['ldd', str(binary)], text=True)
    report['reference_sha256'] = digest(Path(REF))
    report['rss_launcher'] = dict(binary=rusage.name, sha256=digest(rusage), source_sha256=digest(ROOT/'bench/sol-zstd-rusage.c'))
    with tempfile.TemporaryDirectory(prefix='sol-zstd-bench-') as directory:
        root = Path(directory)
        # Exact zstd catalog fixtures, without unrelated hardware/xattr setup.
        rng = random.Random(20260908)
        words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
        text = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n'
                       for _ in range(12000)).encode()[:423000]
        (root/'text').write_bytes(text)
        (root/'blob').write_bytes(bytes(range(256))*4096)
        # Fixed 32 MiB work unit, seeded text/catalog blob repeated together.
        block = (root/'text').read_bytes() + (root/'blob').read_bytes()[:65536]
        with (root/'large').open('wb') as f:
            size = 32 * 1024**2
            while size:
                piece = block[:size]
                f.write(piece)
                size -= len(piece)
        for name in ['text', 'blob', 'large']:
            file = root/name
            report['fixtures'][name] = dict(bytes=file.stat().st_size, sha256=digest(file))
            with file.open('rb') as source, (root/(name+'.zst')).open('wb') as out:
                subprocess.run([REF, '-q', '-3', '-c', '-'], stdin=source, stdout=out, check=True)
            report['fixtures'][name+'.zst'] = dict(bytes=(root/(name+'.zst')).stat().st_size, sha256=digest(root/(name+'.zst')), producer='host zstd -q -3 -c - (stdin)')
        cases = []
        if a.historical:
            for mode in ['compress', 'decompress']:
                for name in ['text', 'blob']:
                    cases.append((mode, name, 3, 'stdin'))
        else:
            for level in [1, 3, 19]:
                for name in ['text', 'large']:
                    for path in ['stdin', 'named']:
                        cases.append(('compress', name, level, path))
            for name in ['text', 'large']:
                for path in ['stdin', 'named']:
                    cases.append(('decompress', name, 3, path))
            cases += [('compress', 'blob', 3, 'stdin'), ('decompress', 'blob', 3, 'stdin')]
        for mode, name, level, path in cases:
            count = 1 if name == 'large' else 8
            fixture = name + ('.zst' if mode == 'decompress' else '')
            row = dict(id=f'{mode}-{name}-{level}-{path}', mode=mode, level=level, path=path,
                       fixture=fixture, work_unit=f'{count} calls x {report["fixtures"][name]["bytes"]} original bytes',
                       passes=count, results={})
            report['cases'].append(row)
            for round_no in range(8):
                labels = ['builtin', 'external'] if round_no % 2 == 0 else ['external', 'builtin']
                for label in labels:
                    for out in root.glob('pass-*'):
                        out.unlink()
                    command = ['zstd' if label == 'builtin' else REF, '-q']
                    command += ['-d'] if mode == 'decompress' else [f'-{level}']
                    script = 'n=$1; input=$2; shift 2; for ((i=0;i<n;i++)); do '
                    if path == 'stdin':
                        command += ['-c', '-']
                        script += '"$@" < "$input" > "pass-$i" || exit; '
                    else:
                        script += '"$@" -f -o "pass-$i" "$input" || exit; '
                    script += 'done'
                    argv = [str(binary), '--noprofile', '--norc', '-c', script, '_', str(count), fixture, *command]
                    with (root/'stderr').open('wb') as err:
                        started = time.perf_counter_ns()
                        proc = subprocess.run([str(rusage), str(root/'rss'), *argv],
                                              cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=err)
                        elapsed = (time.perf_counter_ns() - started) / 1e6
                        rss = int((root/'rss').read_text().strip())
                    assert proc.returncode == 0, (row['id'], label, proc.returncode, (root/'stderr').read_text())
                    frame_bytes = []
                    for i in range(count):
                        output = root/f'pass-{i}'
                        if mode == 'compress':
                            frame_bytes.append(output.stat().st_size)
                            with (root/'decoded').open('wb') as decoded:
                                subprocess.run([REF, '-q', '-d', '-c', str(output)], stdout=decoded, check=True)
                            output = root/'decoded'
                        assert output.stat().st_size == report['fixtures'][name]['bytes']
                        assert digest(output) == report['fixtures'][name]['sha256'], (row['id'], label, i)
                    result = row['results'].setdefault(label, dict(status='ok', warmup_validated_passes=0, validation_passes=0, samples_ms=[], peak_rss_kib=[], frame_bytes=frame_bytes, argv=argv[2:]))
                    if round_no == 0:
                        result['warmup_validated_passes'] = count
                    else:
                        result['validation_passes'] += count
                        result['samples_ms'].append(elapsed)
                        result['peak_rss_kib'].append(rss)
                    a.output.write_text(json.dumps(report, indent=2)+'\n')
            for result in row['results'].values():
                result['median_ms'] = statistics.median(result['samples_ms'])
                result['max_rss_kib'] = max(result['peak_rss_kib'])
            row['builtin_over_external'] = row['results']['builtin']['median_ms'] / row['results']['external']['median_ms']
            print(row['id'], {k: (round(v['median_ms'], 3), v['max_rss_kib']) for k, v in row['results'].items()}, flush=True)
        report['load_end'] = os.getloadavg()
        a.output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
