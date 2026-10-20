#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validated diff workloads. Run through the campaign bench gate; never builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import select
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixtures():
    rng = random.Random(20260908)
    words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
    text = ''.join(' '.join(rng.choice(words) for _ in range(10)) + '\n'
                   for _ in range(12000)).encode()[:423000]
    yield 'historical-identical', text, text, [], 24
    records = [f'line {i:06d} unique content\n'.encode() for i in range(12000)]
    other = records.copy()
    for i in (100, 6000, 11900):
        other[i] = f'replaced {i}\n'.encode()
    for opts in ([], ['-u'], ['-q']):
        yield 'sparse' + ''.join(opts), b''.join(records), b''.join(other), opts, 12
    yield 'long-lines', b'x' * 1048576 + b'old\n', b'x' * 1048576 + b'new\n', [], 4
    for n in (250, 500, 1000, 2000):
        a = b''.join(f'old {i:06d}\n'.encode() for i in range(n))
        b = b''.join(f'new {i:06d}\n'.encode() for i in range(n))
        yield f'all-changed-{n}', a, b, [], 3
    yield 'all-changed-quiet', a, b, ['-q'], 3
    # Output cost isolated from high edit distance: every line differs only in case.
    yield 'case-equal', b'UPPER content\n' * 40000, b'upper content\n' * 40000, ['-i'], 6
    yield 'large-output', b'', b'new record\n' * 2000, [], 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', action='append', required=True, help='LABEL=PATH')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', type=Path, default=ROOT / 'loadables/diff.c')
    parser.add_argument('--source-for', action='append', default=[], help='LABEL=SOURCE, for paired builds')
    parser.add_argument('--only', help='comma-separated workload names')
    parser.add_argument('--profile', action='store_true')
    parser.add_argument('--profile-fixture', action='append', default=[], help='LABEL=MODULE, counters only')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('choose a new output path to preserve previous reports')
    affinity = sorted(os.sched_getaffinity(0))
    assert len(affinity) == 1, 'pin the process with taskset or the bench gate'
    binaries = {label: str(Path(path).resolve()) for label, path in
                (arg.split('=', 1) for arg in args.binary)}
    if 'GNU' in binaries:
        parser.error('GNU is reserved for the external reference')
    sources = dict(arg.split('=', 1) for arg in args.source_for)
    shell = next(iter(binaries.values()))
    implementations = {**binaries, 'GNU': shell}
    env = {**os.environ, 'LC_ALL': 'C', 'PATH': ''}
    env.pop('BASH_ENV', None)
    report = dict(cpu_affinity=affinity, platform=platform.platform(),
                  harness_sha256=sha(Path(__file__).read_bytes()),
                  python_version=platform.python_version(),
                  environment={'PATH': '', 'LC_ALL': 'C', 'BASH_ENV': 'removed',
                               'TZ': os.environ.get('TZ'),
                               'reset': 'immutable fixture bytes; output truncated before each batch'},
                  external_reference={'path': '/usr/bin/diff', 'sha256': sha(Path('/usr/bin/diff').read_bytes())},
                  memory_metric='Linux shell VmHWM; excludes external GNU child; wait4 RSS may inherit parent high-water floor',
                  timed_work='shell startup, comparison loop, per-pass framing, regular-file output, final shell VmHWM read; validation outside timer',
                  cpu_model=next(line.split(':', 1)[1].strip() for line in
                                 Path('/proc/cpuinfo').read_text().splitlines()
                                 if line.startswith('model name')),
                  source_sha256=sha(args.source.read_bytes()),
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
                  binaries={k: dict(path=v, sha256=sha(Path(v).read_bytes()),
                                    source_sha256=sha(Path(sources.get(k, args.source)).read_bytes()))
                            for k, v in binaries.items()},
                  versions={k: subprocess.check_output([v, '--version']).decode().splitlines()[0]
                            for k, v in {**binaries, 'GNU diff': '/usr/bin/diff', 'cc': '/usr/bin/cc'}.items()},
                  load_start=os.getloadavg(), samples=7, warmups=1, cases=[])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sol-diff-', dir=args.output.parent) as tmp:
        directory = Path(tmp)
        for name, a, b, opts, passes in fixtures():
            if args.only and name not in args.only.split(','):
                continue
            (directory / 'a').write_bytes(a)
            (directory / 'b').write_bytes(b)
            # -u headers have intentionally different timestamp formatting. Strip
            # headers only when validating, preserving every hunk byte below them.
            reference = subprocess.run(['/usr/bin/diff', *opts, 'a', 'b'], cwd=tmp,
                                       env=env, capture_output=True, timeout=30)
            assert reference.returncode in (0, 1) and not reference.stderr
            status = reference.returncode
            expected = reference.stdout
            case = dict(name=name, options=opts, passes=passes, bytes=[len(a), len(b)],
                        lines=[a.count(b'\n'), b.count(b'\n')],
                        fixture_sha256=[sha(a), sha(b)], expected_status=status,
                        expected_sha256=sha(expected), expected_bytes=len(expected), results={})
            def script(label, count):
                command = '/usr/bin/diff' if label == 'GNU' else 'diff'
                return ('for ((i=0;i<' + str(count) + ';i++)); do ' + command + ' ' +
                        ' '.join(opts) + ' a b; r=$?; [[ $r == ' + str(status) +
                        ' ]] || exit 99; printf "\\0sol-diff-pass:%s\\0" "$i" || exit 98; done')

            def validate(path, count):
                actual = path.read_bytes()
                # NUL-framed pass boundaries prevent a doubled first output and
                # an empty later output from masquerading as a valid batch.
                frames = actual.split(b'\0')
                assert len(frames) == count * 2 + 1 and frames[-1] == b''
                for i in range(count):
                    assert frames[2 * i + 1] == f'sol-diff-pass:{i}'.encode()
                    observed, wanted = frames[2 * i], expected
                    if '-u' in opts and expected:
                        left_header, right_header, observed = observed.split(b'\n', 2)
                        assert left_header.split(b'\t', 1)[0] == b'--- a'
                        assert right_header.split(b'\t', 1)[0] == b'+++ b'
                        wanted = expected.split(b'\n', 2)[2]
                    assert observed == wanted, (name, i, sha(observed), sha(wanted))

            for round_no in range(8):
                order = list(implementations)
                if round_no % 2:
                    order.reverse()
                for label in order:
                    output = directory / 'output'
                    errors = directory / 'errors'
                    argv = [implementations[label], '--noprofile', '--norc', '-c', script(label, passes)]
                    # wait4's ru_maxrss may retain the spawning Python process's
                    # pre-exec high-water mark. VmHWM belongs to the shell's
                    # current mm and measures builtin memory without that floor.
                    argv[-1] += ('; while read -r key value rest; do '
                                 'if [[ $key == VmHWM: ]]; then printf "vmhwm=%s\\n" "$value" >&2; break; fi; '
                                 'done < /proc/$BASHPID/status')
                    with output.open('wb') as out, errors.open('wb') as err:
                        start = time.perf_counter_ns()
                        p = subprocess.Popen(argv, cwd=tmp, env=env, stdout=out, stderr=err)
                        pidfd = os.pidfd_open(p.pid)
                        try:
                            if not select.select([pidfd], [], [], 120)[0]:
                                p.kill()
                            _, wait_status, usage = os.wait4(p.pid, 0)
                            p.returncode = os.waitstatus_to_exitcode(wait_status)
                        finally:
                            os.close(pidfd)
                        elapsed = (time.perf_counter_ns() - start) / 1e6
                    stderr = errors.read_bytes()
                    assert p.returncode == 0 and stderr.startswith(b'vmhwm='), (name, label, p.returncode, stderr)
                    vmhwm = int(stderr.removeprefix(b'vmhwm='))
                    validate(output, passes)
                    result = case['results'].setdefault(label, dict(ms=[], shell_vmhwm_kib=[], wait4_ru_maxrss_kib=[]))
                    if round_no:
                        result['ms'].append(elapsed)
                        result['shell_vmhwm_kib'].append(vmhwm)
                        result['wait4_ru_maxrss_kib'].append(usage.ru_maxrss)
            for label, result in case['results'].items():
                result['median_ms'] = statistics.median(result['ms'])
                result['median_shell_vmhwm_kib'] = statistics.median(result['shell_vmhwm_kib'])
                result['validation'] = 'every output byte and every invocation status checked, including warmup'
            if args.profile:
                for label in binaries:
                    profile = args.output.with_name(args.output.stem + '-' + name + '-' + label + '-strace.txt')
                    with (directory / 'profile-output').open('wb') as out:
                        p = subprocess.run(['/usr/bin/strace', '-c', '-o', str(profile),
                                            binaries[label], '--noprofile', '--norc', '-c', script(label, 1)],
                                           cwd=tmp, env=env, stdout=out, stderr=subprocess.PIPE, timeout=120)
                    assert p.returncode == 0 and not p.stderr, p.stderr
                    validate(directory / 'profile-output', 1)
                    case.setdefault('profiles', {})[label] = str(profile)
            for item in args.profile_fixture:
                label, module = item.split('=', 1)
                module = str(Path(module).resolve())
                output = directory / 'counter-output'
                with output.open('wb') as out:
                    p = subprocess.run([shell, '--noprofile', '--norc', '-c',
                                        'enable -f "$1" diff || exit; export BASHOS_DIFF_PROFILE=1; ' +
                                        script(label, 1), 'profile', module], cwd=tmp, env=env,
                                       stdout=out, stderr=subprocess.PIPE, timeout=120)
                assert p.returncode == 0, p.stderr
                validate(output, 1)
                case.setdefault('counters', {})[label] = dict(
                    module_sha256=sha(Path(module).read_bytes()), **json.loads(p.stderr))
            case['status'] = 'ok'
            report['cases'].append(case)
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            print(name, {k: round(v['median_ms'], 3) for k, v in case['results'].items()}, flush=True)
    report['load_end'] = os.getloadavg()
    report['status'] = 'ok'
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
