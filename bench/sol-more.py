#!/usr/bin/env python3
"""Validated more work: historical operands, large copy, real PTY pages.

Run only through the campaign bench gate. This driver never compiles.
"""
import argparse
import hashlib
import importlib.util
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
spec = importlib.util.spec_from_file_location('more_checks', ROOT/'tests/sol-more-check.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--runs', default=7, type=int)
    parser.add_argument('--profile', action='store_true')
    args = parser.parse_args()
    assert args.runs >= 7
    binary = str(args.binary.resolve(strict=True))
    report = dict(binary=binary, binary_sha256=sha(binary), source_sha256=sha(ROOT/'loadables/more.c'),
                  source_hashes={str(p): sha(ROOT/p) for p in
                                 ('loadables/more.c', 'loadables/_bl_key/bl_key.c',
                                  'loadables/_bl_key/bl_key.h', 'loadables/common/bl-output.h')},
                  date=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  source_dirty=bool(subprocess.check_output(['git', 'diff', '--', 'loadables/more.c'], cwd=ROOT)),
                  affinity=sorted(os.sched_getaffinity(0)), kernel=platform.release(),
                  machine=platform.machine(), python=platform.python_version(), environment=checks.ENV,
                  reset='Every command reopens the same immutable fixture; warm page cache; no input producer sleeps.',
                  method='One untimed warmup, seven or more samples; every sample status and complete output validated. Captured-output clocks stop before byte checks; PTY clocks include the driver and per-page event checks. Alternating implementation order for compared cases.',
                  versions={}, cases=[])
    for name, command in [('bash', [binary, '--version']), ('external-more', ['/usr/bin/more', '--version']),
                          ('strace', ['/usr/bin/strace', '--version'])]:
        p = subprocess.run(command, capture_output=True, text=True, check=True)
        report['versions'][name] = (p.stdout or p.stderr).splitlines()[0]
    report['external_sha256'] = sha('/usr/bin/more')
    producer = Path('/usr/bin/cat')
    producer_stat = producer.stat()
    report['producer'] = dict(path=str(producer), sha256=sha(producer),
                              version=subprocess.check_output([str(producer), '--version'], text=True).splitlines()[0],
                              inode=producer_stat.st_ino, ctime_ns=producer_stat.st_ctime_ns)
    report['cpu_model'] = next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                               if line.startswith('model name'))
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.output.write_text(json.dumps(report, indent=2)+'\n')

    with tempfile.TemporaryDirectory(prefix='sol-more-bench-') as temporary:
        root = Path(temporary)
        rng = random.Random(20260908)
        words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
        text = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n'
                       for _ in range(12000)).encode()[:423000]
        (root/'text').write_bytes(text)
        (root/'copy').write_bytes(text)
        (root/'empty').write_bytes(b'')
        large = bytes(range(256))*131072
        (root/'large').write_bytes(large)
        historical = b''.join(b'::::::::::::::\n'+name+b'\n::::::::::::::\n'+text
                              for name in (b'text', b'copy'))
        definitions = [('historical-more-captured', ['-n', '100', 'text', 'copy'], historical, 12, 'empty', 'file'),
                       ('large-noninteractive-copy', [], large, 3, 'large', 'file'),
                       ('large-pipe-copy', [], large, 3, 'large', 'pipe')]
        for name, options, expected, passes, fixture, input_kind in definitions:
            row = dict(name=name, kind='compared', options=options, passes=passes,
                       input_kind=input_kind, fixture=fixture,
                       work_unit=f'{len(expected)} output bytes per pass; {passes} passes per sample',
                       expected_sha256=hashlib.sha256(expected).hexdigest(),
                       fixture_sha256=hashlib.sha256(text if name.startswith('historical') else large).hexdigest(),
                       results={})
            report['cases'].append(row)
            commands = {'builtin': ['more', *options], 'external': ['/usr/bin/more', *options]}
            script = ('PATH=; input=$1; kind=$2; n=$3; shift 3; '
                      'for ((i=0;i<n;i++)); do '
                      'if [[ $kind == pipe ]]; then /usr/bin/cat "$input" | "$@" || exit; '
                      'else "$@" < "$input" || exit; fi; done')
            for label in commands:
                row['results'][label] = dict(status='pending', samples_ms=[])

            def run(label):
                with tempfile.TemporaryFile() as output:
                    start = time.perf_counter_ns()
                    p = subprocess.run([binary, '--noprofile', '--norc', '-o', 'pipefail', '-c', script,
                                        'bench', fixture, input_kind, str(passes), *commands[label]], cwd=root, env=checks.ENV,
                                       stdout=output, stderr=subprocess.PIPE, timeout=30)
                    elapsed = (time.perf_counter_ns()-start)/1e6
                    assert p.returncode == 0 and not p.stderr, (name, label, p.returncode, p.stderr)
                    output.seek(0)
                    for _ in range(passes):
                        assert output.read(len(expected)) == expected, (name, label, 'byte mismatch')
                    assert output.read(1) == b'', (name, label, 'extra bytes')
                return elapsed

            for label in commands:
                run(label)
            for round_number in range(args.runs):
                for label in (list(commands) if round_number % 2 == 0 else list(reversed(commands))):
                    row['results'][label]['samples_ms'].append(run(label))
            for result in row['results'].values():
                values = result['samples_ms']
                result.update(status='ok', median_ms=statistics.median(values), min_ms=min(values), max_ms=max(values))
            row['builtin_over_external'] = row['results']['builtin']['median_ms']/row['results']['external']['median_ms']
            print(name, row['results'], flush=True)
            save()
            if args.profile:
                for label, command in commands.items():
                    trace = args.output.with_name(args.output.stem+'-'+name+'-'+label+'.strace')
                    p = subprocess.run(['/usr/bin/strace', '-f', '-c', '-o', str(trace), binary,
                                        '--noprofile', '--norc', '-o', 'pipefail', '-c', script,
                                        '_', fixture, input_kind, '1', *command],
                                       cwd=root, env=checks.ENV, capture_output=True, timeout=30)
                    assert p.returncode == 0 and p.stdout == expected and not p.stderr, (label, p.returncode, p.stderr)
                    row.setdefault('profiles', {})[label] = str(trace)
                save()

        # This is forward paging on an actual controlling terminal. Every
        # page has an independent expected byte sequence and prompt event.
        lines = [f'page-line-{i:06d}\n'.encode() for i in range(3107)]
        pages = root/'pages'
        pages.write_bytes(b''.join(lines))
        row = dict(name='interactive-page-work', kind='self', options=['-n', '100'], passes=3,
                   work_unit='3 invocations/sample, each 3107 lines / 52819 input bytes, 31 page prompts and 31 space keys, then EOF',
                   fixture_sha256=sha(pages), reference='Independent line and prompt events; no external pager ratio',
                   timing_scope='Three invocations in one persistent shell; excludes PTY/shell setup and final cleanup, includes driver and per-page checks.',
                   results={'builtin': {'status': 'pending', 'samples_ms': []}})
        report['cases'].append(row)

        def page_work():
            terminal = checks.Terminal(binary, rows=30)
            try:
                start = time.perf_counter_ns()
                for invocation in range(3):
                    if invocation:
                        terminal.send(b'continue\n')
                    terminal.start('more -n 100 '+str(pages))
                    out = terminal.until(checks.PROMPT)
                    assert out.endswith(b''.join(lines[:100]).replace(b'\n', b'\r\n')+checks.PROMPT)
                    for page in range(1, 31):
                        terminal.send(b' ')
                        out = terminal.until(checks.PROMPT)
                        assert out == checks.ERASE+b''.join(lines[page*100:(page+1)*100]).replace(b'\n', b'\r\n')+checks.PROMPT
                    terminal.send(b' ')
                    out = terminal.done()
                    assert out == checks.ERASE+b''.join(lines[3100:]).replace(b'\n', b'\r\n')+b'__DONE__:0\r\n'
                return (time.perf_counter_ns()-start)/1e6
            finally:
                terminal.close()

        page_work()
        result = row['results']['builtin']
        for _ in range(args.runs):
            result['samples_ms'].append(page_work())
            save()
        values = result['samples_ms']
        result.update(status='ok', median_ms=statistics.median(values), min_ms=min(values), max_ms=max(values))
        print('interactive-page-work', result, flush=True)
        save()


if __name__ == '__main__':
    main()
