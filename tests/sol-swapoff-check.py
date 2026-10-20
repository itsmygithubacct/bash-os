#!/usr/bin/env python3
"""Closed production swapoff contract; never compiles or uses host swap.

Build the shim separately with sol-swapoff-build.sh through the build gate.
An optional sanitizer module replaces swapoff in an ordinary Bash shell.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

HEADER = b'Filename\tType\tSize\tUsed\tPriority\n'


def quote(value):
    return shlex.quote(str(value))


def row(path, kind='file', size='4096', used='0', priority='-2'):
    return f'{path}\t{kind}\t{size}\t{used}\t{priority}\n'.encode()


def shell_setup(shim, module=None):
    setup = 'PATH=; LC_ALL=C; export PATH LC_ALL\n'
    if module:
        setup += f'enable -f {quote(module)} swapoff || exit 90\n'
    setup += f'enable -f {quote(shim)} swapoff_fixture || exit 91\n'
    setup += '[[ $(type -t swapoff) == builtin ]] || exit 92\n'
    setup += 'swapoff_fixture reset || exit 93\n'
    setup += 'swapoff_fixture guard || exit 96\n'
    return setup


def environment(shim, asan=None):
    env = os.environ.copy()
    for name in ('BASH_ENV', 'ENV', 'LD_PRELOAD', 'BASHOPTS', 'SHELLOPTS'):
        env.pop(name, None)
    env.update(PATH='', LC_ALL='C', LD_PRELOAD=(str(asan) + ':' if asan else '') + str(shim))
    if asan:
        env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    return env


def cases():
    # expected paths are independent literals, never derived by the C parser.
    yield dict(name='named-literal-escapes', args=['/named space', '/tab\tname', '/line\nname', r'/literal\040'],
               expected=['/named space', '/tab\tname', '/line\nname', r'/literal\040'])
    yield dict(name='named-relative-and-dash', args=['--', '-device', 'relative'], expected=['-device', 'relative'])
    yield dict(name='named-duplicates-are-explicit', args=['/a', '/a'], expected=['/a', '/a'])
    yield dict(name='named-partial-errors', args=['/good', '/denied', '/missing', '/last'],
               expected=['/good', '/denied', '/missing', '/last'], fails=[('/denied', 13), ('/missing', 19)],
               rc=1, stderr=['/denied: Permission denied', '/missing: No such device'])
    yield dict(name='named-permission', args=['/root-only'], expected=['/root-only'], fails=[('/root-only', 1)],
               rc=1, stderr=['Operation not permitted'])
    yield dict(name='empty-name-partial', args=['', '/last'], expected=['/last'], rc=1, stderr=['empty device name'])
    yield dict(name='no-operands', args=[], expected=[], rc=2, stderr=['no device specified'])
    yield dict(name='only-separator', args=['--'], expected=[], rc=2, stderr=['no device specified'])
    yield dict(name='invalid-option', args=['--bogus', '/a'], expected=[], rc=2, stderr=['unknown option'])
    yield dict(name='all-with-operand', args=['-a', '/a'], expected=[], rc=2, stderr=['does not accept'])
    yield dict(name='all-with-separated-operand', args=['--all', '--', '/a'], expected=[], rc=2, stderr=['does not accept'])
    yield dict(name='help', args=['--help'], expected=[], stdout='Disable a swap area.')
    yield dict(name='help-output-failure', args=['--help'], expected=[], rc=1, redirect='/dev/full', allow_stderr=True)
    yield dict(name='all-empty', args=['-a'], data=HEADER, expected=[])
    yield dict(name='long-all-empty', args=['--all'], data=HEADER, expected=[])
    yield dict(name='all-repeated-option', args=['-a', '--all'], data=HEADER + row('/a'), expected=['/a'])
    yield dict(name='all-path-escapes', args=['-a'], data=HEADER + row(r'/space\040name') + row(r'/tab\011name') +
               row(r'/line\012name') + row(r'/slash\134name') + row(r'/literal\134040'),
               expected=['/space name', '/tab\tname', '/line\nname', '/slash\\name', r'/literal\040'])
    yield dict(name='all-carriage-return-path', args=['-a'], data=HEADER + row('/carriage\rname'), expected=['/carriage\rname'])
    yield dict(name='all-duplicates', args=['-a'], data=HEADER + row('/a') + row('/b', 'partition') + row('/a', priority='4'),
               expected=['/a', '/b'])
    yield dict(name='all-permission-continues', args=['-a'], data=HEADER + row('/a') + row('/denied') + row('/last'),
               expected=['/a', '/denied', '/last'], fails=[('/denied', 1)], rc=1, stderr=['Operation not permitted'])
    yield dict(name='header-whitespace', args=['-a'], data=b' Filename Type Size Used Priority \n' + row('/a'), expected=['/a'])
    yield dict(name='no-final-newline', args=['-a'], data=HEADER + row('/a').rstrip(b'\n'), expected=['/a'])
    yield dict(name='blank-rows', args=['-a'], data=HEADER + b'\n \t\n' + row('/a'), expected=['/a'])
    yield dict(name='long-path-not-truncated', args=['-a'], data=HEADER + row('/' + 'x' * 16384), expected=['/' + 'x' * 16384])
    yield dict(name='long-duplicate-set', args=['-a'], data=HEADER + b''.join(row('/p' + str(i)) for i in range(100)) * 2,
               expected=['/p' + str(i) for i in range(100)])
    for name, data in [('data-instead-of-header', b''), ('missing-header', row('/never')), ('wrong-header', b'Filename Type Size Used Wrong\n'),
                       ('header-extra', HEADER.rstrip(b'\n') + b' Extra\n'), ('header-nul', HEADER.replace(b'Type', b'Ty\x00pe'))]:
        yield dict(name=name, args=['-a'], data=data + row('/never'), expected=[], rc=1, stderr=['header'])
    # Truly empty input separately: appended rows above exercise header rejection.
    yield dict(name='truly-empty-file', args=['-a'], data=b'', expected=[], rc=1, stderr=['missing header'])
    malformed = {
        'one-field': b'/never\n', 'missing-field': b'/never file 4 0\n',
        'extra-field': b'/never file 4 0 -2 extra\n', 'relative': row('relative'),
        'unknown-type': row('/never', 'bogus'), 'negative-size': row('/never', size='-1'),
        'bad-size': row('/never', size='12x'), 'size-overflow': row('/never', size='18446744073709551616'),
        'negative-used': row('/never', used='-1'), 'used-over-size': row('/never', used='4097'),
        'bad-priority': row('/never', priority='--1'), 'priority-overflow': row('/never', priority='2147483648'),
        'priority-underflow': row('/never', priority='-2147483649'),
        'nul-path': row('/ne\x00ver'), 'nul-tail': row('/never') + b'\x00\n',
        'nul-escape': row(r'/never\000'), 'unknown-escape': row(r'/never\141'),
        'short-escape': row('/never\\04'), 'bare-backslash': row('/never\\'),
        'header-again': HEADER, 'long-bad-row': b'/never ' + b'x' * 20000 + b'\n',
    }
    for name, bad in malformed.items():
        # A later valid row must survive rejection of even a very long bad row.
        expected = ['/before', '/after']
        if name == 'nul-tail':
            # The first complete row is valid; only the following NUL row is bad.
            expected = ['/before', '/never', '/after']
        yield dict(name='malformed-' + name, args=['-a'], data=HEADER + row('/before') + bad + row('/after'),
                   expected=expected, rc=1, stderr=['malformed row'])
    for fault, errno_value, opens, closes, message in [('open', 13, 1, 0, 'Permission denied'),
                                                    ('read', 1, 1, 1, 'read error'),
                                                    ('close', 5, 1, 1, 'Input/output error')]:
        yield dict(name='source-' + fault + '-error', args=['-a'], data=HEADER + row('/never'), expected=[],
                   fault=(fault, errno_value), opens=opens, closes=closes, rc=1, stderr=[message])
    yield dict(name='integer-boundaries', args=['-a'], data=HEADER + row('/max', size='18446744073709551615', priority='2147483647') +
               row('/min', size='0', priority='-2147483648'), expected=['/max', '/min'])


def run_suite(args):
    results = []
    env = environment(args.shim, args.asan)
    args.fixture_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sol-swapoff-', dir=args.fixture_dir) as tmp:
        tmp = Path(tmp)
        for case in cases():
            data = case.get('data', HEADER)
            fixture = tmp / 'swaps'
            fixture.write_bytes(data)
            script = shell_setup(args.shim, args.module)
            script += f'swapoff_fixture source {quote(fixture)} || exit 93\n'
            script += 'swapoff_fixture expect ' + ' '.join(map(quote, case['expected'])) + ' || exit 93\n'
            for path, error in case.get('fails', []):
                script += f'swapoff_fixture fail {quote(path)} {error} || exit 93\n'
            if 'fault' in case:
                script += f'swapoff_fixture fault {case["fault"][0]} {case["fault"][1]} || exit 93\n'
            command = 'swapoff ' + ' '.join(map(quote, case['args']))
            if 'redirect' in case:
                command += ' >' + quote(case['redirect'])
            script += command + '\nrc=$?\n'
            script += f'[[ $rc == {case.get("rc", 0)} ]] || {{ printf "wrong status: %s\\n" "$rc" >&2; exit 89; }}\n'
            opens = case.get('opens', 1 if 'data' in case else 0)
            closes = case.get('closes', opens)
            script += f'swapoff_fixture check {len(case["expected"])} {opens} {closes} || exit 88\n'
            script += 'swapoff_fixture reset || exit 87\n'
            proc = subprocess.run([args.binary, '--noprofile', '--norc', '-c', script], env=env, capture_output=True)
            stderr = proc.stderr.decode(errors='replace')
            ok = proc.returncode == 0 and all(s in stderr for s in case.get('stderr', []))
            if not case.get('stderr') and not case.get('allow_stderr'):
                ok = ok and not proc.stderr
            ok = ok and ('stdout' not in case or case['stdout'].encode() in proc.stdout)
            if 'stdout' not in case:
                ok = ok and not proc.stdout
            results.append(dict(name=case['name'], status='pass' if ok else 'fail', exit_code=proc.returncode,
                                fixture_sha256=hashlib.sha256(data).hexdigest(), stdout=proc.stdout.decode(errors='replace'), stderr=stderr))
            print(f'{"PASS" if ok else "FAIL"} {case["name"]}', flush=True)
        # Mixed success/failure paths in one process: state and FD oracle every call.
        fixture = tmp / 'swaps'
        fixture.write_bytes(HEADER + row('/a') + row(r'/space\040name') + row('/a'))
        script = shell_setup(args.shim, args.module)
        script += f'swapoff_fixture source {quote(fixture)} || exit 93\n'
        script += '''swapoff --help >/dev/full 2>/dev/null
[[ $? == 1 ]] || exit 79
swapoff --help >/dev/null || exit 80
before=(/proc/$$/fd/*)
for ((i=0;i<200;i++)); do
swapoff_fixture expect /a '/space name' || exit 93
swapoff -a || exit 81
swapoff_fixture check 2 1 1 || exit 82
swapoff_fixture expect /literal || exit 93
swapoff /literal || exit 83
swapoff_fixture check 1 0 0 || exit 84
swapoff --bogus 2>/dev/null
[[ $? == 2 ]] || exit 85
swapoff_fixture check 0 0 0 || exit 86
swapoff_fixture fault read 1 || exit 93
swapoff -a 2>/dev/null
[[ $? == 1 ]] || exit 75
swapoff_fixture check 0 1 1 || exit 76
swapoff_fixture fault read 0 || exit 93
swapoff_fixture fault close 5 || exit 93
swapoff -a 2>/dev/null
[[ $? == 1 ]] || exit 73
swapoff_fixture check 0 1 1 || exit 74
swapoff_fixture fault close 0 || exit 93
done
after=(/proc/$$/fd/*)
[[ ${#before[@]} == ${#after[@]} ]] || exit 78
swapoff_fixture reset || exit 87
'''
        proc = subprocess.run([args.binary, '--noprofile', '--norc', '-c', script], env=env, capture_output=True)
        ok = proc.returncode == 0 and not proc.stdout and not proc.stderr
        results.append(dict(name='persistent-mixed-1000-calls', status='pass' if ok else 'fail', exit_code=proc.returncode,
                            stdout=proc.stdout.decode(errors='replace'), stderr=proc.stderr.decode(errors='replace')))
        print(f'{"PASS" if ok else "FAIL"} persistent-mixed-1000-calls', flush=True)
    report = dict(binary=str(args.binary), shim=str(args.shim), module=str(args.module) if args.module else None,
                  sanitizer=bool(args.asan), results=results, passed=sum(r['status'] == 'pass' for r in results),
                  failed=sum(r['status'] != 'pass' for r in results))
    report['sha256'] = {name: hashlib.sha256(getattr(args, name).read_bytes()).hexdigest()
                        for name in ('binary', 'shim', 'module') if getattr(args, name)}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{report["passed"]} passed, {report["failed"]} failed; {args.output}')
    return bool(report['failed'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--shim', type=Path, required=True)
    parser.add_argument('--module', type=Path)
    parser.add_argument('--asan', type=Path)
    parser.add_argument('--fixture-dir', type=Path,
                        default=Path(os.environ.get('BASHOS_TASK_DIR', Path.cwd())) / 'tmp')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for field in ('binary', 'shim', 'module', 'asan'):
        if getattr(args, field):
            setattr(args, field, getattr(args, field).resolve())
    raise SystemExit(run_suite(args))


if __name__ == '__main__':
    main()
