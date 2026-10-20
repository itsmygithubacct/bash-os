#!/usr/bin/env python3
"""Production fsfreeze parser/syscall contract; never issues a real ioctl.

Build separately through the build gate, then run:
  python3 tests/sol-fsfreeze-check.py --binary out/bash-sol-fsfreeze \
      --module /path/to/fsfreeze.so [--asan-library /path/to/libasan.so]
"""
import argparse
import errno
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run_shell(binary, module, script, asan_library=None):
    env = os.environ.copy()
    for name in ('BASH_ENV', 'ENV', 'LD_PRELOAD', 'ASAN_OPTIONS', 'UBSAN_OPTIONS'):
        env.pop(name, None)
    env.update(LC_ALL='C', PATH='')
    if asan_library:
        env.update(LD_PRELOAD=str(asan_library),
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    prelude = ''
    if module:
        prelude = 'enable -f "$1" fsfreeze fsfreeze_fixture || exit 90\n'
    return subprocess.run([str(binary), '--noprofile', '--norc', '-c',
                           prelude + script, 'sol-fsfreeze', str(module or '')],
                          env=env, capture_output=True, text=True, timeout=60)


def counts(stat=0, open=0, freeze=0, thaw=0, close=0, trace=''):
    return (f'stat={stat} open={open} freeze={freeze} thaw={thaw} close={close} '
            f'live=0 bad=0 trace={trace}\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--asan-library', type=Path)
    args = parser.parse_args()
    binary, module = args.binary.resolve(), args.module.resolve()
    failures = []
    passed = 0

    def check(name, script, stdout, diagnostic=None, native=False):
        nonlocal passed
        p = run_shell(binary, None if native else module, script, args.asan_library)
        good = p.returncode == 0 and p.stdout == stdout
        good &= diagnostic in p.stderr if diagnostic else not p.stderr
        if good:
            passed += 1
            print(f'PASS {name}')
        else:
            failures.append(name)
            print(f'FAIL {name}: exit={p.returncode} stdout={p.stdout!r} stderr={p.stderr!r}')

    def case(name, argv, status, scenario='success', expected=None, diagnostic=None):
        script = (f'fsfreeze_fixture reset {shlex.quote(scenario)}\n'
                  f'fsfreeze {shlex.join(argv)}\n'
                  'rc=$?\nprintf "status=%s\\n" "$rc"\nfsfreeze_fixture dump\n')
        check(name, script, f'status={status}\n' + (expected or counts()), diagnostic)

    usage = [
        ('no arguments', [], 'exactly one'),
        ('missing action', ['/fixture/mount'], 'exactly one'),
        ('freeze missing operand', ['-f'], 'a mountpoint'),
        ('thaw missing operand', ['--unfreeze'], 'a mountpoint'),
        ('conflicting actions', ['-f', '-u', '/fixture/mount'], 'exactly one'),
        ('reverse conflict', ['--unfreeze', '--freeze', '/fixture/mount'], 'exactly one'),
        ('duplicate action', ['-f', '--freeze', '/fixture/mount'], 'exactly one'),
        ('duplicate thaw', ['-u', '-u', '/fixture/mount'], 'exactly one'),
        ('extra operands', ['-f', '/fixture/mount', '/fixture/other'], 'too many'),
        ('extra option after operand', ['-u', '/fixture/mount', '-f'], 'too many'),
        ('unknown option', ['--invalid'], 'unknown option'),
        ('unknown short option', ['-x', '/fixture/mount'], 'unknown option'),
        ('no action after delimiter', ['--', '-mount'], 'exactly one'),
        ('empty operand', ['-f', ''], 'mountpoint'),
    ]
    for name, argv, diagnostic in usage:
        case(name, argv, 2, diagnostic=diagnostic)
    for action in ('-f', '--freeze', '-u', '--unfreeze'):
        freeze = action in ('-f', '--freeze')
        case('success ' + action, [action, '/fixture/mount'], 0,
             expected=counts(1, 1, int(freeze), int(not freeze), 1,
                             'stat,open,' + ('freeze,' if freeze else 'thaw,') + 'close,'))
    case('option delimiter', ['-f', '--', '-mount'], 0,
         expected=counts(1, 1, 1, 0, 1, 'stat,open,freeze,close,'))
    case('path with spaces', ['-u', '/fixture/with space'], 0,
         expected=counts(1, 1, 0, 1, 1, 'stat,open,thaw,close,'))
    for kind in ('regular', 'block'):
        case('reject ' + kind, ['-f', '/fixture/mount'], 1, kind,
             counts(stat=1, trace='stat,'), 'not a directory')
    for e in ('ENOENT', 'EACCES', 'ENOTDIR'):
        case('stat ' + e, ['-u', '/fixture/mount'], 1, 'stat-' + e,
             counts(stat=1, trace='stat,'), os.strerror(getattr(errno, e)))
    for e in ('EACCES', 'EPERM', 'EMFILE', 'ENOTDIR'):
        case('open ' + e, ['-f', '/fixture/mount'], 1, 'open-' + e,
             counts(stat=1, open=1, trace='stat,open,'), os.strerror(getattr(errno, e)))
    for action in ('-f', '-u'):
        freeze = action == '-f'
        for e in ('EPERM', 'EACCES', 'ENOTTY', 'EOPNOTSUPP', 'EBUSY', 'EINVAL', 'EINTR'):
            case(f'ioctl {action} {e}', [action, '/fixture/mount'], 1, 'ioctl-' + e,
                 counts(1, 1, int(freeze), int(not freeze), 1,
                        'stat,open,' + ('freeze,' if freeze else 'thaw,') + 'close,'),
                 ('freeze: ' if freeze else 'unfreeze: ') + os.strerror(getattr(errno, e)))

    # A bounded descriptor table makes leaks fail quickly. Inspect actual shell
    # descriptor counts as well as independent fixture call counters.
    for scenario, status in (('success', 0), ('ioctl-EPERM', 1)):
        script = f'''ulimit -n 64 || exit 91
fsfreeze_fixture reset {scenario} quiet || exit 92
before=(/proc/$$/fd/*)
for ((i=0;i<1000;i++)); do
  fsfreeze -f /fixture/mount 2>/dev/null; [[ $? == {status} ]] || exit 93
  fsfreeze -u /fixture/mount 2>/dev/null; [[ $? == {status} ]] || exit 94
done
after=(/proc/$$/fd/*)
[[ ${{#before[@]}} == ${{#after[@]}} ]] || exit 95
fsfreeze_fixture dump
'''
        check('repeated pairs ' + scenario, script, counts(2000, 2000, 1000, 1000, 2000))
    check('state reset after failures', '''fsfreeze_fixture reset ioctl-EPERM
fsfreeze -f /fixture/mount 2>/dev/null; [[ $? == 1 ]] || exit 91
fsfreeze_fixture reset success || exit 92
fsfreeze -u /fixture/mount || exit 93
fsfreeze_fixture dump
''', counts(1, 1, 0, 1, 1, 'stat,open,thaw,close,'))

    help_text = ('Suspend or resume access to a filesystem.\n\n'
                 '    fsfreeze -f | --freeze    MOUNTPOINT\n'
                 '    fsfreeze -u | --unfreeze  MOUNTPOINT\n\n'
                 'Uses the FIFREEZE / FITHAW ioctls; requires root and a freezable fs.\n')
    check('help without syscalls', '''fsfreeze_fixture reset success
fsfreeze --help || exit 91
fsfreeze_fixture dump
''', help_text + counts())
    check('help write failure and recovery', '''fsfreeze_fixture reset success
fsfreeze --help >/dev/full 2>/dev/null; [[ $? == 1 ]] || exit 91
fsfreeze --help || exit 92
fsfreeze_fixture dump
''', help_text + counts())

    # Native binary only: paths guaranteed not to reach open/ioctl.
    with tempfile.TemporaryDirectory(prefix='sol-fsfreeze-') as tmp:
        f = Path(tmp, 'file')
        f.write_text('private fixture\n')
        check('native builtin with empty PATH', 'type -t fsfreeze\n', 'builtin\n', native=True)
        check('native regular file rejection',
              f'fsfreeze -f {shlex.quote(str(f))}\nprintf "status=%s\\n" "$?"\n',
              'status=1\n', 'not a directory', native=True)
        check('native missing path',
              f'fsfreeze -u {shlex.quote(str(f) + "/missing")}\nprintf "status=%s\\n" "$?"\n',
              'status=1\n', 'Not a directory', native=True)
        for argv in (['-f', '-u', str(f)], ['-f', '-f', str(f)],
                     ['-u', str(f), str(f)]):
            check('native parser ' + shlex.join(argv),
                  'fsfreeze ' + shlex.join(argv) + '\nprintf "status=%s\\n" "$?"\n',
                  'status=2\n', 'fsfreeze', native=True)
        check('native help registration',
              'help fsfreeze >/dev/null; printf "status=%s\\n" "$?"\n',
              'status=0\n', native=True)
        check('native help', 'fsfreeze --help\n', help_text, native=True)
        check('native help write failure',
              'fsfreeze --help >/dev/full 2>/dev/null; printf "status=%s\\n" "$?"\n',
              'status=1\n', native=True)
    print(f'fsfreeze: {passed} passed, {len(failures)} failed; real filesystem freeze/thaw never attempted')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
