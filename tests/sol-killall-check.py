#!/usr/bin/env python3
"""Killall production-path fixtures and individually guarded owned children.

Build tests/sol-killall-shim.c separately (through the build gate). This driver
never compiles. Broad fixture selection cannot forward any real signals.
"""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def entry(root, pid, comm='target', cmdline=b'/bin/demo\0arg\0', uid=1234, status=None):
    d = root / str(pid)
    d.mkdir(exist_ok=True)
    (d / 'comm').write_bytes(comm if isinstance(comm, bytes) else (comm + '\n').encode())
    (d / 'cmdline').write_bytes(cmdline)
    (d / 'status').write_text(status if status is not None else f'Name:\tfixture\nUid:\t{uid}\t99\t99\t99\n')


class Runner:
    def __init__(self, binary, shim, root, log):
        self.binary, self.shim, self.root, self.log = map(lambda p: str(Path(p).resolve()), (binary, shim, root, log))

    def env(self, extra=None):
        env = dict(os.environ, PATH='', LD_PRELOAD=(os.environ.get('SOL_KILLALL_ASAN', '') + ' ' + self.shim).strip(), SOL_KILLALL_PROC=self.root,
                   SOL_KILLALL_LOG=self.log)
        env.pop('BASHOS_PROC_ROOT', None)
        env.update(extra or {})
        return env

    def run(self, args, rc=0, calls=(), extra=None, stdout='', stderr=None, script=None):
        Path(self.log).write_text('')
        command = script or ('killall ' + shlex.join(args))
        command = module_prefix() + command
        p = subprocess.run([self.binary, '--noprofile', '--norc', '-c', command], env=self.env(extra),
                           capture_output=True, text=True, timeout=15)
        actual = [tuple(map(int, line.split())) for line in Path(self.log).read_text().splitlines()]
        assert p.returncode == rc, (args, 'status', p.returncode, rc, p.stderr)
        assert sorted(actual) == sorted(calls), (args, 'delivery', actual, calls)
        assert p.stdout == stdout, (args, 'stdout', p.stdout, stdout)
        if stderr is not None:
            assert (stderr in p.stderr if stderr else not p.stderr), (args, 'stderr', p.stderr, stderr)
        return p


def module_prefix():
    module = os.environ.get('SOL_KILLALL_MODULE')
    return ('enable -f ' + shlex.quote(module) + ' bashkillall || exit 90; killall() { bashkillall \"$@\"; }; ') if module else ''


def fixtures(binary, shim, directory):
    root = directory / 'proc'
    root.mkdir()
    log = directory / 'calls'
    runner = Runner(binary, shim, root, log)
    entry(root, 101)
    entry(root, 102, 'target-worker')
    entry(root, 103, 'pretarget')
    entry(root, 104, 'other', uid=4321)
    results = []

    def case(name, fn):
        try:
            fn()
            results.append(dict(name=name, status='pass'))
        except Exception as e:
            results.append(dict(name=name, status='fail', error=repr(e)))
        print(json.dumps(results[-1]), flush=True)

    case('exact-comm', lambda: runner.run(['target'], calls=[(101, 15, 0)]))
    case('multiple-names-deduplicated', lambda: runner.run(['target', 'other', 'target'], calls=[(101, 15, 0), (104, 15, 0)]))
    for flag, sig in [('-HUP', 1), ('-SIGUSR1', 10), ('-usr2', 12), ('-9', 9), ('-15', 15)]:
        case('signal-' + flag, lambda flag=flag, sig=sig: runner.run([flag, 'target'], calls=[(101, sig, 0)]))
    case('full-command-exact', lambda: runner.run(['-f', '/bin/demo arg'], calls=[(n, 15, 0) for n in (101,102,103,104)]))
    case('full-command-substring-rejected', lambda: runner.run(['-f', 'demo'], rc=1))
    case('uid-real-not-effective', lambda: runner.run(['-u', '1234', 'target'], calls=[(101,15,0)]))
    case('uid-excludes', lambda: runner.run(['-u', '99', 'target'], rc=1))
    entry(root, 106, 'owned-user-fixture', uid=os.getuid())
    case('uid-name-resolution', lambda: runner.run(['-u', pwd.getpwuid(os.getuid()).pw_name, 'owned-user-fixture'],
         calls=[(106,15,0)]))
    case('uid-and-full-command', lambda: runner.run(['-f', '-u', '4321', '/bin/demo arg'], calls=[(104,15,0)]))
    case('nonexistent', lambda: runner.run(['no-such-fixture'], rc=1))
    case('exact-flags', lambda: runner.run(['-e', '--exact', 'target'], calls=[(101,15,0)]))
    entry(root, 105, '--exact')
    case('double-dash', lambda: runner.run(['--', '--exact'], calls=[(105,15,0)]))
    for args in ([], ['-u'], ['-u', '1234'], ['-u', 'no_such_sol_killall_user'],
                 ['-BOGUS', 'target'], ['-0', 'target'], ['-9999', 'target'],
                 ['-4294967311', 'target'], ['-18446744073709551631', 'target'],
                 ['-u', '4294968530', 'target'], ['-u', '18446744073709551616', 'target']):
        case('invalid-' + shlex.join(args), lambda args=args: runner.run(args, rc=2))
    case('exit-race', lambda: runner.run(['target'], rc=1, calls=[(101,15,errno.ESRCH)],
         extra={'SOL_KILLALL_FAIL_PID':'101','SOL_KILLALL_FAIL_ERRNO':str(errno.ESRCH)}, stderr=''))
    case('permission-failure', lambda: runner.run(['target'], rc=1, calls=[(101,15,errno.EPERM)],
         extra={'SOL_KILLALL_FAIL_PID':'101','SOL_KILLALL_FAIL_ERRNO':str(errno.EPERM)}, stderr='Operation not permitted'))
    case('partial-success', lambda: runner.run(['target', 'other'], calls=[(101,15,errno.ESRCH),(104,15,0)],
         extra={'SOL_KILLALL_FAIL_PID':'101','SOL_KILLALL_FAIL_ERRNO':str(errno.ESRCH)}))
    case('disappears-before-read', lambda: runner.run(['target'], rc=1, extra={'SOL_KILLALL_VANISH':'101'}))
    case('proc-fixture-guard', lambda: runner.run(['target'], rc=3, extra={'BASHOS_PROC_ROOT':str(root)}, stderr='read-only'))
    case('count', lambda: runner.run(['-c', 'target'], stdout='1\n', calls=[(101,15,0)]))
    case('output-failure', lambda: runner.run([], rc=1, calls=[(101,15,0)], script='killall -c target > /dev/full'))
    case('version-output-failure', lambda: runner.run([], rc=1, script='killall --version > /dev/full'))
    case('output-failure-recovery', lambda: runner.run([], calls=[(101,15,0)], stdout='recovered\n',
         script='killall -c target > /dev/full; [[ $? == 1 ]] || exit 80; killall --version > /dev/null || exit 81; printf \"recovered\\n\"'))
    # Malformed directory PIDs must never wrap to another process or group.
    for name in ['0','-1','101x','4294967397','4294967295','18446744073709551717','999999999999999999999999999999999999']:
        entry(root, name, 'malformed')
    case('malformed-pid-directories', lambda: runner.run(['target','malformed'], calls=[(101,15,0)] ))
    for pid, status in [(201,'Uid:\t-4294966062\n'), (202,'Uid:\t1234junk\n'),
                        (203,'Uid:\t4294968530\n'), (204,'Uid:\t18446744073709551616\n'),
                        (205,'Uid:\tnonsense\n'), (206,'Name:\tmissing uid\n')]:
        entry(root, pid, 'baduid', status=status)
    case('malformed-uid', lambda: runner.run(['-u','1234','baduid'], rc=1))
    entry(root, 210, b'broken\0hidden\n')
    entry(root, 211, b'')
    entry(root, 212, b'x' * 100)
    case('embedded-nul-comm', lambda: runner.run(['broken'], rc=1))
    case('truncated-comm-not-exact', lambda: runner.run(['x' * 63], rc=1))
    entry(root, 213, 'longcmd', cmdline=b'y' * 5000)
    case('truncated-command-not-exact', lambda: runner.run(['-f', 'y' * 4095], rc=1))
    entry(root, 215, 'emptycmd', cmdline=b'')
    case('empty-command-line', lambda: runner.run(['-f', ''], rc=1))
    entry(root, 216, 'fifteencharname', cmdline=b'a\0\0b\0')
    case('kernel-comm-length', lambda: runner.run(['fifteencharname'], calls=[(216,15,0)]))
    case('full-command-empty-argument', lambda: runner.run(['-f', 'a  b'], calls=[(216,15,0)]))
    case('companion-pgrep-exact', lambda: runner.run([], script='pgrep -x target', stdout='101\n'))
    case('companion-pgrep-substring-long-line', lambda: runner.run([], script='pgrep -f yyyyyyyy', stdout='213\n'))
    case('companion-pgrep-exact-long-line', lambda: runner.run([], rc=1,
         script='pgrep -f -x ' + shlex.quote('y' * 4095)))
    (root / '214').mkdir()
    case('missing-proc-files', lambda: runner.run(['missing'], rc=1))
    case('missing-root', lambda: runner.run(['target'], rc=3, extra={'SOL_KILLALL_PROC':str(root / 'absent')}, stderr='opendir'))

    def repeat():
        # Inspect the persistent shell's actual fd table outside the redirector.
        p = subprocess.Popen([str(Path(binary).resolve()), '--noprofile','--norc'], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=runner.env())
        try:
            entry(root, p.pid, 'self-only')
            p.stdin.write(module_prefix() + 'printf "ready\\n"\n'); p.stdin.flush()
            assert p.stdout.readline() == 'ready\n'
            before = sorted(os.listdir(f'/proc/{p.pid}/fd'))
            Path(runner.log).write_text('')
            p.stdin.write('for ((i=0;i<250;i++)); do killall --exact target || exit 80; killall self-only; [[ $? == 1 ]] || exit 81; done\nprintf "done\\n"\n')
            p.stdin.flush()
            assert p.stdout.readline() == 'done\n'
            assert sorted(os.listdir(f'/proc/{p.pid}/fd')) == before
            assert Path(runner.log).read_text().splitlines() == ['101 15 0'] * 250
            p.stdin.write('exit 0\n'); p.stdin.flush()
            assert p.wait(timeout=10) == 0
        finally:
            if p.poll() is None:
                status = dict(x.split(':', 1) for x in Path(f'/proc/{p.pid}/status').read_text().splitlines() if ':' in x)
                assert int(status['PPid']) == os.getpid() and int(status['Uid'].split()[0]) == os.getuid()
                assert Path(f'/proc/{p.pid}/exe').resolve() == Path(binary).resolve()
                p.terminate(); p.wait(timeout=5)
    case('persistent-shell-self-exclusion-fd-cleanup', repeat)
    return results


CHILD = r'''
import ctypes, os, signal, sys
ctypes.CDLL(None).prctl(15, sys.argv[1].encode(), 0, 0, 0)
def handler(sig, frame):
    print('handled:' + str(sig), flush=True)
signal.signal(signal.SIGUSR1, handler)
signal.signal(signal.SIGUSR2, handler)
print('ready', flush=True)
while True: signal.pause()
'''


def owned(binary, shim, directory):
    name = 'sk' + uuid.uuid4().hex[:10]
    child = subprocess.Popen([sys.executable, '-u', '-c', CHILD, name], stdout=subprocess.PIPE, text=True)
    neighbor = subprocess.Popen([sys.executable, '-u', '-c', CHILD, name + 'x'], stdout=subprocess.PIPE, text=True)
    log = directory / 'owned-calls'
    runner = Runner(binary, shim, directory, log)

    def line(p):
        assert select.select([p.stdout], [], [], 5)[0], 'child event timed out'
        return p.stdout.readline().strip()

    def verify(p, expected):
        assert p.poll() is None
        status = Path(f'/proc/{p.pid}/status').read_text()
        values = dict(x.split(':', 1) for x in status.splitlines() if ':' in x)
        assert int(values['PPid']) == os.getpid()
        assert int(values['Uid'].split()[0]) == os.getuid()
        assert Path(f'/proc/{p.pid}/comm').read_text().rstrip('\n') == expected

    env = {'SOL_KILLALL_PROC':'/proc', 'SOL_KILLALL_OWNED_PID':str(child.pid),
           'SOL_KILLALL_OWNED_COMM':name, 'SOL_KILLALL_PARENT':str(os.getpid())}
    try:
        assert line(child) == line(neighbor) == 'ready'
        for flag, sig in [('-SIGUSR1',signal.SIGUSR1), (str(-signal.SIGUSR2),signal.SIGUSR2)]:
            verify(child, name); verify(neighbor, name + 'x')
            runner.run([flag, name], calls=[(child.pid,sig,0)], extra=env)
            assert line(child) == f'handled:{sig}'
            assert neighbor.poll() is None
        verify(child, name)
        runner.run(['-STOP',name], calls=[(child.pid,signal.SIGSTOP,0)], extra=env)
        waited, status = os.waitpid(child.pid, os.WUNTRACED)
        assert waited == child.pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP
        verify(child, name)
        runner.run(['-CONT',name], calls=[(child.pid,signal.SIGCONT,0)], extra=env)
        waited, status = os.waitpid(child.pid, os.WCONTINUED)
        assert waited == child.pid and os.WIFCONTINUED(status)
        verify(child, name)
        runner.run([name], calls=[(child.pid,signal.SIGTERM,0)], extra=env)
        assert child.wait(timeout=5) == -signal.SIGTERM
        assert neighbor.poll() is None
        print(json.dumps(dict(name='owned-handlers-stop-continue-default-term',status='pass')), flush=True)
        return [dict(name='owned-handlers-stop-continue-default-term',status='pass')]
    finally:
        for p, expected in [(child,name),(neighbor,name+'x')]:
            if p.poll() is None:
                verify(p, expected)
                p.kill(); p.wait(timeout=5)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', required=True)
    ap.add_argument('--shim', required=True)
    ap.add_argument('--report', required=True)
    ap.add_argument('--module', help='optional sanitizer-built replacement loadable')
    args = ap.parse_args()
    if args.module:
        os.environ['SOL_KILLALL_MODULE'] = str(Path(args.module).resolve())
    with tempfile.TemporaryDirectory(prefix='sol-killall-') as tmp:
        directory = Path(tmp)
        results = fixtures(args.binary, args.shim, directory)
        try:
            results += owned(args.binary, args.shim, directory)
        except Exception as e:
            results.append(dict(name='owned-children',status='fail',error=repr(e)))
            print(json.dumps(results[-1]), flush=True)
    Path(args.report).write_text(json.dumps(dict(cases=results), indent=2) + '\n')
    failed = sum(x['status'] != 'pass' for x in results)
    print(f'{len(results)-failed}/{len(results)} cases passed')
    return bool(failed)


if __name__ == '__main__':
    sys.exit(main())
