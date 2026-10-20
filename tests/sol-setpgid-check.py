#!/usr/bin/env python3
"""Real-kernel setpgid checks; only the shell and its owned children are targets.
No compilation. --module optionally loads the production UBSan module.
"""
import argparse
import contextlib
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import tempfile


class Shell:
    def __init__(self, binary, module=None, session=False):
        self.errors = tempfile.TemporaryFile(mode='w+t')
        env = {k: v for k, v in os.environ.items()
               if k not in ('BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS')}
        env.update(PATH='', LC_ALL='C', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        self.p = subprocess.Popen([str(Path(binary).resolve()), '--noprofile', '--norc'],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=self.errors, env=env, start_new_session=session)
        self.pending = b''
        self.children = []
        if module:
            assert self.call('enable -f ' + shlex.quote(str(Path(module).resolve())) + ' setpgid')[0] == 0
        assert self.call('set +m; type -t setpgid')[:2] == (0, ['builtin'])

    def line(self):
        while b'\n' not in self.pending:
            with selectors.DefaultSelector() as sel:
                sel.register(self.p.stdout, selectors.EVENT_READ)
                assert sel.select(10), 'shell protocol timeout'
            chunk = os.read(self.p.stdout.fileno(), 65536)
            assert chunk, 'shell exited before reply'
            self.pending += chunk
        line, self.pending = self.pending.split(b'\n', 1)
        return line.decode()

    def call(self, command):
        self.errors.seek(0, 2)
        offset = self.errors.tell()
        self.p.stdin.write((command + "; printf 'RESULT:%s\\n' \"$?\"\n").encode())
        self.p.stdin.flush()
        output = []
        while True:
            line = self.line()
            if line.startswith('RESULT:'):
                status = int(line.split(':')[1])
                break
            output.append(line)
        self.errors.seek(offset)
        return status, output, self.errors.read()

    def child(self, program=None):
        default = program is None
        if default:
            program = 'printf "READY\\n"; read -r token'
        rc, out, err = self.call('coproc HOLD { ' + program + '; }; child=$HOLD_PID; '
                                 'printf "%s\\n" "$child"')
        assert rc == 0 and not err, (rc, out, err)
        pid = int(out[0])
        self.children.append(pid)
        if default:
            rc, out, err = self.call('read -r ready <&"${HOLD[0]}"; [[ $ready == READY ]]')
            assert (rc, out, err) == (0, [], ''), (rc, out, err)
        return pid

    def release(self, pid):
        rc, out, err = self.call('printf "done\\n" >&"${HOLD[1]}"; wait ' + str(pid))
        assert rc == 0 and not out and not err, (rc, out, err)
        self.children.remove(pid)

    def close(self):
        try:
            for pid in list(self.children):
                self.release(pid)
            self.p.stdin.close()
            assert self.p.wait(timeout=10) == 0
            self.errors.seek(0)
            assert 'runtime error:' not in self.errors.read()
        finally:
            if self.p.poll() is None:
                self.p.kill()  # Only this Popen-owned shell.
                self.p.wait()
            self.p.stdout.close()
            self.errors.close()


@contextlib.contextmanager
def shell(binary, module=None, session=False):
    s = Shell(binary, module, session)
    try:
        yield s
    finally:
        s.close()


def check(binary, module=None):
    passed, failed = [], []

    def case(name, fn):
        try:
            fn()
            passed.append(name)
            print('PASS', name, flush=True)
        except AssertionError as e:
            failed.append(name)
            print('FAIL', name, str(e), flush=True)

    def success(s, args, target, expected):
        rc, out, err = s.call('setpgid ' + args)
        assert (rc, out, err) == (0, [], ''), (args, rc, out, err)
        assert os.getpgid(target) == expected, (args, os.getpgid(target), expected)

    def self_values(args):
        with shell(binary, module) as s:
            assert os.getpgid(s.p.pid) != s.p.pid
            success(s, args.replace('PID', str(s.p.pid)), s.p.pid, s.p.pid)
            success(s, '0 0', s.p.pid, s.p.pid)

    for args in ('0 0', 'PID 0', '0 PID', 'PID PID'):
        case('self explicit/default ' + args, lambda a=args: self_values(a))

    def child_values():
        with shell(binary, module) as s:
            group = os.getpgid(s.p.pid)
            pid = s.child()
            assert os.getpgid(pid) == group
            for _ in range(20):
                success(s, f'{pid} 0', pid, pid)
                success(s, f'{pid} {group}', pid, group)
                success(s, f'{pid} {pid}', pid, pid)
                success(s, f'{pid} {group}', pid, group)
            assert os.getpgid(s.p.pid) == group
            s.release(pid)
            rc, out, err = s.call(f'setpgid {pid} 0')
            assert rc == 1 and not out and 'No such process' in err, (rc, out, err)
    case('owned child move/reset/repeat and dead child ESRCH', child_values)

    invalid = ['', '0', '0 0 extra', 'abc 0', '0 abc', "'' 0", "0 ''", '-1 0',
               '0 -1', '1.0 0', '0 1x', '9223372036854775808 0',
               '0 9223372036854775808', '4294967296 0', '0 4294967296',
               '2147483648 0', '0 2147483648', '9223372036854775807 0', '0 9223372036854775807',
               '18446744073709551616 0',
               '0 18446744073709551616', '--help']
    def invalid_case(args):
        with shell(binary, module) as s:
            before = os.getpgid(s.p.pid)
            rc, out, err = s.call('setpgid ' + args)
            expected = 2 if len(shlex.split(args)) != 2 else 1
            after = os.getpgid(s.p.pid)
            assert after == before, (args, 'invalid input mutated group', before, after, rc)
            assert rc == expected and not out and err, (args, rc, expected, out, err)
            if any(v in args for v in ('2147483648', '4294967296', '9223372036854775807')):
                assert 'out of range' in err, err
            success(s, '0 0', s.p.pid, s.p.pid)
    for args in invalid:
        case('invalid ' + repr(args), lambda a=args: invalid_case(a))

    def errors():
        with shell(binary, module) as s:
            group = os.getpgid(s.p.pid)
            missing = int(Path('/proc/sys/kernel/pid_max').read_text()) + 1
            assert not Path(f'/proc/{missing}').exists()
            for args, diagnostic in ((f'{missing} 0', 'No such process'),
                                     (f'{os.getpid()} 0', 'No such process'),
                                     (f'0 {missing}', 'Operation not permitted'),
                                     ('2147483647 0', 'No such process'),
                                     ('0 2147483647', 'Operation not permitted')):
                rc, out, err = s.call('setpgid ' + args)
                assert rc == 1 and not out and diagnostic in err, (args, rc, out, err)
                assert os.getpgid(s.p.pid) == group
            # No stdout is required, so even a failing output device is irrelevant.
            success(s, '0 0 >/dev/full', s.p.pid, s.p.pid)
    case('missing/nonchild ESRCH, nonexistent group EPERM, stdout', errors)

    def leader():
        with shell(binary, module, session=True) as s:
            assert os.getsid(s.p.pid) == s.p.pid == os.getpgid(s.p.pid)
            for _ in range(3):
                rc, out, err = s.call('setpgid 0 0')
                assert rc == 1 and not out and 'Operation not permitted' in err
                assert os.getsid(s.p.pid) == s.p.pid == os.getpgid(s.p.pid)
    case('session leader EPERM', leader)

    def foreign_group():
        with shell(binary, module) as s, shell(binary, module, session=True) as foreign:
            pid = s.child()
            group = os.getpgid(pid)
            assert os.getsid(pid) != os.getsid(foreign.p.pid)
            rc, out, err = s.call(f'setpgid {pid} {foreign.p.pid}')
            assert rc == 1 and not out and 'Operation not permitted' in err, (rc, out, err)
            assert os.getpgid(pid) == group
            assert os.getpgid(foreign.p.pid) == foreign.p.pid
    case('owned child cannot join another session group EPERM', foreign_group)

    def cross_session():
        with shell(binary, module) as s:
            # exec makes EACCES possible too; Linux checks the session first.
            program = ('exec ' + shlex.quote(os.sys.executable) +
                       " -c 'import os; os.setsid(); print(os.getpid(), flush=True); input()'")
            pid = s.child(program)
            rc, out, err = s.call('read -r ready <&"${HOLD[0]}"; [[ $ready == "$child" ]]')
            assert rc == 0 and not out and not err
            assert os.getsid(pid) == pid == os.getpgid(pid)
            rc, out, err = s.call(f'setpgid {pid} 0')
            assert rc == 1 and not out and 'Operation not permitted' in err, (rc, out, err)
            assert os.getsid(pid) == pid == os.getpgid(pid)
    case('owned child in another session EPERM', cross_session)

    def executed():
        with shell(binary, module) as s:
            pid = s.child('exec ' + shlex.quote(os.sys.executable) +
                          " -c 'import os; print(os.getpid(), flush=True); input()'")
            assert s.call('read -r ready <&"${HOLD[0]}"; [[ $ready == "$child" ]]')[0] == 0
            group = os.getpgid(pid)
            rc, out, err = s.call(f'setpgid {pid} 0')
            assert rc == 1 and not out and 'Permission denied' in err, (rc, out, err)
            assert os.getpgid(pid) == group
    case('owned exec child EACCES', executed)

    def cleanup():
        with shell(binary, module) as s:
            initial = len(list(Path(f'/proc/{s.p.pid}/fd').iterdir()))
            group = os.getpgid(s.p.pid)
            for _ in range(30):
                pid = s.child()
                success(s, f'{pid} 0', pid, pid)
                s.release(pid)
                # Reap and close the coprocess before measuring the next turn.
                assert s.call(':')[0] == 0
                assert len(list(Path(f'/proc/{s.p.pid}/fd').iterdir())) == initial
            assert os.getpgid(s.p.pid) == group
    case('repeated child lifecycle FD/group cleanup', cleanup)
    print(f'{len(passed)} passed; {len(failed)} failed')
    assert not failed, failed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--module')
    args = parser.parse_args()
    check(args.binary, args.module)
