#!/usr/bin/env python3
"""Signal-specific tests: intercepted production walker plus owned children.
No compilation or timing measurements. Run build helper through the build gate.
"""
import argparse
import ctypes
import errno
import grp
import importlib.util
import os
from pathlib import Path
import pwd
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import time


def load_fixture_module():
    spec = importlib.util.spec_from_file_location(
        'pkill_fixture', Path(__file__).resolve().parents[1] / 'bench/sol-pkill.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def clean_env():
    env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
    for key in ('BASH_ENV', 'ENV', 'LD_PRELOAD', 'BASHOS_PROC_ROOT',
                'SOL_PKILL_PROC_ROOT', 'SOL_PKILL_FAIL', 'SOL_PKILL_REPEAT'):
        env.pop(key, None)
    return env


def fixture_checks(binary, shim, sanitizer=False, regression=False):
    count = 0
    repeats = 25 if sanitizer else 1
    with tempfile.TemporaryDirectory(prefix='sol-pkill-fixture-') as tmp:
        root = Path(tmp) / 'proc'
        root.mkdir()
        load_fixture_module().fixture(root)
        log = Path(tmp) / 'signals'
        env = dict(clean_env(), SOL_PKILL_PROC_ROOT=str(root), SOL_PKILL_LOG=str(log),
                   SOL_PKILL_REPEAT=str(repeats),
                   ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        if not sanitizer:
            env['LD_PRELOAD'] = shim

        def run(args, expected, sig=signal.SIGTERM, status=None, stdout=None,
                fail=None, extra=None, diagnostic=None):
            nonlocal count
            log.write_text('')
            e = dict(env)
            if fail:
                e['SOL_PKILL_FAIL'] = ','.join(f'{pid}:{err}' for pid, err in fail.items())
            if extra:
                e.update(extra)
            delivered = sum(not (fail or {}).get(pid) for pid in expected)
            status = (0 if delivered else 1) if status is None else status
            if stdout is None:
                stdout = f'{delivered}\n' if '-c' in args or '--count' in args else ''
            command = ([binary, *args] if sanitizer else
                       [binary, '--noprofile', '--norc', '-c', shlex.join(['pkill', *args])])
            p = subprocess.run(command, env=e, text=True, capture_output=True, timeout=30)
            assert (p.returncode, p.stdout) == (status, stdout * repeats), (
                args, p.returncode, p.stdout[:200], p.stderr[-2000:], status, stdout)
            actual = [tuple(map(int, line.split())) for line in log.read_text().splitlines()]
            wanted = [(pid, int(sig), (fail or {}).get(pid, 0)) for pid in expected]
            assert sorted(actual) == sorted(wanted * repeats), (args, actual[:20], wanted[:20])
            assert 'AddressSanitizer' not in p.stderr and 'runtime error:' not in p.stderr, p.stderr
            if diagnostic is not None:
                assert (diagnostic in p.stderr) if diagnostic else not p.stderr, p.stderr
            count += 1

        if regression == 'cluster':
            run(['-USR1', '-cfx', '/usr/bin/worker000 --task 0'],
                [2000000000], signal.SIGUSR1, stdout='1\n')
            return count
        if regression == 'age':
            run(['-USR1', '-n', '-c', 'worker'], [2000000510], signal.SIGUSR1)
            return count
        if regression == 'errors':
            run(['-USR1', '-c', '-x', 'worker000'], [2000000000], signal.SIGUSR1,
                fail={2000000000: errno.EINVAL}, diagnostic=os.strerror(errno.EINVAL))
            return count

        # The fixture arithmetic is the oracle; no production regex/selector code
        # is reused to compute which PIDs must reach the intercepted syscall.
        run(['-c', '^worker(00[02468]|010)$'],
            [2000000000 + i for i in (0, 2, 4, 6, 8, 10)])
        run(['-c', '-x', 'worker000|kthreadd'], [2000000000, 2000000511])
        run(['-c', '-x', 'worker00|kthreadd'], [2000000511])
        run(['-c', 'worker00'], list(range(2000000000, 2000000010)))
        run(['-c', '-x', 'worker00'], [])
        run(['-c', '-u2001', '-G3001', '-P77', '-s99',
             '^worker(0[0-9][0-9]|1[0-9][0-9])$'],
            [2000000000 + i for i in range(200) if i % 6 == 0])
        run(['-c', '-u2002', '-U1001', '-G3002', '-g88', '-s99', 'worker'],
            [2000000000 + i for i in range(511) if i % 2 == 1 and i % 3 != 0])
        run(['--count', '--euid=2001,2002', '--uid', '1001',
             '--group=3001,3002', '--parent', '77', '--pgroup=88', '--session=99'],
            list(range(2000000000, 2000000512)))
        run(['-c', '-u2001', '-u2002', '-P77'], list(range(2000000000, 2000000512)))
        for selector in ('-u2003', '-U1002', '-G3003', '-P78', '-g89', '-s100'):
            run(['-c', selector, '.'], [])
        run(['-c', '-f', '--', '--task 5[01][0-9]$'], list(range(2000000500, 2000000512)))
        run(['-c', '-f', '-x', '/usr/bin/worker001 --task 1'], [2000000001])
        for cluster in ('-cfx', '-xfc', '-fcx'):
            run(['-USR1', cluster, '/usr/bin/worker000 --task 0'],
                [2000000000], signal.SIGUSR1, stdout='1\n')
        run(['-cfP77', '--', '--task 0$'], [2000000000], stdout='1\n')
        run(['-cfu', '2001', '--', '--task 0$'], [2000000000], stdout='1\n')
        run(['-USR1', '-n', 'worker'], [2000000510], signal.SIGUSR1)
        run(['-USR2', '--oldest', 'worker'], [2000000000], signal.SIGUSR2)
        run(['-nc', 'worker'], [2000000510], stdout='1\n')
        run(['-oc', '-u2002', 'worker'], [2000000001], stdout='1\n')
        run(['--newest', '-c', 'absent'], [])
        run(['-n', '-c', 'worker'], [2000000510], fail={2000000510: errno.ESRCH}, diagnostic='')
        run(['-o', '-c', 'worker'], [2000000000], fail={2000000000: errno.EPERM},
            diagnostic=os.strerror(errno.EPERM))

        # All supported symbolic names, lower-case SIG prefixes and numbers.
        names = ('HUP INT QUIT ILL TRAP ABRT BUS FPE KILL USR1 SEGV USR2 PIPE '
                 'ALRM TERM CHLD CONT STOP TSTP TTIN TTOU URG XCPU XFSZ '
                 'VTALRM PROF WINCH IO PWR SYS').split()
        for name in names:
            run(['-' + name, '-c', '-x', 'worker000'], [2000000000], getattr(signal, 'SIG' + name))
        for spelling, number in [('-sigusr1', signal.SIGUSR1), ('-SigURG', signal.SIGURG), ('-0', 0),
                                 ('-SIG0', 0), ('-9', 9), ('-15', 15),
                                 (f'-{signal.SIGRTMAX}', signal.SIGRTMAX)]:
            run([spelling, '-c', '-x', 'worker000'], [2000000000], number)
        for args in ([], ['-n'], ['-o'], ['['], ['-x', '['], ['foo', 'bar'], ['-USR1', '['],
                     ['-u'], ['-P', '-1'], ['-P', '77,'], ['-G', '1,,2'],
                     ['-u', '99999999999999999999'], ['-9999999999999999999', '.'],
                     ['-64x', '.'], [f'-{signal.NSIG}', '.'], ['-BOGUS', '.'], ['-v', '.'], ['-l', '.'],
                     ['-u', 'missing-sol-pkill-user'], ['-s', '2147483648'],
                     ['-P', ',77'], ['-P', '77,' * 256 + '77'],
                     ['-cv', '.'], ['-cfq', '.'], ['-cfP'], ['-cfUbad-user', '.'],
                     ['-no', '.'], ['-n', '-o', '.']):
            run(args, [], status=2, stdout='')

        # Successful deliveries determine count/status. ESRCH is a normal race;
        # EPERM is diagnosed and failures must not stop later selected requests.
        for error in (errno.ESRCH, errno.EPERM, errno.EINVAL):
            run(['-USR1', '-c', '-x', 'worker000'], [2000000000], signal.SIGUSR1,
                fail={2000000000: error},
                diagnostic='' if error == errno.ESRCH else os.strerror(error))
            run(['-USR2', '-c', '^worker00[0-2]$'], [2000000000, 2000000001, 2000000002],
                signal.SIGUSR2, fail={2000000001: error},
                diagnostic='' if error == errno.ESRCH else os.strerror(error))
        run(['-c', '.'], [], status=3, stdout='',
            extra={'BASHOS_PROC_ROOT': str(root)}, diagnostic='read-only')
        run(['-c', '.'], [], status=3, stdout='',
            extra={'SOL_PKILL_PROC_ROOT': str(root / 'absent')}, diagnostic='opendir')
        run(['-c', '['], [], status=2, stdout='',
            extra={'SOL_PKILL_PROC_ROOT': str(root / 'absent')}, diagnostic='regular expression')
        stat_path = root / '2000000001/stat'
        stat_path.write_text(stat_path.read_text().replace('1001 4096000', '1000 4096000'))
        run(['-n', '-c', '^worker00[01]$'], [2000000001])
        run(['-o', '-c', '^worker00[01]$'], [2000000000])

        # Complete cmdline matching, embedded newline normalization, empty
        # command lines, malformed status/stat and vanished process records.
        (root / '2000000000/cmdline').write_bytes(b'prefix\0' + b'x' * 10000 + b'\0TAIL\0')
        run(['-c', '-f', 'TAIL$'], [2000000000])
        run(['-c', '-f', '-x', 'prefix x+ TAIL'], [2000000000])
        (root / '2000000000/cmdline').write_bytes(b'line1\nline2\0')
        run(['-c', '-f', '-x', 'line1 line2'], [2000000000])
        (root / '2000000000/cmdline').write_bytes(b'')
        run(['-c', '-f', '-x', ''], [])
        (root / '2000000000/status').write_text('Uid:\t1001\t2001\nGid:\t3001\t3001\n')
        run(['-c', '-u2001', '-x', 'worker000'], [])
        (root / '2000000000/stat').write_text('2000000000 (bad) S -77 88 99\n')
        run(['-c', '-P77', '-x', 'worker000'], [])
        (root / '2000000000/comm').unlink()
        run(['-c', '-x', 'worker000'], [])
        (root / '2000000000/comm').write_text('forbidden\n')
        for name in ('02000000000', '2147483648', '2000000000x', '0'):
            d = root / name
            d.mkdir()
            (d / 'comm').write_text('forbidden\n')
        run(['-c', 'forbidden'], [2000000000])
    return count


def persistent_checks(binary, shim):
    with tempfile.TemporaryDirectory(prefix='sol-pkill-persistent-') as tmp:
        root = Path(tmp) / 'proc'
        root.mkdir()
        load_fixture_module().fixture(root)
        log = Path(tmp) / 'signals'
        log.write_text('')
        env = dict(clean_env(), LD_PRELOAD=shim, SOL_PKILL_PROC_ROOT=str(root),
                   SOL_PKILL_LOG=str(log))
        script = r'''
printf '%s\n' "$$"
read -r ready
before=(/dev/fd/*)
for ((i=0;i<100;i++)); do
  pkill -USR1 -c -x worker000 || exit 11
  pkill -9 '[' >/dev/null 2>&1; [[ $? == 2 ]] || exit 12
  pkill -0 -c -u2002 -x worker001 || exit 13
  pkill -c -x nomatch; [[ $? == 1 ]] || exit 14
done
pkill -USR2 -c -x worker000 >/dev/full 2>/dev/null; [[ $? == 3 ]] || exit 15
pkill -USR2 -c -x worker000 >&- 2>/dev/null; [[ $? == 3 ]] || exit 16
pkill -TERM -c -x worker000 || exit 17
pkill -c -x self-fixture; [[ $? == 1 ]] || exit 18
after=(/dev/fd/*)
[[ ${#before[@]} -ge 3 && ${#before[@]} == ${#after[@]} ]] || exit 19
printf 'fds:%d\n' "${#after[@]}"
'''
        p = subprocess.Popen([binary, '--noprofile', '--norc', '-c', script], env=env,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        try:
            assert select.select([p.stdout], [], [], 10)[0], 'shell did not start'
            pid = int(p.stdout.readline())
            (root / str(pid)).mkdir()
            (root / str(pid) / 'comm').write_text('self-fixture\n')
            out, err = p.communicate('ready\n', timeout=60)
        finally:
            if p.poll() is None:
                p.kill()
            p.wait()
        assert p.returncode == 0, (p.returncode, out[-200:], err)
        assert out.splitlines()[:-1] == ['1', '1', '0'] * 100 + ['1', '0'], out[-200:]
        assert out.splitlines()[-1].startswith('fds:'), out[-200:]
        actual = [tuple(map(int, x.split())) for x in log.read_text().splitlines()]
        assert actual == [(2000000000, signal.SIGUSR1, 0), (2000000001, 0, 0)] * 100 + [
            (2000000000, signal.SIGUSR2, 0), (2000000000, signal.SIGUSR2, 0),
            (2000000000, signal.SIGTERM, 0)], actual[-10:]
    return 1


def race_check(binary, shim):
    """Synchronize removal after cmdline opens but before it is consumed."""
    with tempfile.TemporaryDirectory(prefix='sol-pkill-race-') as tmp:
        root = Path(tmp) / 'proc'
        entry = root / '2000000600'
        entry.mkdir(parents=True)
        fifo = entry / 'cmdline'
        os.mkfifo(fifo)
        log = Path(tmp) / 'signals'
        log.write_text('')
        env = dict(clean_env(), LD_PRELOAD=shim, SOL_PKILL_PROC_ROOT=str(root),
                   SOL_PKILL_LOG=str(log), SOL_PKILL_FAIL=f'2000000600:{errno.ESRCH}')
        p = subprocess.Popen([binary, '-c', "pkill -USR1 -f -c -x vanishing"],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        writer = None
        try:
            deadline = time.monotonic() + 10
            while writer is None:
                try:
                    writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as error:
                    assert error.errno == errno.ENXIO and time.monotonic() < deadline, error
                    time.sleep(.01)
            fifo.unlink()
            entry.rmdir()
            os.write(writer, b'vanishing\0')
            os.close(writer)
            writer = None
            out, err = p.communicate(timeout=10)
            assert (p.returncode, out, err) == (1, '0\n', ''), (p.returncode, out, err)
            assert log.read_text() == f'2000000600 {signal.SIGUSR1} {errno.ESRCH}\n'
        finally:
            if writer is not None:
                os.close(writer)
            if p.poll() is None:
                p.kill()  # only this test-owned shell, never a fixture PID
                p.wait()
    return 1


def live_checks(binary):
    """Every query has this Python parent's PID selector and unique child comm.
    Real signals are sent only to these direct children; cleanup uses their PIDs.
    Child acknowledgements prevent standard-signal coalescing from hiding loss.
    """
    stem = f'spk{os.getpid():x}'
    children = []
    count = 0
    env = clean_env()
    previous_chld = signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    try:
        for suffix in ('a', 'b', 'skip'):
            readfd, writefd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(readfd)
                if ctypes.CDLL(None).prctl(15, (stem + suffix).encode(), 0, 0, 0):
                    os._exit(99)
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                for number in (signal.SIGUSR1, signal.SIGUSR2):
                    signal.signal(number, lambda sig, frame: os.write(writefd, f'{sig}\n'.encode()))
                os.write(writefd, b'ready\n')
                while True:
                    signal.pause()
            os.close(writefd)
            children.append((pid, readfd))
            assert select.select([readfd], [], [], 5)[0] and os.read(readfd, 32) == b'ready\n'

        def check(options, pattern, expected, sig=None, status=0):
            nonlocal count
            cmd = ['pkill', *options, '-c', '-P', str(os.getpid()), '-x', pattern]
            p = subprocess.run([binary, '-c', shlex.join(cmd)], env=env,
                               capture_output=True, text=True, timeout=15)
            assert (p.returncode, p.stdout) == (status, f'{len(expected)}\n'), (cmd, p)
            for index, (pid, fd) in enumerate(children):
                if index in expected and sig:
                    assert select.select([fd], [], [], 5)[0], (index, 'no acknowledgement')
                    assert os.read(fd, 32) == f'{sig}\n'.encode()
                else:
                    assert not select.select([fd], [], [], 0)[0], (index, 'unexpected signal')
                os.kill(pid, 0)
            count += 1

        check(['-USR1'], stem + '(a|b)', {0, 1}, signal.SIGUSR1)
        check([f'-{signal.SIGUSR2}'], stem + 'a', {0}, signal.SIGUSR2)
        check(['-sigusr1', '-u', str(os.geteuid()), '-U', str(os.getuid()),
               '-G', str(os.getgid()), '-g0', '-s0'], stem + 'b', {1}, signal.SIGUSR1)
        check(['-USR1', '-u', pwd.getpwuid(os.geteuid()).pw_name,
               '-G', grp.getgrgid(os.getgid()).gr_name], stem + 'a', {0}, signal.SIGUSR1)
        check(['-0'], stem + '(a|b)', {0, 1})
        ranks = []
        for index, (pid, _) in enumerate(children[:2]):
            start = int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
            ranks.append((start, pid, index))
        check(['-USR1', '-n'], stem + '(a|b)', {max(ranks)[2]}, signal.SIGUSR1)
        check([f'-{signal.SIGUSR2}', '-o'], stem + '(a|b)', {min(ranks)[2]}, signal.SIGUSR2)
        check(['-TERM'], stem + 'absent', set(), status=1)
        for args in (['-USR1', '['], ['-TERM', stem + '.*', 'extra'],
                     ['-USR1', '-u', 'invalid-sol-pkill-user', stem + '.*']):
            p = subprocess.run([binary, '-c', shlex.join(
                ['pkill', '-P', str(os.getpid()), *args])], env=env,
                capture_output=True, text=True, timeout=15)
            assert p.returncode == 2 and not p.stdout, p
            for pid, fd in children:
                assert not select.select([fd], [], [], 0)[0]
                os.kill(pid, 0)
            count += 1
        # Default TERM must actually terminate exactly the two selected children.
        p = subprocess.run([binary, '-c', shlex.join([
            'pkill', '-c', '-P', str(os.getpid()), '-x', stem + '(a|b)'])],
            env=env, capture_output=True, text=True, timeout=15)
        assert (p.returncode, p.stdout) == (0, '2\n'), p
        for _ in range(2):
            pid, fd = children[0]
            assert select.select([fd], [], [], 5)[0]
            assert os.read(fd, 32) == b''
            waited, status = os.waitpid(pid, 0)
            children.pop(0)  # never retain a reaped PID as a cleanup target
            os.close(fd)
            assert waited == pid and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGTERM
        os.kill(children[0][0], 0)
        count += 1
    finally:
        for pid, fd in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
            os.close(fd)
        signal.signal(signal.SIGCHLD, previous_chld)
    return count


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--shim', type=Path)
    ap.add_argument('--sanitizer', action='store_true')
    ap.add_argument('--regression', choices=('cluster', 'age', 'errors'))
    args = ap.parse_args()
    binary = str(args.binary.resolve(strict=True))
    shim = str(args.shim.resolve(strict=True)) if args.shim else None
    assert args.sanitizer or shim
    checks = fixture_checks(binary, shim, args.sanitizer, args.regression)
    if not args.sanitizer and not args.regression:
        checks += persistent_checks(binary, shim)
        checks += race_check(binary, shim)
        checks += live_checks(binary)
    print(f'PASS: {checks} pkill cases' + ('; each fixture case repeated 25 times under ASan/UBSan' if args.sanitizer else ''))


if __name__ == '__main__':
    main()
