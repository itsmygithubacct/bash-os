#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only child, Python syscall reference, and bounded spawn observer."""
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

SELF = '/opt/bashos-parity/harness/helpers/terminal-review112-pty-spawn-r2-2122027aae1f.py'

CANDIDATE = r'''
mode=$1
pty spawn master target /usr/bin/python3 "$HELPER" child "$mode" 2>"$HOME/spawn-call.err"
spawn_rc=$?
printf 'mode=%s\nspawn_rc=%s\nmaster_fd=%s\ntarget_pid=%s\nshell_pid=%s\n' \
  "$mode" "$spawn_rc" "${master-unset}" "${target-unset}" "$BASHPID" >"$HOME/spawn-candidate-values.txt"
if ((spawn_rc != 0)); then printf 'spawn=0\n'; exit 1; fi
printf 'spawn=1\n'
/usr/bin/readlink "/proc/$BASHPID/fd/$master" >"$HOME/spawn-master-before.txt" 2>&1
if [[ -r /proc/$target/stat ]]; then IFS= read -r statline <"/proc/$target/stat"; printf '%s\n' "$statline" >"$HOME/spawn-process-before.txt"; else printf 'absent\n' >"$HOME/spawn-process-before.txt"; fi
line=
IFS= read -r -t 4 -u "$master" line; readrc=$?
printf '%s\n' "$line" >"$HOME/spawn-ready.raw"
printf 'ready_read_rc=%s\n' "$readrc" >>"$HOME/spawn-candidate-values.txt"
line=${line%$'\r'}
IFS=' ' read -r tag childpid session tty stdio <<< "$line"
if [[ $readrc == 0 && $tag == READY && $childpid == "$target" && $session == 1 && $tty == 1 && $stdio == 1 ]]; then
  printf 'wiring-ok=1\n'
else
  printf 'wiring-ok=0\n'
fi
if [[ $mode == io ]]; then
  printf 'ping-fixed\n' >&"$master"
  line=
  IFS= read -r -t 4 -u "$master" line; readrc=$?
  printf '%s\n' "$line" >"$HOME/spawn-reply.raw"
  printf 'reply_read_rc=%s\n' "$readrc" >>"$HOME/spawn-candidate-values.txt"
  line=${line%$'\r'}
  if [[ $readrc == 0 && $line == REPLY=ping-fixed ]]; then printf 'exchange=1\n'; else printf 'exchange=0\n'; fi
  expected=7
else
  expected=143
fi
result=unset
pty waitpid "$target" result 2>"$HOME/spawn-wait.err"; waitrc=$?
printf 'wait_rc=%s\nstatus_variable=%s\n' "$waitrc" "$result" >>"$HOME/spawn-candidate-values.txt"
if [[ $waitrc == "$expected" && $result == "$expected" ]]; then printf 'wait-status=1\n'; else printf 'wait-status=0\n'; fi
pty waitpid "$target" >/dev/null 2>"$HOME/spawn-second-wait.err"; twice=$?
printf 'repeat_wait_rc=%s\n' "$twice" >>"$HOME/spawn-candidate-values.txt"
if ((twice != 0)); then printf 'repeat-wait=1\n'; else printf 'repeat-wait=0\n'; fi
pty close "$master" 2>"$HOME/spawn-close.err"; closer=$?
if [[ -e /proc/$BASHPID/fd/$master ]]; then fd_after=present; else fd_after=absent; fi
printf 'close_rc=%s\nmaster_after_close=%s\n' "$closer" "$fd_after" >>"$HOME/spawn-candidate-values.txt"
if ((closer == 0)) && [[ ! -e /proc/$BASHPID/fd/$master ]]; then printf 'close=1\n'; else printf 'close=0\n'; fi
pty close "$master" >/dev/null 2>"$HOME/spawn-second-close.err"; closer=$?
printf 'repeat_close_rc=%s\n' "$closer" >>"$HOME/spawn-candidate-values.txt"
if ((closer != 0)); then printf 'repeat-close=1\n'; else printf 'repeat-close=0\n'; fi
if [[ ! -e /proc/$target ]]; then child_after=absent; printf 'child-reaped=1\n'; else child_after=present; printf 'child-reaped=0\n'; fi
printf 'child_after_wait=%s\n' "$child_after" >>"$HOME/spawn-candidate-values.txt"
if [[ -r /proc/$target/stat ]]; then IFS= read -r statline <"/proc/$target/stat"; printf '%s\n' "$statline" >"$HOME/spawn-process-after.txt"; else printf 'absent\n' >"$HOME/spawn-process-after.txt"; fi
'''


def child(mode):
    attrs = termios.tcgetattr(0)
    attrs[3] &= ~(termios.ECHO | termios.ECHONL)
    termios.tcsetattr(0, termios.TCSANOW, attrs)
    ident = [os.fstat(n) for n in (0, 1, 2)]
    names = [os.ttyname(n) for n in (0, 1, 2)]
    sid = os.getsid(0)
    pgrp = os.getpgrp()
    terminal_sid = struct.unpack('i', fcntl.ioctl(0, 0x5429, struct.pack('i', 0)))[0]
    foreground = os.tcgetpgrp(0)
    record = {'pid': os.getpid(), 'sid': sid, 'pgrp': pgrp, 'terminal_sid': terminal_sid,
              'foreground_pgrp': foreground, 'tty_names': names,
              'descriptors': [{'fd': n, 'isatty': os.isatty(n), 'device': s.st_dev,
                               'inode': s.st_ino, 'rdev': s.st_rdev, 'mode': s.st_mode}
                              for n, s in enumerate(ident)]}
    Path(os.environ['HOME'], 'spawn-child-identity.json').write_text(
        json.dumps(record, indent=2, sort_keys=True) + '\n')
    session = int(sid == os.getpid() == pgrp and terminal_sid == os.getpid())
    tty = int(re.fullmatch(r'/dev/pts/[0-9]+', names[0]) is not None
              and foreground == pgrp)
    stdio = int(all(os.isatty(n) for n in (0, 1, 2)) and len(set(names)) == 1
                and len({(s.st_dev, s.st_ino, s.st_rdev) for s in ident}) == 1)
    os.write(1, ('READY %d %d %d %d\n' % (os.getpid(), session, tty, stdio)).encode())
    if mode == 'io':
        line = sys.stdin.buffer.readline(128)
        os.write(1, b'REPLY=' + line)
        return 7
    os.kill(os.getpid(), signal.SIGTERM)
    return 99


def readline(fd, deadline):
    data = bytearray()
    while b'\n' not in data and len(data) < 256:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            raise TimeoutError('child output did not arrive')
        data.extend(os.read(fd, 1))
    return bytes(data)


def reference(mode):
    result = {'spawn': False, 'wiring-ok': False, 'wait-status': False,
              'repeat-wait': False, 'close': False, 'repeat-close': False,
              'child-reaped': False}
    if mode == 'io':
        result['exchange'] = False
    raw = {}
    master, slave = os.openpty()
    master_stat, slave_stat = os.fstat(master), os.fstat(slave)
    raw.update(master_fd=master, slave_fd=slave, slave_name=os.ttyname(slave),
               master_identity={'device': master_stat.st_dev, 'inode': master_stat.st_ino, 'rdev': master_stat.st_rdev},
               slave_identity={'device': slave_stat.st_dev, 'inode': slave_stat.st_ino, 'rdev': slave_stat.st_rdev})
    proc = None
    try:
        def setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        proc = subprocess.Popen(['/usr/bin/python3', SELF, 'child', mode],
                                stdin=slave, stdout=slave, stderr=slave, preexec_fn=setup)
        raw['child_pid'] = proc.pid
        os.close(slave)
        slave = -1
        result['spawn'] = True
        first = readline(master, time.monotonic() + 4)
        raw['first_hex'] = first.hex()
        result['wiring-ok'] = first.replace(b'\r\n', b'\n') == ('READY %d 1 1 1\n' % proc.pid).encode()
        if mode == 'io':
            os.write(master, b'ping-fixed\n')
            reply = readline(master, time.monotonic() + 4)
            raw['reply_hex'] = reply.hex()
            result['exchange'] = reply.replace(b'\r\n', b'\n') == b'REPLY=ping-fixed\n'
        code = proc.wait(timeout=4)
        raw['wait_returncode'] = code
        result['wait-status'] = code == (7 if mode == 'io' else -signal.SIGTERM)
        try:
            os.waitpid(proc.pid, os.WNOHANG)
        except ChildProcessError:
            result['repeat-wait'] = True
            raw['repeat_wait'] = 'ECHILD'
        os.close(master)
        result['close'] = True
        try:
            os.fstat(master)
        except OSError as exc:
            result['close'] = exc.errno == errno.EBADF
            raw['fstat_after_close_errno'] = exc.errno
        try:
            os.close(master)
        except OSError as exc:
            result['repeat-close'] = exc.errno == errno.EBADF
            raw['repeat_close_errno'] = exc.errno
        master = -1
        result['child-reaped'] = not Path('/proc/%d' % proc.pid).exists()
        raw['child_after_wait'] = 'absent' if result['child-reaped'] else 'present'
    except Exception as exc:
        raw['exception'] = '%s: %s' % (type(exc).__name__, exc)
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=4)
        if master >= 0:
            os.close(master)
        if slave >= 0:
            os.close(slave)
    return result, raw


def run(mode, side, shell):
    names = ['spawn', 'wiring-ok'] + (['exchange'] if mode == 'io' else []) + [
        'wait-status', 'repeat-wait', 'close', 'repeat-close', 'child-reaped']
    if side == 'reference':
        results, raw = reference(mode)
    else:
        env = dict(os.environ, HELPER=SELF)
        try:
            proc = subprocess.run([shell, '--noprofile', '--norc', '-c', CANDIDATE,
                                   'spawn-fixture', mode], capture_output=True, env=env, timeout=14)
            raw = {'status': proc.returncode, 'stdout_hex': proc.stdout[:16384].hex(),
                   'stderr_hex': proc.stderr[:16384].hex()}
            pairs = re.findall(rb'^([a-z-]+)=([01])$', proc.stdout, re.MULTILINE)
            values = {k.decode(): v == b'1' for k, v in pairs}
            results = {name: values.get(name, False) for name in names}
            if proc.returncode != 0:
                results['spawn'] = False
        except subprocess.TimeoutExpired as exc:
            raw = {'exception': 'candidate timeout',
                   'stdout_hex': (exc.stdout or b'')[:16384].hex(),
                   'stderr_hex': (exc.stderr or b'')[:16384].hex()}
            results = {name: False for name in names}
        except Exception as exc:
            raw = {'exception': '%s: %s' % (type(exc).__name__, exc)}
            results = {name: False for name in names}
    for name in names:
        print(name + ('=PASS' if results.get(name) else '=FAIL'))
    Path(os.environ['HOME'], 'spawn-observation.json').write_text(json.dumps(
        {'mode': mode, 'side': side, 'checks': results, 'raw': raw}, indent=2, sort_keys=True) + '\n')
    return 0 if all(results.get(name) for name in names) else 1


def require_guest():
    # The root guest evaluator verifies the exact UUID; this unprivileged
    # guard checks the readable marker, QEMU vendor, uid and case scratch.
    import uuid
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
        if (vendor != 'QEMU' or os.getuid() != 2000 or os.geteuid() != 2000
                or Path.cwd() != Path('/tmp/parity-case')
                or Path.home() != Path('/tmp/parity-home')):
            raise ValueError('guest identity, fixture uid or scratch mismatch')
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('requires disposable QEMU uid2000 fixture scratch') from exc


if __name__ == '__main__':
    require_guest()
    if len(sys.argv) == 3 and sys.argv[1] == 'child' and sys.argv[2] in ('io', 'signal'):
        raise SystemExit(child(sys.argv[2]))
    if len(sys.argv) != 4 or sys.argv[1] not in ('io', 'signal') or sys.argv[2] not in ('reference', 'candidate'):
        raise SystemExit('invalid fixture arguments')
    raise SystemExit(run(*sys.argv[1:]))
