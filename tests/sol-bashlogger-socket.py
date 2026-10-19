#!/usr/bin/env python3
"""Private AF_UNIX integration checks. Does not compile or use host syslog."""
import argparse
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', nargs='?', default='out/bash-sol-bashlogger')
parser.add_argument('--shim', type=Path)
parser.add_argument('--module', type=Path)
parser.add_argument('--asan-runtime', type=Path)
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
checks = 0
failures = []
prefix = ('enable -f ' + shlex.quote(str(args.module.resolve())) + ' bashlogger || exit 99\n'
          if args.module else '') + 'PATH=\n'

with tempfile.TemporaryDirectory(prefix='blog-') as directory:
    root = Path(directory)
    path = str(root / 'log')
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(path)
    receiver.setblocking(False)
    env = dict(os.environ, LC_ALL='C', PATH='', BASHLOGGER_SOCKET=path)
    env.pop('BASH_ENV', None)
    if args.asan_runtime:
        env.update(LD_PRELOAD=str(args.asan_runtime.resolve()),
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    if args.shim:
        env['LD_PRELOAD'] = str(args.shim.resolve())
        env['BLOG_TEST_AUDIT'] = str(root / 'audit')

    def run(script, data=b'', extra=None):
        return subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script],
                              input=data, capture_output=True, env=env | (extra or {}), timeout=20)

    def drain():
        packets = []
        while True:
            try:
                packets.append(receiver.recv(65536))
            except BlockingIOError:
                return packets

    def check(label, script, expected, status=0, data=b'', extra=None, error=None):
        global checks
        result = run(script, data, extra)
        packets = drain()
        checks += 1
        good = (result.returncode == status and result.stdout == b'' and packets == expected
                and (not result.stderr if status == 0 else bool(result.stderr))
                and (error is None or error in result.stderr)
                and b'runtime error:' not in result.stderr and b'AddressSanitizer' not in result.stderr)
        if not good:
            failures.append(label)
            print(f'FAIL {label}: status={result.returncode}, stdout={result.stdout!r}, '
                  f'stderr={result.stderr[:300]!r}, datagrams={packets!r}')

    check('default numeric header', 'bashlogger hello', [b'<13> user: hello'])
    facilities = {'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3, 'auth': 4, 'syslog': 5,
                  'lpr': 6, 'news': 7, 'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
                  **{f'local{i}': 16+i for i in range(8)}}
    severities = dict(zip(('emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'), range(8)))
    for facility, number in facilities.items():
        for severity, level in severities.items():
            expected = [f'<{number*8+level}> user: message'.encode()]
            check(f'{facility}.{severity}', f'bashlogger -p {facility}.{severity} message', expected)
            check(f'{number}.{level}', f'bashlogger --priority={number}.{level} message', expected)
    for facility in range(12, 16):
        for level in range(8):
            check(f'{facility}.{level}', f'bashlogger -p {facility}.{level} message',
                  [f'<{facility*8+level}> user: message'.encode()])
    for number in range(192):
        check(f'numeric PRI {number}', f'bashlogger -p {number} message',
              [f'<{number}> user: message'.encode()])
    for severity, level in severities.items():
        check(f'bare {severity}', f'bashlogger -p {severity} message', [f'<{8+level}> user: message'.encode()])
        check(f'numeric severity {level}', f'bashlogger -p local7.{level} message',
              [f'<{184+level}> user: message'.encode()])
    for priority, value in [('local0.warn', 132), ('security.error', 35), ('kern.panic', 0),
                            ('LOCAL7.INFO', 190), ('23.debug', 191), ('local0.6', 134)]:
        check(priority, f'bashlogger --priority {priority} message', [f'<{value}> user: message'.encode()])
    check('tags', "bashlogger -t 'my tag' a; bashlogger --tag=other b; bashlogger --tag '' c",
          [b'<13> my tag: a', b'<13> other: b', b'<13> : c'])
    # Use the actual shell PID, also validate include-id state resets on the next call.
    result = run('printf "%s\\n" "$$"; bashlogger --id -t ident hello; bashlogger -i -t ident hello; bashlogger hello')
    pid = int(result.stdout)
    checks += 1
    if (result.returncode, result.stderr, drain()) != (0, b'', [f'<13> ident[{pid}]: hello'.encode(), f'<13> ident[{pid}]: hello'.encode(), b'<13> user: hello']):
        failures.append('id / invocation reset')
    check('argument joining', "bashlogger '' a '' b ''; bashlogger -- -p x; bashlogger ''",
          [b'<13> user:  a  b ', b'<13> user: -p x', b'<13> user: '])
    check('message bytes', "bashlogger 'a%b' $'line1\\nline2' 'é'", [b'<13> user: a%b line1\nline2 \xc3\xa9'])
    check('stdin', 'bashlogger', [b'<13> user: first\nsecond'], data=b'first\nsecond\n')
    check('stdin CRLF', 'bashlogger', [b'<13> user: first\nsecond'], data=b'first\nsecond\r\n')
    check('stdin long line', 'bashlogger', [b'<13> user: ' + b'x'*1500], data=b'x'*1500+b'\n')
    check('repeated stdin EOF reset', 'bashlogger <<< one; bashlogger <<< two', [b'<13> user: one', b'<13> user: two'])
    check('blank stdin line', 'bashlogger', [b'<13> user: '], data=b'\n')
    check('empty stdin', 'bashlogger', [], status=2, error=b'no message')
    check('stdin read failure', 'bashlogger <&-', [], status=1, error=b'read')
    check('stdin NUL', 'bashlogger', [], status=2, data=b'a\0b', error=b'NUL')
    for priority in ('', '-1', '192', '99999999999999999999999', 'bogus', 'user', 'user.bogus',
                     '24.0', '1.8', '.notice', 'user.', 'user.info.more', '+1', '1x', '1.-1'):
        check(f'invalid priority {priority!r}', 'bashlogger -p ' + shlex.quote(priority) + ' hello',
              [], status=2, error=b'priority')
    for flag in ('-t', '--tag', '-p', '--priority', '--bogus'):
        check(f'bad option {flag}', f'bashlogger {flag}', [], status=2)
    check('message max', "printf -v m '%2047s' ''; bashlogger \"${m// /x}\"", [b'<13> user: '+b'x'*2047])
    check('oversized arg', "printf -v m '%2048s' ''; bashlogger \"${m// /x}\"", [], status=2, error=b'too long')
    check('oversized joined', "printf -v m '%1024s' ''; bashlogger \"$m\" \"$m\"", [], status=2, error=b'too long')
    check('oversized stdin', 'bashlogger', [], status=2, data=b'x'*2048, error=b'too long')
    check('datagram max', "printf -v t '%3063s' ''; bashlogger -t \"${t// /t}\" x",
          [b'<13> '+b't'*3063+b': x'])
    check('oversized datagram', "printf -v t '%3064s' ''; bashlogger -t \"$t\" x", [], status=2, error=b'too long')
    check('oversized tag', "printf -v t '%3072s' ''; bashlogger -t \"$t\" x", [], status=2, error=b'too long')
    check('missing socket', 'bashlogger message', [], status=1,
          extra={'BASHLOGGER_SOCKET': str(root/'missing')}, error=b'sendto')
    # A live endpoint at the old truncation target must receive nothing.
    long_base = str(root) + '/' + 'x'*(107-len(str(root))-1)
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as truncated:
        truncated.bind(long_base)
        truncated.setblocking(False)
        check('socket path truncation', 'bashlogger message', [], status=1,
              extra={'BASHLOGGER_SOCKET': long_base+'suffix'}, error=b'path')
        checks += 1
        try:
            truncated.recv(65536)
            failures.append('truncated socket received a datagram')
        except BlockingIOError:
            pass
    regular = root/'regular'
    regular.touch()
    check('non-socket destination', 'bashlogger message', [], status=1,
          extra={'BASHLOGGER_SOCKET': str(regular)}, error=b'sendto')

    # Stop-and-inspect protocol keeps the very same shell alive for all calls.
    repeated = prefix + '''
printf 'ready\\n'
read -r go
for ((i=0;i<200;i++)); do bashlogger -p 999 bad 2>/dev/null; [[ $? == 2 ]] || exit 81; done
for ((i=0;i<200;i++)); do BASHLOGGER_SOCKET="$BASHLOGGER_SOCKET.missing" bashlogger bad 2>/dev/null; [[ $? == 1 ]] || exit 82; done
printf 'failures-done\\n'
read -r go
for ((i=0;i<200;i++)); do bashlogger -p local0.info -t repeat "$i" || exit 83; done
printf 'success-done\\n'
read -r go
'''
    proc = subprocess.Popen([binary, '--noprofile', '--norc', '-c', repeated], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    def descriptors():
        return {p.name: os.readlink(p) for p in Path(f'/proc/{proc.pid}/fd').iterdir()}
    try:
        assert proc.stdout.readline() == b'ready\n'
        before = descriptors()
        proc.stdin.write(b'go\n'); proc.stdin.flush()
        assert proc.stdout.readline() == b'failures-done\n'
        assert descriptors() == before, (before, descriptors())
        assert drain() == []
        proc.stdin.write(b'go\n'); proc.stdin.flush()
        receiver.settimeout(20)
        for i in range(200):
            assert receiver.recv(65536) == f'<134> repeat: {i}'.encode()
        receiver.setblocking(False)
        assert proc.stdout.readline() == b'success-done\n'
        assert descriptors() == before, (before, descriptors())
        proc.stdin.write(b'go\n'); proc.stdin.flush()
        stdout, stderr = proc.communicate(timeout=20)
        assert (proc.returncode, stdout, stderr, drain()) == (0, b'', b'', [])
        checks += 1
    finally:
        if proc.poll() is None:
            proc.kill(); proc.communicate()

    if args.shim:
        for mode in ('fallback', 'eintr'):
            check(mode, 'bashlogger -t shim message', [b'<13> shim: message'], extra={'BLOG_TEST_MODE': mode})
        for mode in ('socket-fail', 'setfd-fail', 'send-fail', 'short-send'):
            check(mode, 'bashlogger message', [], status=1, extra={'BLOG_TEST_MODE': mode})
            check(mode + ' repeated cleanup', '''ulimit -n 32
for ((i=0;i<100;i++)); do bashlogger message 2>/dev/null; [[ $? == 1 ]] || exit 80; done
unset BLOG_TEST_MODE
bashlogger -t recover okay''', [b'<13> recover: okay'], extra={'BLOG_TEST_MODE': mode})
        audit = (root/'audit').read_text().splitlines()
        assert len(audit) >= 200 and set(audit) == {'cloexec+exec-closed'}, audit[:5]
        checks += 1
        print(f'CLOEXEC and exec inheritance checked at {len(audit)} production sendto calls')
    receiver.close()

print(f'{checks} checks, {len(failures)} failures')
if failures:
    print('Failed:', ', '.join(failures))
raise SystemExit(bool(failures))
