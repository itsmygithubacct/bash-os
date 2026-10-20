#!/usr/bin/env python3
"""Production ping correctness with deterministic loopback-only syscall fixtures.
No compilation or timing. Build fixtures separately using sol-ping-build.sh.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import signal
import selectors
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary')
parser.add_argument('fixtures')
parser.add_argument('--sanitize', action='store_true')
parser.add_argument('--native-only', action='store_true')
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
fixtures = Path(args.fixtures).resolve()
module = fixtures / ('fixture-sanitize.so' if args.sanitize else 'fixture.so')
base_env = dict(os.environ, PATH='', LC_ALL='C')
for startup_var in ['BASH_ENV', 'ENV']:
    base_env.pop(startup_var, None)
if args.sanitize:
    base_env.update(LD_PRELOAD=(fixtures/'asan-runtime.txt').read_text().strip(),
                    ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                    UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
checks = 0

def run(script, mode=None, rc=0, load=True):
    global checks
    env = dict(base_env)
    if mode: env['SOL_PING_MODE'] = mode
    prefix = f'enable -f {shlex.quote(str(module))} ping; ' if load else ''
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script],
                       env=env, capture_output=True, text=True, timeout=15)
    assert p.returncode == rc, (script, mode, p.returncode, p.stdout, p.stderr)
    assert 'runtime error:' not in p.stderr and 'AddressSanitizer' not in p.stderr, p.stderr
    checks += 1
    return p


def summary(p, sent, received, loss):
    assert re.search(rf'\b{sent} packets transmitted, {received} received, {loss}% packet loss', p.stdout), p.stdout
    assert ('rtt min/avg/max/mdev' in p.stdout) == (received > 0), p.stdout
    if received:
        values = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', p.stdout)
        assert values, p.stdout
        assert all(float(v) >= 0 for v in values.groups())
    return p

if not args.native_only:
    for family, host in [(4, '127.0.0.1'), (6, '::1')]:
        command = f'ping -{family} -c 3 -W .1 -i .1 {host}'
        for mode in ['clean', 'mixed', 'dgram', 'eintr', 'eagain']:
            p = summary(run(command, mode), 3, 3, 0)
            assert p.stdout.count('icmp_seq=') == 3
            expected_rtt = (5.25 if family == 4 else 3.25) if mode == 'mixed' else .25
            assert f'rtt min/avg/max/mdev = {expected_rtt:.3f}/{expected_rtt:.3f}/{expected_rtt:.3f}/0.000' in p.stdout, p.stdout
            expected_reads = 3 * (21 if family == 4 else 13) if mode == 'mixed' else 3
            if mode == 'mixed':
                # Every rejected malformed packet advances the fake arrival clock.
                assert f'reads={expected_reads}' in p.stderr
            assert f'raw={int(mode != "dgram")}' in p.stderr
            print(f'PASS IPv{family} {mode} request/reply identity and payload')
        p = summary(run(command, 'loss-duplicates'), 3, 2, 33)
        assert 'reads=3' in p.stderr
        print(f'PASS IPv{family} duplicate cannot satisfy next probe; 33% loss')
        for mode in ['timeout', 'late-reply', 'wrong-id', 'wrong-seq', 'wrong-payload']:
            summary(run(command, mode, rc=1), 3, 0, 100)
        p = summary(run(f'ping -{family} -c 10 -w .25 -W 1 -i .1 {host}', 'clean'), 3, 3, 0)
        assert 'elapsed=250.000' in p.stderr, p.stderr
        p = summary(run(f'ping -{family} -c 10 -w .25 -W 1 -i .1 {host}', 'timeout', rc=1), 1, 0, 100)
        assert 'elapsed=250.000' in p.stderr
        p = summary(run(command, 'timeout', rc=1), 3, 0, 100)
        assert 'elapsed=300.000' in p.stderr, p.stderr
        for mode in ['denied', 'denied-access', 'unsupported', 'send-error', 'short-send', 'poll-error',
                     'poll-revents', 'recv-error', 'clock-error', 'clock-late-error', 'clock-backwards', 'sleep-error',
                     'connect-error', 'name-error']:
            p = run(command, mode, rc=1)
            assert p.stderr.strip(), mode
            if mode not in ['denied', 'denied-access', 'unsupported']:
                assert p.stderr.count('FIXTURE sends=') == 1, (mode, p.stderr)
        p = run("trap 'interrupted=yes' INT; before=(/proc/$$/fd/*); "
                + command + '; status=$?; '
                '[[ $status == 1 && $interrupted == yes ]] || exit 8; '
                'after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]]', 'interrupt')
        assert 'sends=1 reads=1' in p.stderr
        print(f'PASS IPv{family} deadline, timeout, permissions and injected failures')
    summary(run('ping -6 -c 1 -q [::1]', 'clean'), 1, 1, 0)
    summary(run('ping -q 127.0.0.1', 'clean'), 5, 5, 0)
    summary(run('ping -q -c 1 -w 86400 127.0.0.1', 'clean'), 1, 1, 0)
    p = summary(run('ping -q -c 2 -i 60 127.0.0.1', 'clean'), 2, 2, 0)
    assert 'elapsed=60000.250' in p.stderr
    p = summary(run('ping -q -c 1 -W 60 127.0.0.1', 'timeout', rc=1), 1, 0, 100)
    assert 'elapsed=60000.000' in p.stderr
    for option, values in [('-c', ['', '0', '-1', '10001', '1.5', 'x', '1x', '999999999999999999999']),
                           ('-W', ['', '0', '.09', '60.1', '-1', 'nan', 'inf', '1x']),
                           ('-i', ['', '0', '.09', '60.1', '-1', 'nan', 'inf', '1x']),
                           ('-w', ['', '0', '.0009', '86401', '-1', 'nan', 'inf', '1x'])]:
        for value in values:
            p = run(f'ping {option} {shlex.quote(value)} 127.0.0.1', 'clean', rc=2)
            assert 'FIXTURE' not in p.stderr
    for command in ['ping', 'ping -c', 'ping -w', 'ping -Z 127.0.0.1',
                    'ping 127.0.0.1 extra', 'ping selftest-checksum extra', 'ping -T -w 1 127.0.0.1']:
        run(command, 'clean', rc=2)
    for opts, n in [('-c 1 -W 60 -i 60', 1), ('-c 10000 -w .001 -W .1 -i .1', 1),
                    ('-c 10000 -W .1 -i .1', 10000)]:
        summary(run(f'ping -q {opts} 127.0.0.1', 'clean'), n, n, 0)
    p = run('before=(/proc/$$/fd/*); for ((i=0;i<100;i++)); do ping -q -c 1 127.0.0.1 >/dev/null || exit; done; '
            'after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]] || exit 9; '
            'IFS= read -r children </proc/$$/task/$$/children || :; [[ -z $children ]]', 'clean')
    assert p.stderr.count('FIXTURE sends=1 reads=1') == 100
    # A failed write must affect status; a subsequent invocation must recover.
    p = run('ping -q -c 1 127.0.0.1 >/dev/full; r=$?; [[ $r == 1 ]] || exit 8; '
            'ping -q -c 1 127.0.0.1', 'clean')
    summary(p, 1, 1, 0)
    print('PASS parsing boundaries, 10000 probes, repeated calls, descriptor cleanup, output failure')

# Existing production selftests are retained with their original assertions.
for verb, count in [('selftest-checksum', 6), ('selftest-truncated', 6),
                    ('selftest-trace-truncated', 9), ('selftest-ipv6-codec', 11)]:
    p = run(f'ping {verb}', 'clean', load=not args.native_only)
    assert p.stdout.startswith(f'1..{count}\n') and p.stdout.count('\nok ') == count and 'not ok' not in p.stdout
print('PASS all 32 original checksum/truncation/IPv6 codec assertions')
if not args.sanitize:
    for family, host in [(4, '127.0.0.1'), (6, '::1')]:
        for _ in range(2):
            p = summary(run(f'ping -{family} -c 3 -i .1 -W 1 {host}', load=False), 3, 3, 0)
            assert p.stdout.count('icmp_seq=') == 3
        # One persistent shell, native calls with an empty PATH.
        run(f'before=(/proc/$$/fd/*); for ((i=0;i<10;i++)); do ping -{family} -q -c 1 {host} >/dev/null || exit; done; '
            'after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]] || exit 9; '
            'IFS= read -r children </proc/$$/task/$$/children || :; [[ -z $children ]]', load=False)
        print(f'PASS IPv{family} real loopback and native repeated-call FD cleanup')
if not args.sanitize:
    # Interrupt only this owned shell. Its trap verifies that Bash's unwind
    # cleanup closed the raw/datagram socket before returning to the caller.
    script = r"""before=(/proc/$$/fd/*)
trap 'after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]] || exit 9; printf "CLEAN\n"; exit 0' INT
printf 'READY\n'
ping -4 -q -c 10000 -i 60 -W 1 127.0.0.1
exit 10
"""
    child = subprocess.Popen([binary, '--noprofile', '--norc', '-c', script],
                             env=base_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            assert selector.select(5), 'owned shell did not become ready'
        assert child.stdout.readline() == 'READY\n'
        time.sleep(.1)  # synchronization only; this is not a timing measurement
        child.send_signal(signal.SIGINT)
        stdout, stderr = child.communicate(timeout=5)
        assert child.returncode == 0 and 'CLEAN' in stdout, (child.returncode, stdout, stderr)
        checks += 1
        print('PASS owned-shell SIGINT unwinds socket before caller trap')
    finally:
        if child.poll() is None: child.kill()
        child.wait()
print(f'PASS {checks} shell cases')
