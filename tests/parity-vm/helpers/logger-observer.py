#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only AF_UNIX datagram observer for the documented bashlogger contract.

The receiver is bound before each invocation and drained after the child exits.
Linux datagram enqueueing completes before sendto returns, so absence and extra
packet checks need no timing window. Raw bytes and process statuses are retained.
Priority numbers come from Python's independent SysLogHandler table.
"""
import base64
import json
from logging.handlers import SysLogHandler
import os
from pathlib import Path
import socket
import subprocess
import sys
import uuid


ROOT = Path('/opt/bashos-parity')
GUARD = ROOT / 'harness/helpers/system-sequence.py'


def require_guest():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    uuid.UUID(marker)
    # The root evaluator checks the UUID match. This unprivileged observer
    # cannot read the kernel's root-only product_uuid attribute.
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU'
    assert Path.cwd() == Path('/tmp/parity-case')
    assert os.geteuid() == 2000


def receiver(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(path)
    sock.setblocking(False)
    return sock


def drain(sock):
    packets = []
    while True:
        try:
            packets.append(sock.recv(65536))
        except BlockingIOError:
            return packets


def tracing(log):
    return ['/usr/bin/python3', str(GUARD), '--notify', 'socket', '--reply', 'socket=continue',
            '--log-args', 'socket=0,1,2', '--notify', 'write:0=1', '--reply', 'write=continue',
            '--log-args', 'write=0,2', '--log-mem', 'write=1:64', '--log', str(log), '--']


def socket_observations(log, marker):
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    markers = before = after = 0
    for row in rows:
        if row['syscall'] == 'write':
            data = bytes.fromhex(row.get('memory1', {}).get('hex', ''))[:row['arg2']]
            if data == marker:
                markers += 1
        elif row['syscall'] == 'socket':
            if markers:
                after += 1
            else:
                before += 1
    return {'markers': markers, 'before_marker': before, 'after_marker': after, 'records': rows}


def setup():
    with receiver('control.sock') as server:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
            client.sendto(b'control\x00\r\n\xff', 'control.sock')
        assert drain(server) == [b'control\x00\r\n\xff']
        assert drain(server) == []
    Path('control.sock').unlink()
    scripts = [
        ("import os,socket; os.write(1,b'LOGGER-BEGIN:1\\n'); socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)", 0, 1),
        ("import os; os.write(1,b'LOGGER-BEGIN:1\\n')", 0, 0),
        ("import os,socket; socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); os.write(1,b'LOGGER-BEGIN:1\\n')", 1, 0)]
    for index, (script, before, after) in enumerate(scripts):
        log = Path('control-%d.jsonl' % index)
        p = subprocess.run(tracing(log) + ['/usr/bin/python3', '-c', script],
                           capture_output=True, timeout=5)
        assert p.returncode == 0 and p.stdout == b'LOGGER-BEGIN:1\n' and not p.stderr, (p.returncode, p.stderr)
        seen = socket_observations(log, p.stdout)
        assert (seen['markers'], seen['before_marker'], seen['after_marker']) == (1, before, after), seen
    print('receiver-and-socket-observer=verified')


def observe(shell, label, args, *, message=None, pri=13, tag='user', include_pid=False,
            stdin=b'', status=0, diagnostic=None, no_socket=False,
            destination='receiver.sock', bound='receiver.sock', socket_expectation=None):
    if no_socket:
        socket_expectation = 0
    traced = socket_expectation is not None
    with receiver(bound) as server:
        env = dict(os.environ, BASHLOGGER_SOCKET=destination)
        argv = [shell, '--noprofile', '--norc', '-c',
                'printf "LOGGER-BEGIN:%s\\n" "$BASHPID"; bashlogger "$@"', 'logger-case', *args]
        log = Path('trace-'+label+'.jsonl')
        if traced:
            argv = tracing(log) + argv
        proc = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, close_fds=True)
        out, err = proc.communicate(stdin, timeout=5)
        packets = drain(server)
    Path(bound).unlink()
    try:
        child_pid = int(out.decode().removeprefix('LOGGER-BEGIN:').strip())
    except ValueError:
        child_pid = -1
    identity_ok = child_pid > 0 and out == ('LOGGER-BEGIN:%d\n' % child_pid).encode() and (traced or child_pid == proc.pid)
    trace = socket_observations(log, out) if traced else None
    socket_check = 'unchecked' if not traced else str(trace['after_marker']) if trace['markers'] == 1 else 'invalid-marker'
    prefix = '<%d> %s%s: ' % (pri, tag, '[%d]' % child_pid if include_pid else '')
    wanted = [] if message is None else [prefix.encode() + message]
    exact = packets == wanted
    diag_ok = (not err if diagnostic is None else diagnostic.encode() in err)
    row = {'label': label, 'argv': args, 'destination': destination, 'bound': bound,
           'status': proc.returncode, 'expected_status': status, 'pid': child_pid,
           'identity_ok': identity_ok, 'socket_observation': trace,
           'expected_sockets_after_marker': socket_expectation,
           'stdout_base64': base64.b64encode(out).decode(),
           'stderr_base64': base64.b64encode(err).decode(),
           'packets_base64': [base64.b64encode(p).decode() for p in packets],
           'expected_packets_base64': [base64.b64encode(p).decode() for p in wanted]}
    with Path('observations.jsonl').open('a') as stream:
        stream.write(json.dumps(row, sort_keys=True) + '\n')
    print('%s status=%d packets=%d exact=%s diag=%s identity=%s sockets=%s' %
          (label, proc.returncode, len(packets), 'yes' if exact else 'no',
           'yes' if diag_ok else 'no', 'yes' if identity_ok else 'no', socket_check))


def wire(shell):
    observe(shell, 'default', ['hello'], message=b'hello')
    observe(shell, 'socket-observer-positive', ['hello'], message=b'hello', socket_expectation=1)
    for label, flags in [('tag-short', ['-t', 'fixture tag']),
                         ('tag-long', ['--tag', 'fixture tag']),
                         ('tag-equals', ['--tag=fixture tag'])]:
        observe(shell, label, flags + ['hello'], message=b'hello', tag='fixture tag')
    for label, flags in [('priority-short', ['-p', 'local0.info']),
                         ('priority-long', ['--priority', '16.6']),
                         ('priority-equals', ['--priority=134'])]:
        observe(shell, label, flags + ['hello'], message=b'hello', pri=16*8+6)
    for label, flag in [('pid-short', '-i'), ('pid-long', '--id')]:
        observe(shell, label, [flag, '-t', 'fixture', 'hello'], message=b'hello',
                tag='fixture', include_pid=True)


FACILITIES = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
              'uucp', 'cron', 'authpriv', 'ftp'] + ['local%d' % i for i in range(8)]
SEVERITIES = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']
INVALID = ['-1', '192', '999999999999999999999', '0x10', '24.info', 'local0.8',
           '.info', 'user.', 'user.nope', 'absent.info', 'user.info.extra', '+1', ' 1', '']


def priorities(shell):
    for pri in (0, 191):
        observe(shell, 'endpoint-%d' % pri, ['-p', str(pri), 'm'], pri=pri, message=b'm')
    for facility in FACILITIES:
        for severity in SEVERITIES:
            pair = facility + '.' + severity
            pri = SysLogHandler.facility_names[facility]*8 + SysLogHandler.priority_names[severity]
            observe(shell, pair, ['-p', pair, 'm'], pri=pri, message=b'm')
    for facility in range(24):
        for severity in range(8):
            pair = '%d.%d' % (facility, severity)
            observe(shell, pair, ['-p', pair, 'm'], pri=facility*8+severity, message=b'm')
    for pair, pri in [('local0.3', 16*8+3), ('16.info', 16*8+6), ('USER.Notice', 1*8+5),
                      ('security.error', 4*8+3), ('user.warn', 1*8+4), ('user.panic', 1*8)]:
        observe(shell, pair, ['-p', pair, 'm'], pri=pri, message=b'm')
    for name in SEVERITIES + ['error', 'warn', 'panic']:
        pri = 8 + SysLogHandler.priority_names[name]
        observe(shell, 'bare-' + name, ['-p', name, 'm'], pri=pri, message=b'm')
    for index, value in enumerate(INVALID):
        observe(shell, 'invalid-%d' % index, ['-p', value, 'm'], status=2,
                diagnostic='invalid priority', no_socket=True)


def framing(shell):
    for label, args, message in [('empty-middle', ['a', '', 'b'], b'a  b'),
                                 ('empty-first', ['', 'b'], b' b'),
                                 ('empty-last', ['a', ''], b'a '),
                                 ('empty-operand', [''], b''),
                                 ('terminator', ['--', '-x', '--tag=literal'], b'-x --tag=literal')]:
        observe(shell, label, args, message=message)
    for label, data, message in [('stdin-lf', b'a\nb\n', b'a\nb'),
                                 ('stdin-crlf', b'a\r\nb\r\n', b'a\r\nb'),
                                 ('stdin-two-lf', b'a\n\n', b'a\n'),
                                 ('stdin-cr', b'a\r', b'a\r'),
                                 ('stdin-one-lf', b'\n', b'')]:
        observe(shell, label, [], stdin=data, message=message)
    observe(shell, 'stdin-nul', [], stdin=b'before\0after', status=2,
            diagnostic='NUL in message', no_socket=True)
    observe(shell, 'stdin-empty', [], status=2, diagnostic='no message', no_socket=True)
    for count in (2047, 2048):
        data = b'x'*count
        for mode in ('operand', 'stdin'):
            observe(shell, '%s-%d' % (mode, count), [data.decode()] if mode == 'operand' else [],
                    stdin=data if mode == 'stdin' else b'', message=data if count == 2047 else None,
                    status=0 if count == 2047 else 2,
                    diagnostic=None if count == 2047 else 'message too long', no_socket=count == 2048)
    for size in (3071, 3072):
        tag = 't'*(size-8)
        observe(shell, 'formatted-%d' % size, ['-t', tag, 'm'], tag=tag,
                message=b'm' if size == 3071 else None, status=0 if size == 3071 else 2,
                diagnostic=None if size == 3071 else 'formatted message too long', no_socket=size == 3072)


def paths(shell):
    observe(shell, 'missing', ['m'], destination='missing.sock', status=1, diagnostic='sendto')
    Path('regular').write_bytes(b'preserve-this-file\n')
    observe(shell, 'non-socket', ['m'], destination='regular', status=1, diagnostic='sendto')
    print('regular-file-preserved=' + ('yes' if Path('regular').read_bytes() == b'preserve-this-file\n' else 'no'))
    edge = 's'*107
    observe(shell, 'path-107', ['m'], destination=edge, bound=edge, message=b'm')
    for size in (108, 256):
        observe(shell, 'path-%d' % size, ['m'], destination=edge+'x'*(size-107), bound=edge,
                status=1, diagnostic='socket path too long', no_socket=True)


if __name__ == '__main__':
    require_guest()
    if sys.argv[1:] == ['setup']:
        setup()
    else:
        shell, scenario = sys.argv[1:]
        {'wire': wire, 'priorities': priorities, 'framing': framing, 'paths': paths}[scenario](shell)
