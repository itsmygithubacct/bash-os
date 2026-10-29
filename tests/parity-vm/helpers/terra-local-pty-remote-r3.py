#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only independent BSCR frames and fixture-owned loopback SSH peer."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import time
import tty
import uuid

HOME = Path('/tmp/parity-home')
SELF = '/opt/bashos-parity/harness/helpers/terra-local-pty-remote-r3.py'
PORT = 20861
CLIENT = b'client-payload!'
REMOTE = b'remote-payload'
ACK = b'ack'


def frame(kind, payload):
    return b'BSCR' + bytes([1, kind]) + struct.pack('>I', len(payload)) + payload


def save(name, data):
    (HOME / name).write_bytes(data)


def write_all(fd, data):
    pending = memoryview(data)
    while pending:
        written = os.write(fd, pending)
        if written <= 0:
            raise OSError('short peer write')
        pending = pending[written:]


def fixtures():
    root = HOME / 'frames'
    root.mkdir(mode=0o700)
    examples = [('pty', 1, b'hi!'), ('query', 2, b''), ('control', 3, b'resize 24 80')]
    for label, kind, payload in examples:
        (root / (label + '.frame')).write_bytes(frame(kind, payload))
        (root / (label + '.decoded')).write_bytes(
            b'type=' + label.encode() + b'\nlen=' + str(len(payload)).encode() + b'\npayload=' + payload + b'\n')
    payload = b'x' * (1024 * 1024)
    (root / 'maximum.payload').write_bytes(payload)
    (root / 'maximum.frame').write_bytes(frame(1, payload))
    (root / 'maximum.decoded').write_bytes(b'type=pty\nlen=1048576\npayload=' + payload + b'\n')
    binary = b'A\x00\xffB'
    (root / 'binary.frame').write_bytes(frame(1, binary))
    (root / 'binary.decoded').write_bytes(b'type=pty\nlen=4\npayload=' + binary + b'\n')
    malformed = {
        'short-header': b'BSC',
        'bad-magic': b'NOPE' + bytes([1, 1]) + struct.pack('>I', 0),
        'bad-version': b'BSCR' + bytes([2, 1]) + struct.pack('>I', 0),
        'bad-type': b'BSCR' + bytes([1, 9]) + struct.pack('>I', 0),
        'short-payload': b'BSCR' + bytes([1, 1]) + struct.pack('>I', 4) + b'ab',
        'over-limit': b'BSCR' + bytes([1, 1]) + struct.pack('>I', 1024 * 1024 + 1),
    }
    for label, data in malformed.items():
        (root / (label + '.frame')).write_bytes(data)


def frame_evidence(encode_rc, decode_rc):
    paths = {'expected_frame': HOME / 'frames/maximum.frame',
             'actual_frame': HOME / 'maximum-encoded',
             'expected_decoded': HOME / 'frames/maximum.decoded',
             'actual_decoded': HOME / 'maximum-decoded'}
    records = {}
    for label, path in paths.items():
        try:
            digest = hashlib.sha256()
            size = 0
            first = b''
            last = b''
            with path.open('rb') as source:
                while True:
                    chunk = source.read(65536)
                    if not chunk:
                        break
                    if not first:
                        first = chunk[:16]
                    last = (last + chunk)[-16:]
                    size += len(chunk)
                    digest.update(chunk)
            records[label] = {'length': size, 'sha256': digest.hexdigest(),
                              'first_hex': first.hex(), 'last_hex': last.hex()}
        except OSError as exc:
            records[label] = {'error': '%s: %s' % (type(exc).__name__, exc)}
    save('frame-boundary-observation.json', (json.dumps(
        {'encode_status': int(encode_rc), 'decode_status': int(decode_rc),
         'files': records}, indent=2, sort_keys=True) + '\n').encode())


def read_exact(fd, count, seconds=5, trace=None):
    end = time.monotonic() + seconds
    result = bytearray()
    while len(result) < count:
        remaining = end - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise TimeoutError('peer input %d/%d' % (len(result), count))
        chunk = os.read(fd, count - len(result))
        if not chunk:
            raise EOFError('peer input %d/%d' % (len(result), count))
        result.extend(chunk)
        if trace is not None:
            trace.extend(chunk)
    return bytes(result)


def peer():
    pid = os.getpid()
    prefix = 'ssh-peer-%d-' % pid
    record = {'pid': pid, 'start_line_base64': '', 'input_base64': '',
              'outbound_base64': base64.b64encode(frame(1, REMOTE)).decode(),
              'valid_input': False, 'phases': []}
    line, incoming = bytearray(), bytearray()
    try:
        attrs = termios.tcgetattr(0)
        record['termios_before'] = {'iflag': attrs[0], 'oflag': attrs[1],
                                    'cflag': attrs[2], 'lflag': attrs[3]}
        record['phases'].append({'phase': 'pre-raw', 'monotonic_ns': time.monotonic_ns()})
        save(prefix + 'pre-raw', b'1\n')
        # The startup line can arrive while the forced command is starting.
        # TCSAFLUSH discards that queued line; first prove it is readable,
        # then switch with TCSANOW so the already-arrived bytes survive.
        if not select.select([0], [], [], 8)[0]:
            raise TimeoutError('startup line was not queued')
        record['phases'].append({'phase': 'startup-readable', 'monotonic_ns': time.monotonic_ns()})
        save(prefix + 'queued', b'1\n')
        if not wait_for(lambda: (HOME / (prefix + 'release-raw')).is_file(), seconds=8):
            raise TimeoutError('raw transition was not released')
        tty.setraw(0, termios.TCSANOW)
        attrs = termios.tcgetattr(0)
        record['termios_after'] = {'iflag': attrs[0], 'oflag': attrs[1],
                                   'cflag': attrs[2], 'lflag': attrs[3]}
        record['phases'].append({'phase': 'raw', 'monotonic_ns': time.monotonic_ns()})
        save(prefix + 'ready', b'1\n')
        while not line.endswith(b'\n') and len(line) < 512:
            line.extend(read_exact(0, 1))
        if not line.endswith(b'\n'):
            raise ValueError('missing startup line')
        record['start_line_base64'] = base64.b64encode(line).decode()
        save(prefix + 'startup-line', bytes(line))
        save(prefix + 'started', b'1\n')
        write_all(1, frame(1, REMOTE))
        header = read_exact(0, 10, trace=incoming)
        if header[:6] != b'BSCR\x01\x01':
            raise ValueError('input is not a BSCR PTY frame')
        length = struct.unpack('>I', header[6:])[0]
        if length > 1024:
            raise ValueError('peer frame too large')
        payload = read_exact(0, length, trace=incoming)
        record['valid_input'] = payload == CLIENT
        if not record['valid_input']:
            raise ValueError('wrong framed payload')
        write_all(1, frame(3, ACK))
    except Exception as exc:
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
    record['start_line_base64'] = base64.b64encode(line).decode()
    record['input_base64'] = base64.b64encode(incoming).decode()
    save(prefix + 'result.json', (json.dumps(record, indent=2, sort_keys=True) + '\n').encode())
    return 0 if record['valid_input'] and 'error' not in record else 42


def run_program(argv, **kw):
    return subprocess.run(argv, capture_output=True, timeout=8, **kw)


def listening():
    wanted = '0100007F:%04X' % PORT
    return any(len(parts := line.split()) > 3 and parts[1] == wanted and parts[3] == '0A'
               for line in Path('/proc/net/tcp').read_text().splitlines()[1:])


def wait_for(predicate, seconds=5):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(.03)
    return None


def ready_set():
    return {p.name for p in HOME.glob('ssh-peer-*-pre-raw')}


def next_peer(previous):
    new = sorted(ready_set() - previous)
    if not new:
        return None
    return new[0][:-len('pre-raw')]


def start_server(logname):
    log = (HOME / logname).open('wb')
    proc = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(HOME / 'ssh-server.conf')],
                            stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    if not wait_for(lambda: proc.poll() is None and listening()):
        proc.terminate()
        proc.wait(timeout=3)
        log.close()
        raise RuntimeError('fixture sshd did not listen on loopback')
    return proc, log


def stop_server(server, log):
    report = {'pid': server.pid, 'status_before': server.poll(),
              'terminate_sent': False, 'kill_sent': False}
    if server.poll() is None:
        report['terminate_sent'] = True
        server.terminate()
    try:
        server.wait(timeout=4)
    except subprocess.TimeoutExpired:
        report['kill_sent'] = True
        server.kill()
        server.wait(timeout=3)
    report['status_after'] = server.returncode
    log.close()
    return report


def prepare_ssh():
    username = pwd.getpwuid(os.getuid()).pw_name
    for name in ('ssh-host', 'ssh-client'):
        result = run_program(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                              '-f', str(HOME / name)])
        if result.returncode:
            raise RuntimeError('ssh-keygen failed: ' + result.stderr.decode(errors='replace'))
    host_type, host_key, *_ = (HOME / 'ssh-host.pub').read_text().split()
    save('ssh-known-hosts', ('[127.0.0.1]:%d %s %s\n' % (PORT, host_type, host_key)).encode())
    save('ssh-authorized-keys', (HOME / 'ssh-client.pub').read_bytes())
    config = '\n'.join([
        'ListenAddress 127.0.0.1', 'Port %d' % PORT,
        'HostKey ' + str(HOME / 'ssh-host'),
        'AuthorizedKeysFile ' + str(HOME / 'ssh-authorized-keys'),
        'PidFile ' + str(HOME / 'ssh-server.pid'),
        'StrictModes no', 'UsePAM no', 'PasswordAuthentication no',
        'KbdInteractiveAuthentication no', 'PubkeyAuthentication yes',
        'PrintMotd no', 'PrintLastLog no', 'LogLevel ERROR',
        'ForceCommand cd /tmp/parity-case && HOME=/tmp/parity-home exec /usr/bin/python3 ' + SELF + ' ssh-peer', ''
    ])
    save('ssh-server.conf', config.encode())
    server, log = start_server('ssh-control-server.log')
    old = ready_set()
    client = None
    report = {'user': username, 'port': PORT}
    try:
        argv = ['/usr/bin/ssh', '-tt', '-F', '/dev/null', '-o', 'BatchMode=yes',
                '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
                '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=' + str(HOME / 'ssh-known-hosts'),
                '-o', 'ConnectTimeout=4', '-i', str(HOME / 'ssh-client'),
                '-p', str(PORT), username + '@127.0.0.1']
        client = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        prefix = wait_for(lambda: next_peer(old))
        if not prefix:
            raise RuntimeError('OpenSSH control did not reach the forced peer')
        client.stdin.write(b'control-start\n')
        client.stdin.flush()
        if not wait_for(lambda: (HOME / (prefix + 'queued')).is_file(), seconds=8):
            raise RuntimeError('control startup line was not observed queued')
        save(prefix + 'release-raw', b'1\n')
        if not wait_for(lambda: (HOME / (prefix + 'ready')).is_file(), seconds=8):
            raise RuntimeError('control peer did not enter raw mode')
        client.stdin.write(frame(1, CLIENT))
        client.stdin.close()
        client.stdin = None
        out, err = client.communicate(timeout=8)
        result_path = HOME / (prefix + 'result.json')
        if not wait_for(result_path.is_file):
            raise RuntimeError('OpenSSH peer result missing')
        peer_result = json.loads(result_path.read_text())
        report.update(status=client.returncode, stdout_base64=base64.b64encode(out[:16384]).decode(),
                      stderr_base64=base64.b64encode(err[:16384]).decode(), peer=peer_result)
        expected_frames = frame(1, REMOTE) + frame(3, ACK)
        # A canonical remote tty may echo exactly the control startup line
        # before the peer changes its mode. Retain and identify this prefix.
        if out == expected_frames:
            report['control_echo_base64'] = ''
        elif out == b'control-start\r\n' + expected_frames:
            report['control_echo_base64'] = base64.b64encode(b'control-start\r\n').decode()
        else:
            raise RuntimeError('independent OpenSSH control received unexpected bytes')
        if (client.returncode != 0 or not peer_result['valid_input']
                or base64.b64decode(peer_result['start_line_base64']) != b'control-start\n'):
            raise RuntimeError('independent OpenSSH framed control failed')
    finally:
        if client is not None and client.poll() is None:
            client.terminate()
            client.wait(timeout=3)
        report['server_cleanup'] = stop_server(server, log)
        save('ssh-control.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())


def process_snapshot(pid):
    path = Path('/proc') / str(pid)
    try:
        text = (path / 'stat').read_text()
        fields = text[text.rindex(')') + 2:].split()
        return {'pid': pid, 'state': fields[0], 'ppid': int(fields[1]),
                'starttime': int(fields[19]), 'uid': path.stat().st_uid, 'stat': text.strip()}
    except FileNotFoundError:
        return {'pid': pid, 'absent': True}
    except (OSError, ValueError, IndexError) as exc:
        return {'pid': pid, 'error': '%s: %s' % (type(exc).__name__, exc)}


def stream_snapshot(stream):
    stream.flush()
    size = os.fstat(stream.fileno()).st_size
    stream.seek(0)
    raw = stream.read(16384)
    return {'size': size, 'captured_bytes': len(raw), 'truncated': size > len(raw),
            'base64': base64.b64encode(raw).decode()}


def observe_ssh(shell):
    checks, report = [], {'events': []}
    server = client = log = out_file = err_file = None
    prefix = None
    peer_before = None

    def check(name, value):
        checks.append({'name': name, 'ok': bool(value)})
        print(name + ('=PASS' if value else '=FAIL'), flush=True)

    try:
        control = json.loads((HOME / 'ssh-control.json').read_text())
        check('independent-ssh-frame-control', control.get('status') == 0 and control['peer']['valid_input'])
        username = pwd.getpwuid(os.getuid()).pw_name
        cluster = HOME / 'ssh-cluster'
        cluster.mkdir(mode=0o700)
        (cluster / 'members').write_text('n1 %s@127.0.0.1:%d %s\n' % (username, PORT, HOME / 'ssh-client'))
        old = ready_set()
        server, log = start_server('ssh-live-server.log')
        env = dict(os.environ, BASHCLUSTER_STATE_DIR=str(cluster),
                   BASHSSH_KNOWN_HOSTS=str(HOME / 'ssh-known-hosts'),
                   BASHSSH_STRICT_HOST_KEY_CHECKING='yes', BASHSCREEN_ROAM_RECONNECT='0')
        for key in ('BASHSCREEN_REMOTE_BASH', 'BASHSCREEN_REMOTE_STATE_DIR', 'BASHSCREEN_STATE_DIR'):
            env.pop(key, None)
        out_file = (HOME / 'ssh-live-client.stdout').open('w+b')
        err_file = (HOME / 'ssh-live-client.stderr').open('w+b')
        client = subprocess.Popen([shell, '--noprofile', '--norc', '-c',
                                   'screen attach n1/work --remote'], env=env,
                                  stdin=subprocess.PIPE, stdout=out_file, stderr=err_file)
        report['client_pid'] = client.pid
        prefix = wait_for(lambda: next_peer(old), seconds=7)
        if not prefix:
            raise RuntimeError('candidate did not reach SSH peer')
        peer_pid_text = prefix.split('-')[2]
        if not peer_pid_text.isdigit():
            raise RuntimeError('invalid peer marker')
        peer_before = process_snapshot(int(peer_pid_text))
        report['peer_before_cleanup'] = peer_before
        if not wait_for(lambda: (HOME / (prefix + 'queued')).is_file(), seconds=8):
            raise RuntimeError('candidate startup line was not observed queued')
        save(prefix + 'release-raw', b'1\n')
        if not wait_for(lambda: (HOME / (prefix + 'ready')).is_file(), seconds=8):
            raise RuntimeError('candidate peer did not enter raw mode')
        started = wait_for(lambda: (HOME / (prefix + 'started')).is_file(), seconds=7)
        if not started:
            raise RuntimeError('candidate did not send remote startup line')
        startup = (HOME / (prefix + 'startup-line')).read_bytes()
        report['startup_line_base64'] = base64.b64encode(startup).decode()
        check('live-peer-startup-line', startup == b'exec screen attach work -r\n')
        if startup != b'exec screen attach work -r\n':
            raise RuntimeError('candidate startup line does not identify the requested attach')
        client.stdin.write(CLIENT)
        client.stdin.flush()
        result_path = HOME / (prefix + 'result.json')
        if not wait_for(result_path.is_file, seconds=7):
            raise RuntimeError('candidate peer did not finish')
        client.stdin.close()
        client.stdin = None
        client.wait(timeout=7)
        out_snapshot = stream_snapshot(out_file)
        out = base64.b64decode(out_snapshot['base64'])
        peer_result = json.loads(result_path.read_text())
        report.update(status=client.returncode, peer=peer_result)
        check('live-peer-receives-framed-input', peer_result.get('valid_input') is True)
        check('live-peer-frame-delivered-as-payload', out_snapshot['size'] == len(REMOTE) and out == REMOTE)
        check('remote-attach-success', client.returncode == 0)
    except Exception as exc:
        report['exception'] = '%s: %s' % (type(exc).__name__, exc)
        check('fixture-completed', False)
    finally:
        cleanup = {'client_launched': client is not None, 'client_terminate_sent': False,
                   'client_kill_sent': False, 'client_status_before': None,
                   'client_status_after': None, 'server': None, 'peer_after': None}
        if client is not None:
            cleanup['client_status_before'] = client.poll()
            if client.stdin is not None:
                try:
                    client.stdin.close()
                except OSError as exc:
                    cleanup['stdin_close_error'] = '%s: %s' % (type(exc).__name__, exc)
                client.stdin = None
            if client.poll() is None:
                # Give an EOF-aware client a short opportunity to exit before
                # signaling its owned Popen handle.
                try:
                    client.wait(timeout=.5)
                except subprocess.TimeoutExpired:
                    cleanup['client_terminate_sent'] = True
                    client.terminate()
                    try:
                        client.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        cleanup['client_kill_sent'] = True
                        client.kill()
                        try:
                            client.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            cleanup['client_still_alive'] = True
            cleanup['client_status_after'] = client.returncode
        if server is not None:
            try:
                cleanup['server'] = stop_server(server, log)
            except Exception as exc:
                cleanup['server_error'] = '%s: %s' % (type(exc).__name__, exc)
        if prefix:
            result_path = HOME / (prefix + 'result.json')
            wait_for(result_path.is_file, seconds=2)
            if result_path.is_file():
                try:
                    report['peer_after_cleanup'] = json.loads(result_path.read_text())
                except (OSError, ValueError) as exc:
                    report['peer_after_cleanup'] = {'error': '%s: %s' % (type(exc).__name__, exc)}
            else:
                report['peer_after_cleanup'] = {'result_missing': True, 'prefix': prefix}
        else:
            report['peer_after_cleanup'] = {'peer_not_observed': True}
        if peer_before and 'pid' in peer_before:
            wait_for(lambda: (lambda state: state.get('absent') or state.get('state') == 'Z'
                              or ('starttime' in state and 'starttime' in peer_before
                                  and state['starttime'] != peer_before['starttime']))(
                                  process_snapshot(peer_before['pid'])), seconds=2)
            cleanup['peer_after'] = process_snapshot(peer_before['pid'])
        for label, stream in (('client_stdout', out_file), ('client_stderr', err_file)):
            if stream is None:
                report[label] = {'not_created': True}
                continue
            try:
                report[label] = stream_snapshot(stream)
            except OSError as exc:
                report[label] = {'error': '%s: %s' % (type(exc).__name__, exc)}
            finally:
                stream.close()
        report['cleanup'] = cleanup
        peer_after = cleanup['peer_after']
        peer_gone = (peer_after is None or peer_after.get('absent') or peer_after.get('state') == 'Z'
                     or (peer_before is not None and 'starttime' in peer_after and 'starttime' in peer_before
                         and peer_after['starttime'] != peer_before['starttime']))
        clean = (client is not None and client.returncode is not None and not cleanup['client_terminate_sent']
                 and not cleanup['client_kill_sent'] and cleanup.get('server') is not None
                 and not cleanup['server'].get('kill_sent') and peer_gone)
        check('owned-cleanup', clean)
        save('ssh-live.json', (json.dumps({'checks': checks, **report}, indent=2, sort_keys=True) + '\n').encode())
    return 0 if checks and all(c['ok'] for c in checks) else 1


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
    args = sys.argv[1:]
    if args == ['fixtures']:
        fixtures()
    elif len(args) == 3 and args[0] == 'frame-evidence':
        frame_evidence(args[1], args[2])
    elif args == ['ssh-peer']:
        raise SystemExit(peer())
    elif args == ['ssh-control']:
        prepare_ssh()
    elif len(args) == 2 and args[0] == 'ssh-observe':
        raise SystemExit(observe_ssh(args[1]))
    else:
        raise SystemExit('invalid fixture arguments')
