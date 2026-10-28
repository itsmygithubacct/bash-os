#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only MAC policy observations with a byte-preserving loopback relay.

Decode RFC4253 identification/clear packets only, stopping each direction at
NEWKEYS. Advertisement, pre-encryption progress and encrypted command success
are distinct observations. No guard, helper or fixture execution on a host.
"""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid


HOME = Path('/tmp/parity-home')
PROXY_PORT = 21223
PORTS = {'default': 21220, 'baseline': 21221, 'restricted': 21222}
CIPHER = 'aes256-ctr'
KEX = 'curve25519-sha256'
VARIANTS = {'standard': ('hmac-sha2-256', 'hmac-sha2-512'),
            'etm': ('hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com')}
LIST_NAMES = ('kex', 'hostkey', 'cipher_c2s', 'cipher_s2c', 'mac_c2s', 'mac_s2c',
              'compression_c2s', 'compression_s2c', 'language_c2s', 'language_s2c')
WIRE_LIMIT = 65536
COMMAND = r"printf 'mac-packet-ok\n'; : > {marker}"


def b64(data):
    return base64.b64encode(data).decode()


def guard():
    if sys.flags.optimize:
        raise RuntimeError("VM fixture requires enabled assertions")
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU'
    assert os.geteuid() == 2000 and Path.cwd() == Path('/tmp/parity-case')
    info = HOME.lstat()
    assert HOME.resolve() == HOME and stat.S_ISDIR(info.st_mode)
    assert info.st_uid == 2000 and not info.st_mode & 0o022


def save(name, data):
    (HOME / name).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def identity(pid):
    try:
        p = Path('/proc') / str(pid)
        text = (p / 'stat').read_text()
        fields = text[text.rindex(')') + 2:].split()
        return {'pid': pid, 'ppid': int(fields[1]), 'start': int(fields[19]),
                'state': fields[0], 'uid': p.stat().st_uid}
    except (FileNotFoundError, ProcessLookupError):
        return None


def live(record):
    now = identity(record['pid'])
    return bool(now and now['uid'] == record['uid'] == 2000 and
                now['start'] == record['start'] and now['state'] != 'Z')


def wait_for(predicate, seconds=3):
    end = time.monotonic() + seconds
    while True:
        value = predicate()
        if value or time.monotonic() >= end:
            return value
        time.sleep(.03)


def ready_listener(record, port, log_path, reference):
    if not live(record):
        return None
    address = '0100007F:%04X' % port
    rows = [x.split() for x in Path('/proc/net/tcp').read_text().splitlines()[1:]
            if len(x.split()) > 9 and x.split()[1] == address and x.split()[3] == '0A']
    # Tie readiness to this newly-created Popen log's post-bind announcement.
    # This prevents a stale listener from making a not-yet-bound child ready,
    # and does not require ptrace access to an OpenSSH master's private fds.
    wanted = (('Server listening on 127.0.0.1 port %d.' % port) if reference else
              ('sshd encrypted listening addr=127.0.0.1 port=%d' % port)).encode()
    return {'tcp_rows': rows, 'server_identity': record,
            'startup_announcement': wanted.decode()} if rows and wanted in log_path.read_bytes() else None


def ssh_string(data, pos):
    if pos + 4 > len(data):
        raise ValueError('short SSH string length')
    size = struct.unpack('!I', data[pos:pos + 4])[0]
    pos += 4
    if size > WIRE_LIMIT or pos + size > len(data):
        raise ValueError('short or oversized SSH string')
    return data[pos:pos + size], pos + size


def decode_stream(raw):
    """Pure decoder, invoked only by the guarded guest after relay collection."""
    result = {'wire_base64': b64(raw), 'wire_sha256': hashlib.sha256(raw).hexdigest(),
              'packets': [], 'newkeys': False, 'kexinit': None}
    try:
        pos = 0
        for _ in range(50):
            end = raw.find(b'\n', pos)
            if end < 0 or end - pos > 1024:
                raise ValueError('missing or oversized identification line')
            line = raw[pos:end + 1]
            pos = end + 1
            if line.startswith(b'SSH-2.0-'):
                result['identification'] = line.decode('ascii').rstrip('\r\n')
                result['identification_end'] = pos
                break
        else:
            raise ValueError('missing SSH2 identification')
        while pos < len(raw):
            offset = pos
            if pos + 5 > len(raw):
                raise ValueError('incomplete clear packet header')
            length = struct.unpack('!I', raw[pos:pos + 4])[0]
            padding = raw[pos + 4]
            end = pos + 4 + length
            if not 12 <= length <= 35000 or end > len(raw) or (length + 4) % 8:
                raise ValueError('invalid or incomplete clear packet framing')
            if not 4 <= padding <= 255 or length - padding - 1 < 1:
                raise ValueError('invalid clear packet padding')
            payload = raw[pos + 5:end - padding]
            message = payload[0]
            packet = {'offset': offset, 'end': end, 'length': length,
                      'padding_length': padding, 'message': message,
                      'packet_sha256': hashlib.sha256(raw[offset:end]).hexdigest()}
            result['packets'].append(packet)
            if message == 20:
                if result['kexinit'] is not None or len(payload) < 17:
                    raise ValueError('invalid duplicate/short KEXINIT')
                cursor, proposal = 17, {}
                for name in LIST_NAMES:
                    value, cursor = ssh_string(payload, cursor)
                    text = value.decode('ascii')
                    names = text.split(',') if text else []
                    if any(not n or any(ord(c) < 33 or ord(c) > 126 for c in n) for n in names):
                        raise ValueError('invalid algorithm name-list')
                    proposal[name] = names
                if cursor + 5 != len(payload) or payload[cursor] not in (0, 1):
                    raise ValueError('invalid KEXINIT tail')
                proposal['first_kex_packet_follows'] = bool(payload[cursor])
                proposal['reserved'] = struct.unpack('!I', payload[cursor + 1:cursor + 5])[0]
                if proposal['reserved'] != 0:
                    raise ValueError('nonzero KEXINIT reserved field')
                proposal['packet_offset'] = offset
                proposal['packet_end'] = end
                result['kexinit'] = proposal
            elif message == 1:
                reason = struct.unpack('!I', payload[1:5])[0]
                description, cursor = ssh_string(payload, 5)
                language, cursor = ssh_string(payload, cursor)
                if cursor != len(payload):
                    raise ValueError('invalid disconnect tail')
                packet['disconnect'] = {'reason': reason, 'description': description.decode(errors='replace'),
                                        'language_base64': b64(language)}
            pos = end
            if message == 21:
                if payload != b'\x15':
                    raise ValueError('invalid NEWKEYS payload')
                result['newkeys'] = True
                result['opaque_after_newkeys_offset'] = pos
                result['opaque_after_newkeys_bytes'] = len(raw) - pos
                break  # Never parse encrypted packets as plaintext.
        result['clear_parse_complete'] = True
    except (ValueError, UnicodeError, struct.error) as error:
        result['parse_error'] = str(error)
    return result


class Relay:
    """One owned, loopback-only connection; preserve TCP half-close semantics."""
    def __init__(self, backend):
        self.backend = backend
        self.stop = threading.Event()
        self.data = {'c2s': bytearray(), 's2c': bytearray()}
        self.errors, self.connections, self.threads = [], [], []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', PROXY_PORT))
        self.listener.listen(1)
        self.listener.settimeout(.2)
        self.worker = threading.Thread(target=self.accept, daemon=True)
        self.worker.start()

    def pump(self, src, dst, direction):
        try:
            while not self.stop.is_set():
                try:
                    data = src.recv(8192)
                except socket.timeout:
                    continue
                if not data:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    break
                if len(self.data[direction]) + len(data) > WIRE_LIMIT:
                    self.errors.append({'direction': direction, 'error': 'wire capture limit', 'terminal': False})
                    self.stop.set()
                    break
                self.data[direction].extend(data)
                dst.sendall(data)
        except OSError as error:
            if not self.stop.is_set():
                self.errors.append({'direction': direction, 'error': str(error), 'errno': error.errno,
                                    'terminal': error.errno in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN)})

    def accept(self):
        try:
            while not self.stop.is_set():
                try:
                    client, peer = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            assert peer[0] == '127.0.0.1'
            self.connections.append(client)
            server = socket.create_connection(('127.0.0.1', self.backend), timeout=3)
            self.connections.append(server)
            for s in self.connections:
                s.settimeout(.2)
            for src, dst, direction in [(client, server, 'c2s'), (server, client, 's2c')]:
                thread = threading.Thread(target=self.pump, args=(src, dst, direction), daemon=True)
                self.threads.append(thread)
                thread.start()
            for thread in self.threads:
                thread.join(8)
        except (OSError, AssertionError) as error:
            if not self.stop.is_set():
                self.errors.append({'direction': 'relay', 'error': str(error), 'terminal': False})

    def finish(self):
        self.worker.join(.3)
        self.stop.set()
        for s in self.connections + [self.listener]:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()
        self.worker.join(1)
        for thread in self.threads:
            thread.join(1)
        return {'c2s': decode_stream(bytes(self.data['c2s'])),
                's2c': decode_stream(bytes(self.data['s2c'])), 'relay_errors': self.errors,
                'threads_stopped': not self.worker.is_alive() and not any(x.is_alive() for x in self.threads)}


class Fixture:
    def __init__(self, shell, variant, reference=False, prefix='behavior'):
        self.shell, self.variant, self.reference, self.prefix = shell, variant, reference, prefix
        self.allowed, self.other = VARIANTS[variant]
        self.events, self.children, self.owned, self.logs, self.forced = [], [], [], [], []
        self.result = {}
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        self.env.pop('SSH_AUTH_SOCK', None)
        self.env.pop('BASHSSHD_AUTHORIZED_KEYS', None)

    def remember(self, p, role):
        record = identity(p.pid)
        assert record and record['uid'] == 2000 and record['ppid'] == os.getpid()
        self.owned.append({**record, 'role': role})
        self.children.append(p)
        return record

    def signal(self, record, sig):
        assert any(all(row[k] == record[k] for k in record) for row in self.owned)
        if live(record):
            os.kill(record['pid'], sig)
            self.events.append({'label': 'owned-signal', 'identity': record, 'signal': int(sig)})

    def run(self, argv, label, env=None, timeout=6):
        p = subprocess.Popen(argv, env=env or self.env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        record = self.remember(p, label)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.forced.append(p.pid)
            self.signal(record, signal.SIGKILL)
            out, err = p.communicate(timeout=2)
        self.events.append({'label': label, 'argv': argv, 'identity': record, 'status': p.returncode,
                            'stdout_base64': b64(out), 'stderr_base64': b64(err)})
        return subprocess.CompletedProcess(argv, p.returncode, out, err)

    def start(self, phase):
        port = PORTS[phase]
        run_dir = HOME / ('mac-' + self.prefix + '-' + phase + '-run')
        env = dict(self.env, BASHSSHD_RUN_DIR=str(run_dir))
        lines = ['ListenAddress 127.0.0.1', 'Port %d' % port,
                 'HostKey ' + str(HOME / 'mac-host'),
                 'AuthorizedKeysFile ' + str(HOME / 'mac-authorized'),
                 'PasswordAuthentication no', 'PubkeyAuthentication yes',
                 'Ciphers ' + CIPHER, 'KexAlgorithms ' + KEX]
        if phase != 'default':
            lines += ['MACs ' + (self.allowed + ',' + self.other if phase == 'baseline' else self.allowed)]
        if self.reference:
            lines += ['PidFile ' + str(HOME / ('mac-' + self.prefix + '-' + phase + '.pid')),
                      'StrictModes no', 'UsePAM no', 'KbdInteractiveAuthentication no',
                      'PerSourcePenalties no', 'PrintMotd no', 'PrintLastLog no', 'LogLevel VERBOSE']
        config = HOME / ('mac-' + self.prefix + '-' + phase + '.conf')
        text = '\n'.join(lines) + '\n'; config.write_text(text)
        log = (HOME / ('mac-' + self.prefix + '-' + phase + '-server.log')).open('wb')
        self.logs.append(log)
        argv = (['/usr/sbin/sshd', '-D', '-e', '-f', str(config)] if self.reference else
                [self.shell, '--noprofile', '--norc', '-c', 'sshd run -F "$1" --encrypted', 'server', str(config)])
        p = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True)
        record = self.remember(p, phase + '-server')
        rows = wait_for(lambda: p.poll() is None and ready_listener(record, port, Path(log.name), self.reference))
        self.events.append({'label': phase + '-server-start', 'argv': argv, 'identity': record,
                            'config_base64': b64(text.encode()), 'listener_evidence': rows})
        return {'process': p, 'identity': record, 'port': port, 'run_dir': run_dir,
                'env': env, 'ready': bool(rows), 'log': Path(log.name)}

    def stop_server(self, server):
        p, record = server['process'], server['identity']
        if self.reference:
            self.signal(record, signal.SIGTERM)
            status = 0
        else:
            assert live(record) and int((server['run_dir'] / 'pid').read_text()) == p.pid
            status = self.run([self.shell, '--noprofile', '--norc', '-c', 'sshd stop'],
                              'stop-' + str(server['port']), env=server['env']).returncode
        try:
            ended = p.wait(timeout=4)
        except subprocess.TimeoutExpired:
            ended = None
        self.events.append({'label': 'server-exit', 'port': server['port'], 'pid': p.pid,
                            'stop_status': status, 'server_status': ended,
                            'log_name': server['log'].name})
        return status == ended == 0

    def probe(self, server, label, mac):
        marker = HOME / ('ran-mac-' + self.prefix + '-' + label)
        marker.unlink(missing_ok=True)
        command = COMMAND.format(marker=shlex.quote(str(marker)))
        argv = ['/usr/bin/ssh', '-vv', '-F', '/dev/null', '-o', 'BatchMode=yes',
                '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
                '-o', 'ConnectTimeout=3', '-o', 'PreferredAuthentications=publickey',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile=' + str(HOME / 'mac-known-hosts'),
                '-i', str(HOME / 'mac-client'), '-p', str(PROXY_PORT),
                '-c', CIPHER, '-m', mac, '-o', 'KexAlgorithms=' + KEX,
                'parity@127.0.0.1', command]
        relay = Relay(server['port'])
        try:
            p = self.run(argv, label)
        finally:
            trace = relay.finish()
            trace.update(label=label, backend_port=server['port'], proxy_port=PROXY_PORT)
            save('mac-' + self.prefix + '-' + label + '-wire.json', trace)
        self.events.append({'label': label + '-observed', 'command_marker': marker.exists(),
                            'wire_file': 'mac-' + self.prefix + '-' + label + '-wire.json'})
        return p, marker.exists(), trace

    def close(self):
        for p in reversed(self.children):
            if p.poll() is None:
                record = next(x for x in self.owned if x['pid'] == p.pid)
                record = {k: v for k, v in record.items() if k != 'role'}
                self.forced.append(p.pid)
                self.signal(record, signal.SIGTERM)
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.signal(record, signal.SIGKILL); p.wait(timeout=2)
        server_logs = {Path(log.name).name: b64(Path(log.name).read_bytes()) for log in self.logs}
        for log in self.logs:
            log.close()
        save('mac-' + self.prefix + '-transcripts.json', {'events': self.events,
             'owned': self.owned, 'forced_cleanup_pids': self.forced,
             'server_logs_base64': server_logs})


def proposals(trace):
    if any(not e['terminal'] for e in trace['relay_errors']) or not trace['threads_stopped']:
        return None
    if not all(trace[d].get('clear_parse_complete') and trace[d]['kexinit'] is not None for d in ['c2s', 's2c']):
        return None
    return trace['c2s']['kexinit'], trace['s2c']['kexinit']


def first_common(client, server, name):
    return next((x for x in client[name] if x in server[name]), None)


def pre_encryption_kex(trace, mac):
    pair = proposals(trace)
    if not pair:
        return False
    client, server = pair
    return (first_common(client, server, 'kex') == KEX and
            first_common(client, server, 'hostkey') == 'ssh-ed25519' and
            all(first_common(client, server, n) == CIPHER for n in ['cipher_c2s', 'cipher_s2c']) and
            all(first_common(client, server, n) == mac for n in ['mac_c2s', 'mac_s2c']) and
            30 in [p['message'] for p in trace['c2s']['packets']] and
            31 in [p['message'] for p in trace['s2c']['packets']] and
            all(trace[d]['newkeys'] for d in ['c2s', 's2c']))


def command_succeeded(probe, mac):
    p, ran, trace = probe
    text = p.stderr.decode(errors='replace')
    return (p.returncode == 0 and ran and p.stdout == b'mac-packet-ok\n' and
            pre_encryption_kex(trace, mac) and 'Authenticated to ' in text and
            all(direction + ' cipher: ' + CIPHER + ' MAC: ' + mac in text
                for direction in ['server->client', 'client->server']))


def offered(trace, names, exact=False):
    pair = proposals(trace)
    if not pair:
        return False
    _, server = pair
    return all(set(server[n]) == set(names) if exact else set(names) <= set(server[n])
               for n in ['mac_c2s', 'mac_s2c'])


def denied_at_mac(probe, allowed):
    p, ran, trace = probe
    pair = proposals(trace)
    if not pair:
        return False
    client, server = pair
    return (p.returncode == 255 and not ran and not p.stdout and
            b'no matching MAC found' in p.stderr and offered(trace, [allowed], True) and
            all(first_common(client, server, n) is None for n in ['mac_c2s', 'mac_s2c']) and
            first_common(client, server, 'kex') == KEX and
            all(first_common(client, server, n) == CIPHER for n in ['cipher_c2s', 'cipher_s2c']) and
            not any(trace[d]['newkeys'] for d in ['c2s', 's2c']))


def evaluate(shell, variant, reference=False, prefix='behavior'):
    f = Fixture(shell, variant, reference, prefix)
    r = f.result
    try:
        server = f.start('default'); r['default-server-owned-ready'] = server['ready']
        if not server['ready']:
            return r
        default = f.probe(server, 'default-allowed', f.allowed)
        r['default-both-macs-advertised'] = offered(default[2], [f.allowed, f.other])
        r['default-allowed-encrypted-command'] = command_succeeded(default, f.allowed)
        r['default-server-stopped'] = f.stop_server(server)

        server = f.start('baseline'); r['baseline-server-owned-ready'] = server['ready']
        if not server['ready']:
            return r
        a = f.probe(server, 'baseline-allowed', f.allowed)
        other = f.probe(server, 'baseline-other', f.other)
        r['baseline-both-macs-advertised'] = offered(a[2], [f.allowed, f.other], True) and offered(other[2], [f.allowed, f.other], True)
        r['baseline-allowed-pre-encryption-kex'] = pre_encryption_kex(a[2], f.allowed)
        r['baseline-allowed-encrypted-command'] = command_succeeded(a, f.allowed)
        r['baseline-other-pre-encryption-kex'] = pre_encryption_kex(other[2], f.other)
        r['baseline-other-encrypted-command'] = command_succeeded(other, f.other)
        r['baseline-server-stopped'] = f.stop_server(server)

        server = f.start('restricted'); r['restricted-server-owned-ready'] = server['ready']
        if not server['ready']:
            return r
        a = f.probe(server, 'restricted-allowed', f.allowed)
        other = f.probe(server, 'restricted-other', f.other)
        r['restricted-only-allowed-mac-advertised'] = offered(a[2], [f.allowed], True) and offered(other[2], [f.allowed], True)
        r['restricted-allowed-pre-encryption-kex'] = pre_encryption_kex(a[2], f.allowed)
        r['restricted-allowed-encrypted-command'] = command_succeeded(a, f.allowed)
        r['restricted-other-wire-mac-mismatch-refusal'] = denied_at_mac(other, f.allowed)
        positive = (r['default-allowed-encrypted-command'] and r['baseline-allowed-encrypted-command'] and
                    r['baseline-other-encrypted-command'] and r['restricted-allowed-encrypted-command'])
        r['supported-disallowed-mac-policy-enforced'] = positive and r['restricted-other-wire-mac-mismatch-refusal']
        r['disallowed-command-not-run'] = not other[1]
        r['restricted-server-stopped'] = f.stop_server(server)
    finally:
        f.close()
        r['unforced-cleanup'] = not f.forced
        save('mac-' + prefix + '-results.json', r)
    return r


def prepare():
    for name in ['mac-host', 'mac-client']:
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                        '-C', 'fixture-' + name, '-f', str(HOME / name)],
                       check=True, capture_output=True, timeout=5)
    kind, key, *_ = (HOME / 'mac-host.pub').read_text().split()
    (HOME / 'mac-known-hosts').write_text('[127.0.0.1]:%d %s %s\n' % (PROXY_PORT, kind, key))
    (HOME / 'mac-authorized').write_bytes((HOME / 'mac-client.pub').read_bytes())
    listed = subprocess.run(['/usr/bin/ssh', '-Q', 'mac'], capture_output=True, check=True, timeout=3)
    save('mac-client-supported.json', {'argv': ['/usr/bin/ssh', '-Q', 'mac'], 'stdout_base64': b64(listed.stdout)})
    return listed.stdout.decode().splitlines()


if __name__ == '__main__':
    guard()
    verb, shell, variant = sys.argv[1:4]
    assert variant in VARIANTS
    if verb == 'setup':
        supported = prepare()
        assert set(VARIANTS[variant]) <= set(supported)
        result = evaluate('/bin/bash', variant, True, 'control')
        assert result and all(result.values()), result
        print('independent-packet-and-encrypted-command-controls=verified')
    elif verb == 'run':
        for name, value in evaluate(shell, variant).items():
            print(name + '=' + ('yes' if value else 'no'))
    else:
        raise ValueError(verb)
