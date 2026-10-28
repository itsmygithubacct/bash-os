#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only SSH policy and owned-session observations; no host execution.

OpenSSH controls establish usable algorithms, authentication, held commands and
reload behavior. Management actions use the fixture's own server PID or a
session whose handler is independently linked to that server and command PID.
All cleanup follows the observations and is retained in the transcript.
"""
import base64
import ctypes
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
import uuid


HOME = Path('/tmp/parity-home')
PORT = 20840
CIPHER = 'aes256-ctr'  # MAC case: a real, separately negotiated MAC is mandatory.
KEX_CIPHER = 'chacha20-poly1305@openssh.com'  # KEX only; never counts as MAC evidence.
MAC = 'hmac-sha2-256'
OTHER_MAC = 'hmac-sha2-512'
KEX = 'curve25519-sha256'
OTHER_KEX = 'diffie-hellman-group14-sha256'
# Declared source contract, never learned from a generated key:
# sshd.c:bsshd_write_placeholder_key, comment and format literals at1181-1205.
NATIVE_PRIVATE = b'BASHSSHD-HOSTKEY ed25519\n'
NATIVE_PUBLIC = b'sshd-ed25519 AAAABASHOSHOSTKEY\n'
PROBE_TEMPLATE = r'''printf 'policy-ok\n'; : > {marker}'''
HELD_TEMPLATE = (r'''printf '%s %s\n' "$BASHPID" "$PPID" > {ready}; '''
                 r'''if IFS= read -r -t 30 value; then printf '{tag}:%s\n' "$value"; fi; '''
                 r'''printf done > {done}''')


def require_guest():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU'
    assert Path.cwd() == Path('/tmp/parity-case') and os.geteuid() == 2000
    # Adopt only our own orphaned descendants, so known exited commands can be
    # reaped after a killed connection handler. This never terminates a child.
    lib = ctypes.CDLL(None, use_errno=True)
    assert lib.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER


def b64(data):
    return base64.b64encode(data).decode()


def save(name, data):
    (HOME / name).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def identity(pid):
    try:
        path = Path('/proc') / str(pid)
        text = (path / 'stat').read_text()
        fields = text[text.rindex(')') + 2:].split()
        return {'pid': pid, 'ppid': int(fields[1]), 'start': int(fields[19]),
                'uid': path.stat().st_uid, 'state': fields[0]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def live(record):
    now = identity(record['pid']) if record else None
    return bool(now and now['start'] == record['start'] and
                now['uid'] == record['uid'] == 2000 and now['state'] != 'Z')


def wait_for(predicate, seconds=3):
    deadline = time.monotonic() + seconds
    while True:
        value = predicate()
        if value or time.monotonic() >= deadline:
            return value
        time.sleep(.03)


def listening():
    wanted = '0100007F:%04X' % PORT
    return any(len(f := line.split()) > 3 and f[1] == wanted and f[3] == '0A'
               for line in Path('/proc/net/tcp').read_text().splitlines()[1:])


def encoded_result(proc):
    return {'status': proc.returncode, 'stdout_base64': b64(proc.stdout),
            'stderr_base64': b64(proc.stderr)}


def generate_keys():
    for name in ['host', 'client', 'client-next']:
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                        '-C', 'fixture-' + name, '-f', str(HOME / name)], check=True,
                       capture_output=True, timeout=5)
    kind, key, *_ = (HOME / 'host.pub').read_text().split()
    (HOME / 'known_hosts').write_text('[127.0.0.1]:%d %s %s\n' % (PORT, kind, key))
    (HOME / 'authorized_keys').write_bytes((HOME / 'client.pub').read_bytes())
    (HOME / 'authorized_keys-next').write_bytes((HOME / 'client-next.pub').read_bytes())


def algorithm_options(dimension, disallowed=False):
    kex = OTHER_KEX if dimension == 'kex' and disallowed else KEX
    if dimension == 'mac':
        return ['-c', CIPHER, '-m', OTHER_MAC if disallowed else MAC,
                '-o', 'KexAlgorithms=' + kex]
    return ['-c', KEX_CIPHER, '-o', 'KexAlgorithms=' + kex]


class Fixture:
    def __init__(self, shell, reference=False, prefix='behavior'):
        self.shell, self.reference, self.prefix = shell, reference, prefix
        self.events, self.owned, self.children, self.files = [], [], [], []
        self.server = None
        self.cleanup_forced = []
        self.env = dict(os.environ, BASHSSHD_RUN_DIR=str(HOME / 'run'),
                        PYTHONDONTWRITEBYTECODE='1')

    def run(self, argv, label, **kw):
        try:
            proc = subprocess.run(argv, capture_output=True, env=self.env,
                                  timeout=kw.pop('timeout', 5), **kw)
        except subprocess.TimeoutExpired as exc:
            self.events.append({'label': label, 'argv': argv, 'timeout': True,
                                'stdout_base64': b64(exc.stdout or b''),
                                'stderr_base64': b64(exc.stderr or b'')})
            raise
        self.events.append({'label': label, 'argv': argv, **encoded_result(proc)})
        return proc

    def remember(self, pid, role):
        record = identity(pid)
        assert record and record['uid'] == 2000
        self.owned.append({**record, 'role': role})
        return record

    def config(self, dimension=None, permissive=False, authorized='authorized_keys'):
        lines = ['ListenAddress 127.0.0.1', 'Port %d' % PORT,
                 'HostKey ' + str(HOME / 'host'),
                 'AuthorizedKeysFile ' + str(HOME / authorized),
                 'PasswordAuthentication no', 'PubkeyAuthentication yes']
        # Banner is deliberately absent: static95 exposed an out-of-order
        # pre-auth banner, which prevented the held-command readiness gate.
        if dimension:
            lines += ['Ciphers ' + (CIPHER if dimension == 'mac' else KEX_CIPHER),
                      'KexAlgorithms ' + (KEX + ',' + OTHER_KEX if permissive and dimension == 'kex' else KEX)]
            if dimension == 'mac':
                lines += ['MACs ' + (MAC + ',' + OTHER_MAC if permissive else MAC)]
        if self.reference:
            lines += ['PidFile ' + str(HOME / 'reference.pid'), 'StrictModes no',
                      'UsePAM no', 'KbdInteractiveAuthentication no',
                      'PerSourcePenalties no', 'PrintMotd no', 'PrintLastLog no', 'LogLevel ERROR']
        content = '\n'.join(lines) + '\n'
        (HOME / 'server.conf').write_text(content)
        self.events.append({'label': 'config-write', 'authorized_keys_file': authorized,
                            'bytes_base64': b64(content.encode())})

    def start(self):
        path = HOME / (self.prefix + '-server.log')
        log = path.open('wb'); self.files.append(log)
        argv = (['/usr/sbin/sshd', '-D', '-e', '-f', str(HOME / 'server.conf')]
                if self.reference else
                [self.shell, '--noprofile', '--norc', '-c',
                 'sshd run -F "$1" --encrypted', 'server', str(HOME / 'server.conf')])
        self.server = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                       stderr=log, env=self.env, close_fds=True)
        self.children.append(self.server)
        self.server_id = self.remember(self.server.pid, 'server')
        ready = wait_for(lambda: self.server.poll() is None and listening())
        self.events.append({'label': 'server-start', 'argv': argv, 'ready': bool(ready),
                            'identity': self.server_id})
        return bool(ready)

    def client_argv(self, command, options=(), key='client'):
        return ['/usr/bin/ssh', '-vv', '-F', '/dev/null', '-o', 'BatchMode=yes',
                '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=3',
                '-o', 'IdentityAgent=none', '-o', 'PreferredAuthentications=publickey',
                '-o', 'GlobalKnownHostsFile=/dev/null', '-o',
                'UserKnownHostsFile=' + str(HOME / 'known_hosts'), '-o', 'StrictHostKeyChecking=yes',
                '-i', str(HOME / key), '-p', str(PORT), *options,
                'parity@127.0.0.1', command]

    def probe(self, label, options=(), key='client'):
        marker = HOME / ('ran-' + label)
        marker.unlink(missing_ok=True)
        command = PROBE_TEMPLATE.format(marker=shlex.quote(str(marker)))
        proc = self.run(self.client_argv(command, options, key), label)
        return proc, marker.exists()

    def manage(self, *args):
        # Never pass an unvalidated pidfile to a signaling candidate command.
        if args[0] in ('stop', 'reload', 'kick'):
            assert self.pidfile_is_own_server()
        return self.run([self.shell, '--noprofile', '--norc', '-c', 'sshd "$@"',
                         'manage', *args], 'manage-' + args[0])

    def pidfile_is_own_server(self):
        try:
            return live(self.server_id) and int((HOME / 'run/pid').read_text()) == self.server.pid
        except (FileNotFoundError, ValueError):
            return False

    def sessions(self):
        proc = self.manage('sessions')
        rows = []
        for line in proc.stdout.decode().splitlines():
            fields = line.split()
            if fields:
                rows.append({'id': fields[0], **dict(x.split('=', 1) for x in fields[1:] if '=' in x)})
        return rows

    def held(self, tag):
        ready = HOME / ('ready-' + self.prefix + '-' + tag)
        done = HOME / ('done-' + self.prefix + '-' + tag)
        ready.unlink(missing_ok=True)
        done.unlink(missing_ok=True)
        command = HELD_TEMPLATE.format(tag=tag, ready=shlex.quote(str(ready)), done=shlex.quote(str(done)))
        argv = self.client_argv(command)
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=self.env, close_fds=True)
        self.children.append(proc)
        client_id = self.remember(proc.pid, 'client-' + tag)
        self.events.append({'label': 'held-start-' + tag, 'argv': argv, 'command': command,
                            'client_identity': client_id, 'ready_path': str(ready),
                            'done_path': str(done)})
        wait_for(lambda: (ready.exists() and ready.stat().st_size > 0) or proc.poll() is not None)
        if not ready.exists() or not ready.stat().st_size:
            self.events.append({'label': 'held-readiness-failed-' + tag, 'client_status': proc.poll()})
            return None
        command_pid, parent_pid = map(int, ready.read_text().split())
        cmd = self.remember(command_pid, 'command-' + tag)
        # The command must be descended from this fixture's actual server.
        chain, current = [], cmd
        while current and len(chain) < 16 and current['pid'] != self.server.pid:
            chain.append(current['pid'])
            current = identity(current['ppid'])
        assert current and current['pid'] == self.server.pid and cmd['ppid'] == parent_pid
        handler = self.remember(parent_pid, 'handler-' + tag)
        if not self.reference:
            assert handler['ppid'] == self.server.pid
        sid = None
        if not self.reference:
            rows = wait_for(lambda: [r for r in self.sessions() if r.get('pid') == str(parent_pid)])
            assert len(rows) == 1
            sid = rows[0]['id']
            assert re.fullmatch(r'[0-9]+-[0-9]+', sid)
        session = {'tag': tag, 'client': proc, 'command': cmd, 'handler': handler, 'sid': sid}
        self.events.append({'label': 'held-' + tag, 'command': command, 'command_identity': cmd,
                            'handler_identity': handler, 'server_pid': self.server.pid, 'sid': sid})
        return session

    def collect(self, held, value=None):
        proc = held['client']
        try:
            out, err = proc.communicate(None if value is None else value, timeout=5)
        except subprocess.TimeoutExpired as exc:
            self.events.append({'label': 'client-' + held['tag'], 'timeout': True,
                                'stdout_base64': b64(exc.stdout or b''),
                                'stderr_base64': b64(exc.stderr or b'')})
            raise
        self.events.append({'label': 'client-' + held['tag'], 'status': proc.returncode,
                            'stdout_base64': b64(out), 'stderr_base64': b64(err)})
        return proc.returncode, out, err

    def signal_record(self, record, sig):
        assert record in [dict((k, v) for k, v in row.items() if k != 'role') for row in self.owned]
        if live(record):
            os.kill(record['pid'], sig)
            self.events.append({'label': 'owned-signal', 'pid': record['pid'],
                                'start': record['start'], 'signal': int(sig)})

    def exited(self, record):
        now = identity(record['pid'])
        if now and now['state'] == 'Z' and now['ppid'] == os.getpid():
            # Reap an adopted, already-exited known command/handler, not a
            # Popen server/client whose wait status belongs to Popen.
            try:
                os.waitpid(record['pid'], os.WNOHANG)
            except ChildProcessError:
                pass
        return not live(record)

    def stop(self):
        if self.reference:
            self.signal_record(self.server_id, signal.SIGTERM)
            status = 0
        else:
            status = self.manage('stop').returncode
        try:
            server_status = self.server.wait(timeout=4)
        except subprocess.TimeoutExpired:
            server_status = None
        return status, server_status

    def close(self):
        for proc in reversed(self.children):
            if proc.poll() is None:
                self.cleanup_forced.append(proc.pid)
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=2)
            if proc.stdout is not None and not proc.stdout.closed:
                try:
                    out, err = proc.communicate(timeout=2)
                    self.events.append({'label': 'cleanup-client-transcript', 'pid': proc.pid,
                                        'status': proc.returncode, 'stdout_base64': b64(out),
                                        'stderr_base64': b64(err)})
                except subprocess.TimeoutExpired as exc:
                    self.events.append({'label': 'incomplete-client-transcript', 'pid': proc.pid,
                                        'stdout_base64': b64(exc.stdout or b''),
                                        'stderr_base64': b64(exc.stderr or b'')})
        for row in reversed(self.owned):
            if row['role'].startswith(('command-', 'handler-')) and live(row):
                self.cleanup_forced.append(row['pid'])
                self.signal_record({k: v for k, v in row.items() if k != 'role'}, signal.SIGTERM)
                wait_for(lambda: self.exited(row), 2)
            elif row['role'].startswith(('command-', 'handler-')):
                self.exited(row)
        for handle in self.files:
            handle.close()
        save(self.prefix + '-transcripts.json', {'events': self.events, 'owned': self.owned,
                                                'forced_cleanup_pids': self.cleanup_forced})


def negotiated(proc, dimension, disallowed=False):
    text = proc.stderr.decode('utf-8', 'replace')
    mac = (OTHER_MAC if disallowed else MAC) if dimension == 'mac' else '<implicit>'
    cipher = CIPHER if dimension == 'mac' else KEX_CIPHER
    kex = OTHER_KEX if dimension == 'kex' and disallowed else KEX
    return (proc.returncode == 0 and proc.stdout == b'policy-ok\n' and
            'kex: algorithm: ' + kex in text and
            'server->client cipher: ' + cipher + ' MAC: ' + mac in text and
            'client->server cipher: ' + cipher + ' MAC: ' + mac in text)


def command_succeeded(proc, ran):
    return ran and proc.returncode == 0 and proc.stdout == b'policy-ok\n'


def authentication_refused(proc, ran):
    return (not ran and proc.returncode == 255 and not proc.stdout and
            b'Permission denied (publickey).' in proc.stderr and
            b'Authentications that can continue: publickey' in proc.stderr and
            b'Authenticated to ' not in proc.stderr)


def crypto(shell, dimension, reference=False, permissive=False, prefix='behavior'):
    f = Fixture(shell, reference, prefix)
    result = {}
    try:
        f.config(dimension, permissive)
        result['server-ready'] = f.start()
        if not result['server-ready']:
            return result
        allowed, ran = f.probe(prefix + '-allowed', algorithm_options(dimension))
        result['allowed-negotiation-and-command'] = ran and negotiated(allowed, dimension)
        denied, ran = f.probe(prefix + '-disallowed', algorithm_options(dimension, True))
        if permissive:
            result['disallowed-algorithm-works-when-allowed'] = ran and negotiated(denied, dimension, True)
        else:
            phrase = b'no matching MAC found' if dimension == 'mac' else b'no matching key exchange method found'
            result['disallowed-refused-at-negotiation'] = (
                result['allowed-negotiation-and-command'] and denied.returncode == 255 and phrase in denied.stderr)
            result['disallowed-command-not-run'] = not ran
        status, ended = f.stop()
        result['server-stopped'] = status == ended == 0
    finally:
        f.close()
        result['unforced-cleanup'] = not f.cleanup_forced
        save(prefix + '-results.json', result)
    return result


def session_test(shell, scenario, reference=False, prefix='behavior'):
    f = Fixture(shell, reference, prefix)
    result = {}
    bystander = None
    try:
        keyfiles = {name: (HOME / name).read_bytes()
                    for name in ('authorized_keys', 'authorized_keys-next')}
        f.events.append({'label': 'immutable-key-files',
                         'files_base64': {name: b64(data) for name, data in keyfiles.items()}})
        f.config()
        result['server-ready'] = f.start()
        if not result['server-ready']:
            return result
        if not reference:
            result['pidfile-is-owned-server'] = f.pidfile_is_own_server()
            status = f.manage('status')
            reported = re.search(rb'(?:^|\s)pid=([0-9]+)(?:\s|$)', status.stdout)
            result['status-reports-owned-server'] = (status.returncode == 0 and
                                                     status.stdout.startswith(b'running ') and
                                                     reported is not None and
                                                     int(reported[1]) == f.server.pid)
        first = f.held('a')
        result['initial-held-session-ready'] = first is not None
        if first is None:
            return result  # No subsequent lifecycle assertion was reached.
        if scenario == 'kick':
            second = f.held('b')
            result['second-held-session-ready'] = second is not None
            if second is None:
                return result
            bystander = subprocess.Popen(['/usr/bin/python3', '-c', 'import time;time.sleep(40)'], env=f.env)
            f.children.append(bystander)
            unrelated = f.remember(bystander.pid, 'bystander')
            result['two-independent-live-sessions'] = live(first['command']) and live(second['command'])
            if reference:
                f.signal_record(first['handler'], signal.SIGTERM)
                rc = 0
            else:
                assert live(first['handler']) and live(second['handler']) and first['sid'] != second['sid']
                rc = f.manage('kick', first['sid']).returncode
            closed = wait_for(lambda: first['client'].poll() is not None)
            a_status, _, _ = f.collect(first)
            result['target-kick-closes-only-target'] = rc == 0 and bool(closed) and a_status != 0
            result['target-command-terminated'] = bool(wait_for(lambda: f.exited(first['command'])))
            result['other-session-and-bystander-survive'] = (second['client'].poll() is None and
                                                           live(second['command']) and live(unrelated))
            if not reference:
                f.probe('reap-after-kick')
                def only_survivor():
                    rows = f.sessions()
                    return rows if {x['id'] for x in rows} == {second['sid']} else None
                rows = wait_for(only_survivor)
                result['only-surviving-session-listed'] = bool(rows)
            b_status, out, _ = f.collect(second, b'continue\n')
            result['surviving-session-still-transfers'] = b_status == 0 and out == b'b:continue\n'
            result['surviving-command-terminated'] = bool(wait_for(lambda: f.exited(second['command'])))
            f.signal_record(unrelated, signal.SIGTERM)
            bystander.wait(timeout=3)
        elif scenario == 'disconnect':
            first['client'].terminate()  # This exact owned client's connection is the test stimulus.
            f.collect(first)
            result['disconnect-command-terminated'] = bool(wait_for(lambda: f.exited(first['command'])))
            result['disconnect-handler-terminated'] = bool(wait_for(lambda: f.exited(first['handler'])))
        elif scenario == 'reload':
            before, ran = f.probe('before-reload')
            result['before-authorized-key-and-command'] = command_succeeded(before, ran)
            before_other, ran = f.probe('before-reload-next-key', key='client-next')
            result['before-alternate-key-auth-refused'] = authentication_refused(before_other, ran)
            # Both files already existed. Only the config path changes; the old
            # held session authenticated with the original, now-revoked key.
            f.config(authorized='authorized_keys-next')
            pending_old, ran = f.probe('pending-config-old-key')
            result['pending-config-original-key-still-allowed'] = command_succeeded(pending_old, ran)
            pending_next, ran = f.probe('pending-config-next-key', key='client-next')
            result['pending-config-alternate-key-still-refused'] = authentication_refused(pending_next, ran)
            if reference:
                f.signal_record(f.server_id, signal.SIGHUP)
                rc = 0
            else:
                rc = f.manage('reload').returncode
            changed = False
            for attempt in range(3):
                after, ran = f.probe('after-reload-next-key-' + str(attempt), key='client-next')
                changed = command_succeeded(after, ran)
                if changed:
                    break
                time.sleep(.1)
            result['reload-command-and-new-config-effect'] = (rc == 0 and changed and
                result['before-authorized-key-and-command'] and result['before-alternate-key-auth-refused'] and
                result['pending-config-original-key-still-allowed'] and
                result['pending-config-alternate-key-still-refused'])
            after_old, ran = f.probe('after-reload-old-key')
            result['after-original-key-auth-refused'] = authentication_refused(after_old, ran)
            result['authorized-key-files-unchanged'] = all((HOME / name).read_bytes() == data
                                                         for name, data in keyfiles.items())
            result['reload-server-same-process'] = live(f.server_id)
            result['existing-session-survives-reload'] = (first['client'].poll() is None and live(first['command']))
            status, out, _ = f.collect(first, b'continue\n')
            result['existing-session-still-transfers'] = status == 0 and out == b'a:continue\n'
            result['existing-command-terminated'] = bool(wait_for(lambda: f.exited(first['command'])))
        else:
            raise ValueError(scenario)
        if not reference:
            f.probe('reap-final')
            empty = wait_for(lambda: not f.sessions())
            result['sessions-and-disconnect-cleanup-empty'] = bool(empty)
        status, ended = f.stop()
        result['stop-terminates-owned-server'] = status == ended == 0
        if not reference:
            result['pidfile-removed-and-status-stopped'] = (not (HOME / 'run/pid').exists() and
                                                          f.manage('status').returncode == 1)
    finally:
        f.close()
        result['unforced-cleanup'] = not f.cleanup_forced
        save(prefix + '-results.json', result)
    return result


def setup(scenario):
    generate_keys()
    if scenario in ('mac', 'kex'):
        query = 'mac' if scenario == 'mac' else 'kex'
        supported = subprocess.run(['/usr/bin/ssh', '-Q', query], check=True,
                                   capture_output=True, timeout=3).stdout.decode().splitlines()
        assert {MAC, OTHER_MAC} <= set(supported) if scenario == 'mac' else {KEX, OTHER_KEX} <= set(supported)
        broad = crypto('/bin/bash', scenario, True, True, 'control-permissive')
        restricted = crypto('/bin/bash', scenario, True, False, 'control-restricted')
        controls = {'permissive': broad, 'restricted': restricted}
        assert all(broad.values()) and all(restricted.values()), controls
    elif scenario in ('kick', 'disconnect', 'reload'):
        controls = session_test('/bin/bash', scenario, True, 'control')
        assert controls and all(controls.values()), controls
    else:
        raise ValueError(scenario)
    save('control-results.json', controls)
    print('independent-openssh-controls=verified')


def native_key(shell):
    def mask():
        os.umask(0o022)
    result = subprocess.run([shell, '--noprofile', '--norc', '-c',
                             'sshd keygen -f review-native-key'], capture_output=True,
                            timeout=5, preexec_fn=mask)
    observed = encoded_result(result)
    observed['contract_private_base64'] = b64(NATIVE_PRIVATE)
    observed['contract_public_base64'] = b64(NATIVE_PUBLIC)
    for name, expected in [('review-native-key', NATIVE_PRIVATE), ('review-native-key.pub', NATIVE_PUBLIC)]:
        path = Path(name)
        observed[name] = {'exists': path.exists()}
        if path.exists():
            observed[name].update(mode=stat.S_IMODE(path.stat().st_mode), bytes_base64=b64(path.read_bytes()))
    save('behavior-transcripts.json', observed)
    print('keygen-status=%d stderr-empty=%s' % (result.returncode, 'yes' if not result.stderr else 'no'))
    for label, name, expected in [('private', 'review-native-key', NATIVE_PRIVATE),
                                  ('public', 'review-native-key.pub', NATIVE_PUBLIC)]:
        path = Path(name)
        print('%s bytes=%s mode=%s' % (label, 'exact' if path.exists() and path.read_bytes() == expected else 'different',
                                       '%04o' % stat.S_IMODE(path.stat().st_mode) if path.exists() else 'missing'))


if __name__ == '__main__':
    require_guest()
    verb, args = sys.argv[1], sys.argv[2:]
    if verb == 'setup':
        setup(args[0])
    elif verb == 'native':
        native_key(args[0])
    elif verb == 'run':
        shell, scenario, side = args
        result = (crypto(shell, scenario, side == 'reference') if scenario in ('mac', 'kex') else
                  session_test(shell, scenario))
        save('behavior-results.json', result)
        for label, ok in result.items():
            print(label + '=' + ('yes' if ok else 'no'))
    else:
        raise ValueError(verb)
