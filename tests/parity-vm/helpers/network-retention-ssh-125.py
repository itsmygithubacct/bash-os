#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only SSH policy, agent protocol, SFTP and client PTY/mux observations.

Never import or execute on a host. All signals address remembered owned PIDs;
detached client masters must be adopted by this helper before cleanup signals.
Reference controls use fresh fixture keys and the same OpenSSH protocol clients.
"""
import base64
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import termios
import time
import uuid


HOME = Path('/tmp/parity-home')
PORT = 20980
DATA = b'fixture-sftp\x00bytes\nsecond-line\n'
PROBE = r"printf 'followup-ok\n'; : > {marker}"
PTY_QUERY = "[ -t 0 ] && [ -t 1 ] && printf 'PTY_%s:' OK; /usr/bin/stty size\n"
EXEC_MARKER = "printf 'mux-exec-ok\\n'"
CONNECT_SHELL = ('ssh connect 127.0.0.1 -p "$1" -l parity -i "$2" --encrypted -h handle || exit; '
                 'ssh shell "$handle"; rc=$?; ssh close "$handle"; exit "$rc"')
AGENT_QUERY = r'''#!/usr/bin/python3
import base64,json,os,socket,stat,struct,sys,uuid
from pathlib import Path

def check(condition,message):
 if not condition: raise SystemExit('agent query guest guard: '+message)

def require_guest():
 scenarios={'agent-identities','key-no-agent','match-user-agent','match-address-agent','match-all-agent'}
 check(len(sys.argv)==2 and sys.argv[1] in scenarios,'unknown nonroot scenario')
 uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
 check(Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU','QEMU vendor required')
 check(os.geteuid()==2000,'scenario requires effective uid2000')
 scratch=Path('/tmp/parity-home')
 info=scratch.lstat()
 check(scratch.resolve()==scratch and stat.S_ISDIR(info.st_mode) and
       info.st_uid==2000 and not (info.st_mode & 0o022),'private fixture home required')
 script=Path(__file__)
 check(script.is_absolute() and script==scratch/'agent-query.py' and
       script.resolve()==script,'fixture script path required')
 info=script.lstat()
 check(stat.S_ISREG(info.st_mode) and info.st_uid==2000 and
       not (info.st_mode & 0o022),'owned fixture script required')
 # Remote SSH may legitimately chdir to the account home. Do not require cwd
 # or the login HOME environment variable to equal the fixture scratch path.

def forwarded_socket(path):
 p=Path(path)
 check(p.is_absolute() and '..' not in p.parts and p.parent.parent==Path('/tmp') and
       p.parent.name.startswith(('ssh-','sshd-agent-')),'private forwarded socket path required')
 parent=p.parent.lstat()
 check(p.parent.resolve()==p.parent and stat.S_ISDIR(parent.st_mode) and
       parent.st_uid==2000 and not (parent.st_mode & 0o077),'owned private agent directory required')
 try: info=p.lstat()
 except FileNotFoundError: return False
 check(stat.S_ISSOCK(info.st_mode) and info.st_uid==2000,'owned forwarded agent socket required')
 return True

def take(s,n):
 data=b''
 while len(data)<n:
  part=s.recv(n-len(data))
  if not part: raise RuntimeError('short agent response')
  data+=part
 return data

def main():
 require_guest()
 path=os.environ.get('SSH_AUTH_SOCK','')
 result={'socket_present':bool(path and forwarded_socket(path)), 'request_sent':False}
 if result['socket_present']:
  try:
   with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(3); s.connect(path)
    request=struct.pack('!I',1)+bytes([11])
    s.sendall(request); result['request_sent']=True
    size=struct.unpack('!I',take(s,4))[0]
    if not 1<=size<=65536: raise RuntimeError('agent frame length')
    reply=take(s,size)
    result.update(request_base64=base64.b64encode(request).decode(),reply_base64=base64.b64encode(reply).decode())
  except Exception as e: result['error']=type(e).__name__+': '+str(e)
 print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
 main()
'''


def b64(data):
    return base64.b64encode(data).decode()


def save(name, value):
    (HOME / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def guard(scenario):
    if not __debug__ or scenario not in ('master-persist', 'master-routing'):
        raise RuntimeError('only unoptimized nonroot multiplex scenarios are permitted')
    # The root guest evaluator verifies this marker against product_uuid;
    # product_uuid itself is not necessarily readable by uid 2000.
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
            or Path.cwd() != Path('/tmp/parity-case') or os.geteuid() != 2000):
        raise RuntimeError('disposable parity VM, marker, cwd and uid guard failed')
    if (not hasattr(os, 'pidfd_open') or not hasattr(os, 'P_PIDFD')
            or not hasattr(os, 'waitid') or not hasattr(os, 'WNOWAIT')
            or not hasattr(signal, 'pidfd_send_signal') or not hasattr(time, 'CLOCK_BOOTTIME')):
        raise RuntimeError('pidfd, nonreaping waitid and CLOCK_BOOTTIME are required')
    lib = ctypes.CDLL(None, use_errno=True)
    if lib.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'cannot enable child subreaper')


def clocks():
    # Individual reads are ordered, not simultaneous; all are integer ns.
    return {'monotonic_ns': time.monotonic_ns(),
            'realtime_ns': time.clock_gettime_ns(time.CLOCK_REALTIME),
            'boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME)}


def stat_fields(info):
    return {name: getattr(info, 'st_' + name) for name in
            ('mode', 'uid', 'gid', 'dev', 'ino', 'nlink', 'size', 'mtime_ns')}


def snapshot_path(path):
    result = {'path': str(path), 'before': clocks()}
    try:
        result['lstat'] = stat_fields(path.lstat())
        result['errno'] = 0
    except OSError as exc:
        result['errno'] = exc.errno
        result['error'] = type(exc).__name__
    result['after'] = clocks()
    return result


def wait_observation(fd):
    result = {'before': clocks()}
    try:
        event = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        result['event'] = None if event is None else {
            key: getattr(event, key) for key in ('si_pid', 'si_uid', 'si_signo', 'si_status', 'si_code')}
        result['errno'] = 0
    except OSError as exc:
        result['errno'] = exc.errno
        result['error'] = type(exc).__name__
    result['after'] = clocks()
    return result


def same_birth(now, record):
    return bool(now and all(now[k] == record[k] for k in ('pid', 'uid', 'start')))


def identity(pid):
    try:
        path = Path('/proc') / str(pid)
        value = (path / 'stat').read_text()
        fields = value[value.rindex(')') + 2:].split()
        return {'pid': pid, 'ppid': int(fields[1]), 'start': int(fields[19]),
                'uid': path.stat().st_uid, 'state': fields[0]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def live(record):
    now = identity(record['pid']) if record else None
    return bool(now and now['uid'] == record['uid'] == os.geteuid() and
                now['start'] == record['start'] and now['state'] != 'Z')


def wait_for(predicate, seconds=3):
    deadline = time.monotonic() + seconds
    while True:
        value = predicate()
        if value or time.monotonic() >= deadline:
            return value
        time.sleep(.03)


def tcp_rows(port=PORT, state='0A'):
    address = '0100007F:%04X' % port
    return [line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]
            if len(line.split()) > 3 and line.split()[1] == address and line.split()[3] == state]


def prepare():
    for name in ['host', 'client', 'other']:
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                        '-C', 'fixture-' + name, '-f', str(HOME / name)],
                       check=True, capture_output=True, timeout=5)
    kind, key, *_ = (HOME / 'host.pub').read_text().split()
    (HOME / 'known_hosts').write_text('[127.0.0.1]:%d %s %s\n' % (PORT, kind, key))
    (HOME / 'authorized_keys').write_bytes((HOME / 'client.pub').read_bytes())
    (HOME / 'agent-query.py').write_text(AGENT_QUERY)


class Fixture:
    def __init__(self, shell, reference, prefix):
        self.shell, self.reference, self.prefix = shell, reference, prefix
        self.events, self.children, self.owned, self.handles = [], [], [], []
        self.forced = []
        self.master_fd = None
        self.master_record = None
        self.server = None
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', TERM='xterm',
                        BASHSSHD_RUN_DIR=str(HOME / (prefix + '-run')),
                        BASHSSH_KNOWN_HOSTS=str(HOME / 'known_hosts'),
                        BASHSSH_STRICT_HOST_KEY_CHECKING='yes',
                        BASHSSH_MASTER_LOG=str(HOME / (prefix + '-master.log')))
        # Only explicitly forwarded clients receive the local agent address.
        self.env.pop('SSH_AUTH_SOCK', None)
        self.env.pop('BASHSSHD_AUTHORIZED_KEYS', None)
        self.observations = {}

    def remember(self, pid, role, adopted=False):
        record = identity(pid)
        assert record and record['uid'] == os.geteuid()
        if adopted:
            assert record['ppid'] == os.getpid()
        self.owned.append({**record, 'role': role})
        return record

    def signal(self, record, sig):
        if not any(all(row.get(k) == record[k] for k in record) for row in self.owned):
            raise RuntimeError('refusing signal for an unowned process')
        now = identity(record['pid'])
        if not same_birth(now, record) or now['state'] == 'Z':
            self.events.append({'label': 'cleanup-refused-stale-or-dead', 'identity': record,
                                'observed': now, 'signal': int(sig), 'clock': clocks()})
            return
        try:
            # The master's persistent pidfd was pinned at adoption. Reuse it
            # so a numeric PID cannot redirect even a racing cleanup signal.
            if self.master_fd is not None and same_birth(record, self.master_record):
                fd = os.dup(self.master_fd)
            else:
                fd = os.pidfd_open(record['pid'], 0)
        except ProcessLookupError as exc:
            self.events.append({'label': 'cleanup-refused-disappeared', 'identity': record,
                                'errno': exc.errno, 'signal': int(sig), 'clock': clocks()})
            return
        try:
            now = identity(record['pid'])
            if not same_birth(now, record) or now['state'] == 'Z':
                self.events.append({'label': 'cleanup-refused-stale-or-dead', 'identity': record,
                                    'observed': now, 'signal': int(sig), 'clock': clocks()})
                return
            try:
                signal.pidfd_send_signal(fd, sig)
                self.events.append({'label': 'owned-pidfd-signal', 'identity': record,
                                    'signal': int(sig), 'clock': clocks()})
            except ProcessLookupError as exc:
                self.events.append({'label': 'cleanup-refused-disappeared', 'identity': record,
                                    'errno': exc.errno, 'signal': int(sig), 'clock': clocks()})
        finally:
            os.close(fd)

    def pin_master(self, record):
        before = identity(record['pid'])
        if not same_birth(before, record) or before['ppid'] != os.getpid() or before['state'] == 'Z':
            raise RuntimeError('master identity or adoption changed before pin')
        fd = os.pidfd_open(record['pid'], 0)
        try:
            after = identity(record['pid'])
            if not same_birth(after, record) or after['ppid'] != os.getpid() or after['state'] == 'Z':
                raise RuntimeError('master identity or adoption changed during pin')
            self.master_record = dict(record)
            self.master_fd = fd
        except Exception:
            os.close(fd)
            raise
        self.events.append({'label': 'master-pidfd-pinned', 'before': before, 'after': after,
                            'clock': clocks()})

    def master_snapshot(self, label, record, path):
        if self.master_fd is None:
            raise RuntimeError('master pidfd was not pinned')
        proc = Path('/proc') / str(record['pid'])
        observed = {'before': clocks(), 'directory': snapshot_path(proc)}
        try:
            raw = (proc / 'stat').read_bytes()
            observed.update(stat_base64=b64(raw), stat_errno=0)
        except OSError as exc:
            observed.update(stat_errno=exc.errno, stat_error=type(exc).__name__)
        observed['after'] = clocks()
        wait = wait_observation(self.master_fd)
        self.events.append({'label': 'master-snapshot', 'stage': label, 'identity': record,
                            'proc': observed, 'socket': snapshot_path(path),
                            'pidfd_waitid_wnowait': wait})
        if wait['errno'] != 0:
            raise RuntimeError('master pidfd nonreaping wait unavailable; retained errno %s' % wait['errno'])

    def run(self, argv, label, **kwargs):
        env = kwargs.pop('env', self.env)
        timeout = kwargs.pop('timeout', 6)
        data = kwargs.pop('input', None)
        p = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, **kwargs)
        self.children.append(p)
        record = self.remember(p.pid, 'invocation-' + label)
        try:
            out, err = p.communicate(data, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.forced.append(p.pid)
            self.signal(record, signal.SIGKILL)
            out, err = p.communicate(timeout=2)
            self.events.append({'label': label, 'argv': argv, 'identity': record,
                                'timeout': True, 'status': p.returncode,
                                'stdout_base64': b64(out), 'stderr_base64': b64(err)})
            return subprocess.CompletedProcess(argv, 124, out, err)
        self.events.append({'label': label, 'argv': argv, 'identity': record, 'status': p.returncode,
                            'stdout_base64': b64(out), 'stderr_base64': b64(err)})
        return subprocess.CompletedProcess(argv, p.returncode, out, err)

    def config(self, extra=(), auth='authorized_keys', relative=False):
        parent = HOME / ('config-' + self.prefix)
        parent.mkdir(exist_ok=True)
        lines = ['ListenAddress 127.0.0.1', 'Port %d' % PORT,
                 'HostKey ' + str(HOME / 'host'),
                 'PasswordAuthentication no', 'PubkeyAuthentication yes']
        if not relative:
            lines += ['AuthorizedKeysFile ' + str(HOME / auth)]
        if self.reference:
            lines += ['PidFile ' + str(HOME / (self.prefix + '.pid')), 'StrictModes no',
                      'UsePAM no', 'KbdInteractiveAuthentication no', 'PerSourcePenalties no',
                      'PrintMotd no', 'PrintLastLog no', 'LogLevel VERBOSE',
                      'Subsystem sftp internal-sftp']
        if relative:
            fragments = parent / 'policy.d'
            fragments.mkdir(exist_ok=True)
            (fragments / '10-keys.conf').write_text('AuthorizedKeysFile ' + str(HOME / auth) + '\n')
            (fragments / '90-ignored.txt').write_text('UnsupportedIgnoredDirective value\n')
            self.events.append({'label': 'include-fragments', 'files_base64': {
                str(p): b64(p.read_bytes()) for p in sorted(fragments.iterdir())}})
            # Declared BashOS contract resolves relative Include against parent.
            # OpenSSH uses a different base: its independent positive control
            # receives the same glob as an absolute pathname.
            include = str(fragments / '*.conf') if self.reference else 'policy.d/*.conf'
            lines += ['Include ' + include]
        lines += list(extra)
        self.config_path = parent / 'server.conf'
        text = '\n'.join(lines) + '\n'
        self.config_path.write_text(text)
        self.events.append({'label': 'config', 'path': str(self.config_path), 'bytes_base64': b64(text.encode())})

    def start(self, force_reference=False):
        self.server_reference = self.reference or force_reference
        self.log_path = HOME / (self.prefix + '-server.log')
        log = self.log_path.open('wb'); self.handles.append(log)
        argv = (['/usr/sbin/sshd', '-D', '-e', '-f', str(self.config_path)] if self.server_reference else
                [self.shell, '--noprofile', '--norc', '-c', 'sshd run -F "$1" --encrypted',
                 'server', str(self.config_path)])
        self.server = subprocess.Popen(argv, env=self.env, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=log, close_fds=True)
        self.children.append(self.server)
        self.server_id = self.remember(self.server.pid, 'server')
        ready = wait_for(lambda: self.server.poll() is None and bool(tcp_rows()))
        self.events.append({'label': 'server-start', 'argv': argv, 'identity': self.server_id,
                            'ready': bool(ready)})
        return bool(ready)

    def stop(self):
        if self.server_reference:
            self.signal(self.server_id, signal.SIGTERM)
            rc = 0
        else:
            path = HOME / (self.prefix + '-run/pid')
            assert live(self.server_id) and int(path.read_text()) == self.server.pid
            rc = self.run([self.shell, '--noprofile', '--norc', '-c', 'sshd stop'], 'stop').returncode
        try:
            status = self.server.wait(timeout=4)
        except subprocess.TimeoutExpired:
            status = None
        self.events.append({'label': 'server-exit', 'status': status,
                            'log_base64': b64(self.log_path.read_bytes())})
        return rc == status == 0

    def argv(self, command=None, options=(), key='client', user=None, agent=None):
        user = user or ('root' if os.geteuid() == 0 else 'parity')
        args = ['/usr/bin/ssh', '-vv', '-F', '/dev/null', '-o', 'BatchMode=yes',
                '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=' + (agent or 'none'),
                '-o', 'PreferredAuthentications=publickey', '-o', 'ConnectTimeout=3',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile=' + str(HOME / 'known_hosts'),
                '-i', str(HOME / key), '-p', str(PORT), *options, user + '@127.0.0.1']
        return args if command is None else args + [command]

    def probe(self, label, **kwargs):
        marker = HOME / ('ran-' + self.prefix + '-' + label)
        marker.unlink(missing_ok=True)
        p = self.run(self.argv(PROBE.format(marker=shlex.quote(str(marker))), **kwargs), label)
        return p, marker.exists()

    def close(self):
        for row in reversed(self.owned):
            if row['role'] == 'master':
                if live(row):
                    self.forced.append(row['pid'])
                    self.signal({k: v for k, v in row.items() if k != 'role'}, signal.SIGTERM)
                    wait_for(lambda: not live(row))
                else:
                    self.events.append({'label': 'cleanup-skipped-not-live', 'identity': row,
                                        'observed': identity(row['pid']), 'clock': clocks()})
        for p in reversed(self.children):
            if p.poll() is None:
                self.forced.append(p.pid)
                record = next(x for x in self.owned if x['pid'] == p.pid)
                self.signal({k: v for k, v in record.items() if k != 'role'}, signal.SIGTERM)
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.signal({k: v for k, v in record.items() if k != 'role'}, signal.SIGKILL)
                    p.wait(timeout=2)
        for row in self.owned:
            now = identity(row['pid'])
            if same_birth(now, row) and now['state'] == 'Z' and now['ppid'] == os.getpid():
                try:
                    if self.master_fd is not None and same_birth(row, self.master_record):
                        fd = os.dup(self.master_fd)
                    else:
                        fd = os.pidfd_open(row['pid'], 0)
                except ProcessLookupError:
                    continue
                try:
                    current = identity(row['pid'])
                    if (same_birth(current, row) and current['state'] == 'Z'
                            and current['ppid'] == os.getpid()):
                        try:
                            event = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                            self.events.append({'label': 'owned-pidfd-reap', 'identity': row,
                                                'event': None if event is None else {
                                                    key: getattr(event, key) for key in
                                                    ('si_pid', 'si_uid', 'si_signo', 'si_status', 'si_code')},
                                                'clock': clocks()})
                        except ChildProcessError:
                            self.events.append({'label': 'owned-pidfd-reap-not-child', 'identity': row,
                                                'clock': clocks()})
                    else:
                        self.events.append({'label': 'reap-refused-stale', 'identity': row,
                                            'observed': current, 'clock': clocks()})
                finally:
                    os.close(fd)
        if self.master_fd is not None:
            os.close(self.master_fd)
            self.master_fd = None
            self.master_record = None
        for handle in self.handles:
            handle.close()
        save(self.prefix + '-transcripts.json', {'events': self.events, 'owned': self.owned,
                                                'forced_cleanup_pids': self.forced})


def succeeded(p, marker):
    return p.returncode == 0 and marker and p.stdout == b'followup-ok\n'


def refused(p, marker, method='publickey'):
    return (not marker and p.returncode == 255 and not p.stdout and
            ('Permission denied (' + method + ').').encode() in p.stderr and
            b'Authenticated to ' not in p.stderr)


def config_case(f, scenario):
    result = f.observations
    if scenario == 'pubkey-disabled':
        f.config(); result['allowed-server-ready'] = f.start()
        p, ran = f.probe('pubkey-allowed')
        result['allowed-key-command'] = succeeded(p, ran)
        result['allowed-server-stopped'] = f.stop()
        # OpenSSH takes the first value; replace the global values rather than
        # appending contradictory duplicates and assuming last-value wins.
        f.config()
        text = f.config_path.read_text().replace('PasswordAuthentication no\n', 'PasswordAuthentication yes\n').replace('PubkeyAuthentication yes\n', 'PubkeyAuthentication no\n')
        f.config_path.write_text(text)
        f.events.append({'label': 'disabled-config', 'bytes_base64': b64(text.encode())})
        result['disabled-server-ready'] = f.start()
        p, ran = f.probe('pubkey-disabled')
        result['publickey-disabled-at-auth'] = result['allowed-key-command'] and refused(p, ran, 'password')
        result['disabled-command-not-run'] = not ran
        result['disabled-server-stopped'] = f.stop()
    elif scenario == 'relative-include':
        f.config(relative=True)
        result['server-ready'] = f.start()
        p, ran = f.probe('included-key')
        result['included-authorized-key-command'] = succeeded(p, ran)
        p, ran = f.probe('not-included-key', key='other')
        result['other-key-refused'] = refused(p, ran)
        result['nonmatching-invalid-fragment-ignored'] = result['server-ready'] and result['included-authorized-key-command']
        result['server-stopped'] = f.stop()
    else:
        raise ValueError(scenario)
    return result


def agent_reply(p, expected_key):
    try:
        data = json.loads(p.stdout)
        request = base64.b64decode(data['request_base64'])
        reply = base64.b64decode(data['reply_base64'])
        assert request == b'\x00\x00\x00\x01\x0b' and reply[0] == 12
        count = struct.unpack('!I', reply[1:5])[0]
        pos, keys = 5, []
        for _ in range(count):
            size = struct.unpack('!I', reply[pos:pos+4])[0]; pos += 4
            keys.append(reply[pos:pos+size]); pos += size
            size = struct.unpack('!I', reply[pos:pos+4])[0]; pos += 4 + size
        assert pos == len(reply)
        return (p.returncode == 0 and data['socket_present'] and data['request_sent'] and
                keys == [expected_key] and b'auth-agent@openssh.com' in p.stderr)
    except (ValueError, KeyError, IndexError, struct.error, AssertionError):
        return False


def agent_absent(p):
    try:
        data = json.loads(p.stdout)
        return (p.returncode == 0 and not data['socket_present'] and not data['request_sent'] and
                b'Authenticated to ' in p.stderr and b'auth-agent@openssh.com' not in p.stderr)
    except (ValueError, KeyError):
        return False


def agent_case(f, scenario):
    result = f.observations
    keybytes = base64.b64decode((HOME / 'client.pub').read_text().split()[1])
    f.events.append({'label': 'expected-fixture-agent-key', 'public_blob_base64': b64(keybytes)})
    socket_path = HOME / (f.prefix + '-agent.sock')
    log = (HOME / (f.prefix + '-agent.log')).open('wb'); f.handles.append(log)
    agent = subprocess.Popen(['/usr/bin/ssh-agent', '-D', '-a', str(socket_path)],
                             env=f.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    f.children.append(agent); agent_id = f.remember(agent.pid, 'agent')
    result['local-agent-ready'] = bool(wait_for(lambda: socket_path.exists() and agent.poll() is None))
    env = dict(f.env, SSH_AUTH_SOCK=str(socket_path))
    added = f.run(['/usr/bin/ssh-add', str(HOME / 'client')], 'local-agent-add', env=env)
    listed = f.run(['/usr/bin/ssh-add', '-L'], 'local-agent-identities', env=env)
    result['fixture-key-loaded'] = (added.returncode == listed.returncode == 0 and
                                  listed.stdout == (HOME / 'client.pub').read_bytes())
    if scenario == 'key-no-agent':
        (HOME / 'authorized_keys').write_bytes((HOME / 'client.pub').read_bytes() +
            b'no-agent-forwarding ' + (HOME / 'other.pub').read_bytes())
        extra = ['AllowAgentForwarding yes']
    elif scenario in ('match-user-agent', 'match-address-agent'):
        match = 'User parity' if scenario == 'match-user-agent' else 'Address 127.0.0.1'
        extra = ['AllowAgentForwarding yes', 'Match ' + match, 'AllowAgentForwarding no']
    elif scenario == 'match-all-agent':
        extra = ['AllowAgentForwarding no', 'Match User not-the-fixture-user', 'AllowAgentForwarding yes']
    else:
        extra = ['AllowAgentForwarding yes']
    f.config(extra); result['server-ready'] = f.start()
    options = ['-A']
    command = '/usr/bin/python3 ' + shlex.quote(str(HOME / 'agent-query.py')) + ' ' + shlex.quote(scenario)
    p = f.run(f.argv(command, options, agent=str(socket_path)), 'forwarded-identities', env=env, timeout=8)
    if scenario == 'match-all-agent':
        result['nonmatching-agent-refused'] = agent_absent(p)
        result['server-stopped-before-all'] = f.stop()
        f.config(['AllowAgentForwarding no', 'Match All', 'AllowAgentForwarding yes'])
        result['all-matching-server-ready'] = f.start()
        p = f.run(f.argv(command, options, agent=str(socket_path)), 'all-forwarded-identities', env=env, timeout=8)
        result['all-matching-agent-request-reply'] = agent_reply(p, keybytes)
        result['nonmatching-agent-refused'] = result['nonmatching-agent-refused'] and result['all-matching-agent-request-reply']
    elif scenario in ('match-user-agent', 'match-address-agent'):
        result['matched-agent-refused'] = agent_absent(p)
        result['server-stopped-before-nonmatch'] = f.stop()
        match = 'User not-the-fixture-user' if scenario == 'match-user-agent' else 'Address 192.0.2.0/24'
        f.config(['AllowAgentForwarding yes', 'Match ' + match, 'AllowAgentForwarding no'])
        result['nonmatching-server-ready'] = f.start()
        p = f.run(f.argv(command, options, agent=str(socket_path)), 'nonmatching-forwarded-identities', env=env, timeout=8)
        result['nonmatching-agent-request-reply'] = agent_reply(p, keybytes)
        result['matched-agent-refused'] = result['matched-agent-refused'] and result['nonmatching-agent-request-reply']
    else:
        result['forwarded-agent-request-reply'] = agent_reply(p, keybytes)
        if scenario == 'key-no-agent':
            p = f.run(f.argv(command, options, key='other', agent=str(socket_path)), 'restricted-key-agent', env=env, timeout=8)
            result['restricted-key-authenticated-command'] = p.returncode == 0 and b'Authenticated to ' in p.stderr
            result['per-key-agent-refused'] = result['forwarded-agent-request-reply'] and agent_absent(p)
    result['server-stopped'] = f.stop()
    f.signal(agent_id, signal.SIGTERM); agent.wait(timeout=3)
    result['local-agent-stopped'] = not live(agent_id)
    return result


def forward_case(f, scenario):
    result = f.observations
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0)); listener.listen(2); listener.settimeout(.2)
    destination = listener.getsockname()[1]
    # Denied requests must never reach this private listener. Allowed requests
    # carry bytes without client EOF, then the destination closes after reply.
    address = scenario == 'match-address-forward'
    deny = scenario != 'match-all-forward'
    for phase, match, global_policy, override, expected in [
            ('nonmatch', 'Address 192.0.2.0/24' if address else 'User not-the-fixture-user',
             'yes' if deny else 'no', 'no' if deny else 'yes', deny),
            ('match', ('Address 127.0.0.1' if address else 'User parity') if deny else 'All',
             'yes' if deny else 'no', 'no' if deny else 'yes', not deny)]:
        f.config(['AllowTcpForwarding ' + global_policy, 'Match ' + match, 'AllowTcpForwarding ' + override])
        result[phase + '-server-ready'] = f.start()
        log_path = HOME / (f.prefix + '-' + phase + '-client.log')
        log = log_path.open('wb'); f.handles.append(log)
        argv = f.argv(None, ['-W', '127.0.0.1:%d' % destination])
        p = subprocess.Popen(argv, env=f.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        f.children.append(p); f.remember(p.pid, 'forward-client-' + phase)
        try:
            p.stdin.write(b'match-forward\n'); p.stdin.flush()
        except BrokenPipeError:
            pass
        accepted, response = False, b''
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and p.poll() is None:
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            accepted = True
            with conn:
                conn.settimeout(2)
                received = b''
                while not received.endswith(b'\n'):
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    received += chunk
                response = b'echo:' + received
                conn.sendall(response)
            break
        try:
            out, _ = p.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            out = b''
        error = log_path.read_bytes()
        f.events.append({'label': phase + '-forward', 'argv': argv, 'accepted': accepted,
                         'reply_base64': b64(out), 'destination_reply_base64': b64(response),
                         'status': p.poll(), 'stderr_base64': b64(error)})
        result[phase + '-forward-policy-effect'] = ((accepted and out == b'echo:match-forward\n') if expected else
            (not accepted and p.poll() == 255 and b'administratively prohibited' in error))
        result[phase + '-server-stopped'] = f.stop()
    # Each negative control is qualified only by its paired actual round trip.
    negative = 'match' if deny else 'nonmatch'
    positive = 'nonmatch' if deny else 'match'
    result[negative + '-forward-policy-effect'] = (result[negative + '-forward-policy-effect'] and
                                                  result[positive + '-forward-policy-effect'])
    listener.close()
    return result


def tty_policy_case(f, scenario):
    result = f.observations
    user = scenario == 'match-user-tty'
    for phase, extra, allowed in [
            ('nonmatch', ['PermitTTY ' + ('yes' if user else 'no'),
                         'Match User not-the-fixture-user', 'PermitTTY ' + ('no' if user else 'yes')], user),
            ('match', ['PermitTTY yes', 'Match User parity', 'PermitTTY no'] if scenario == 'match-user-tty' else
             ['PermitTTY no', 'Match All', 'PermitTTY yes'], scenario == 'match-all-tty')]:
        f.config(extra); result[phase + '-server-ready'] = f.start()
        marker = HOME / ('tty-' + f.prefix + '-' + phase)
        marker.unlink(missing_ok=True)
        command = "if [ -t 0 ]; then printf 'actual-tty\\n'; else printf 'no-tty\\n'; fi; : > " + shlex.quote(str(marker))
        p = f.run(f.argv(command, ['-tt']), phase + '-pty-request')
        granted = (p.returncode == 0 and marker.exists() and
                   b'PTY allocation request accepted on channel' in p.stderr)
        if allowed:
            result[phase + '-pty-request-granted'] = granted
            result[phase + '-real-remote-pty'] = p.stdout.replace(b'\r\n', b'\n') == b'actual-tty\n'
        else:
            result[phase + '-pty-request-refused'] = (p.returncode == 255 and not marker.exists() and
                b'PTY allocation request failed on channel' in p.stderr)
        result[phase + '-server-stopped'] = f.stop()
    negative = 'match' if user else 'nonmatch'
    positive = 'nonmatch' if user else 'match'
    result[negative + '-pty-request-refused'] = (result[negative + '-pty-request-refused'] and
                                               result[positive + '-pty-request-granted'])
    return result


def root_case(f):
    result = f.observations
    for phase, match in [('allowed', None), ('user-denied', 'User root'),
                         ('address-denied', 'Address 127.0.0.1'), ('all-denied', 'All')]:
        extra = ['PermitRootLogin yes']
        if match:
            extra += ['Match ' + match, 'PermitRootLogin no']
        f.config(extra); result[phase + '-server-ready'] = f.start()
        p, ran = f.probe(phase, user='root')
        if match:
            result[phase + '-publickey-refused'] = result['root-key-command'] and refused(p, ran)
        else:
            result['root-key-command'] = succeeded(p, ran)
            uid = f.run(f.argv('/usr/bin/id -u', user='root'), 'root-uid')
            result['actual-root-uid'] = uid.returncode == 0 and uid.stdout == b'0\n'
        result[phase + '-server-stopped'] = f.stop()
    return result


def sftp_case(f):
    result = f.observations
    f.config(); result['server-ready'] = f.start()
    remote = HOME / (f.prefix + '-remote')
    remote.mkdir(exist_ok=True)
    (HOME / 'upload.bin').write_bytes(DATA)
    output = HOME / (f.prefix + '-download.bin')
    batch = ('put ' + str(HOME / 'upload.bin') + ' ' + str(remote / 'present.bin') + '\n' +
             'chmod 640 ' + str(remote / 'present.bin') + '\n' +
             'ls -1 ' + str(remote) + '\n' +
             'get ' + str(remote / 'present.bin') + ' ' + str(output) + '\n')
    batch_path = HOME / (f.prefix + '-sftp.batch'); batch_path.write_text(batch)
    argv = ['/usr/bin/sftp', '-vv', '-F', '/dev/null', '-b', str(batch_path),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'UserKnownHostsFile=' + str(HOME / 'known_hosts'), '-i', str(HOME / 'client'),
            '-P', str(PORT), 'parity@127.0.0.1']
    p = f.run(argv, 'sftp-put-list-get', timeout=8)
    result['sftp-subsystem-authenticated'] = p.returncode == 0 and b'Authenticated to ' in p.stderr
    result['uploaded-file-bytes-and-mode'] = ((remote / 'present.bin').exists() and
        (remote / 'present.bin').read_bytes() == DATA and stat.S_IMODE((remote / 'present.bin').stat().st_mode) == 0o640)
    # The echoed ls command contains only the directory, never present.bin.
    # A separate line containing that basename must come from the listing.
    listing = [line.strip() for line in p.stdout.decode(errors='replace').splitlines()
               if line.strip() in ('present.bin', str(remote / 'present.bin'))]
    result['directory-listing-contains-created-file'] = bool(listing)
    result['downloaded-exact-bytes'] = output.exists() and output.read_bytes() == DATA
    f.events.append({'label': 'sftp-observed-files', 'batch': batch, 'listing_lines': listing,
                     'download_base64': b64(output.read_bytes()) if output.exists() else None,
                     'remote_mode': stat.S_IMODE((remote / 'present.bin').stat().st_mode) if (remote / 'present.bin').exists() else None})
    result['server-stopped'] = f.stop()
    return result


class PtyClient:
    def __init__(self, f, argv, label):
        self.f, self.label, self.data = f, label, b''
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        def attach():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.proc = subprocess.Popen(argv, env=f.env, stdin=slave, stdout=slave, stderr=slave,
                                     preexec_fn=attach, close_fds=True)
        os.close(slave)
        f.children.append(self.proc)
        self.record = f.remember(self.proc.pid, 'pty-client-' + label)
        f.events.append({'label': label + '-start', 'argv': argv, 'identity': self.record})

    def read_until(self, wanted, seconds=4):
        end = time.monotonic() + seconds
        while wanted not in self.data and time.monotonic() < end:
            ready, _, _ = select.select([self.master], [], [], .05)
            if ready:
                try:
                    data = os.read(self.master, 8192)
                except OSError:
                    break
                if not data:
                    break
                self.data += data
                assert len(self.data) < 1024 * 1024
            elif self.proc.poll() is not None:
                break
        return wanted in self.data

    def send(self, data):
        os.write(self.master, data)
        self.f.events.append({'label': self.label + '-send', 'bytes_base64': b64(data)})

    def observe(self, resize):
        result = {}
        self.send(PTY_QUERY.encode())
        result['interactive-shell-real-pty-and-command'] = self.read_until(b'PTY_OK:24 80\r\n')
        if result['interactive-shell-real-pty-and-command'] and resize:
            foreground = os.tcgetpgrp(self.master)
            assert foreground == self.proc.pid
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack('HHHH', 39, 107, 0, 0))
            self.f.events.append({'label': 'local-pty-resize', 'rows': 39, 'cols': 107,
                                  'foreground_pid': foreground, 'owned_client_pid': self.proc.pid})
            time.sleep(.2)
            self.send(PTY_QUERY.encode())
            result['remote-window-change-observed'] = self.read_until(b'PTY_OK:39 107\r\n')
        if result['interactive-shell-real-pty-and-command']:
            self.send(b'exit 0\n')
        try:
            status = self.proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            status = None
        self.read_until(b'__never_emitted__', .1)
        result['interactive-client-exits-zero'] = status == 0
        self.f.events.append({'label': self.label + '-transcript', 'status': status,
                              'output_base64': b64(self.data)})
        os.close(self.master)
        return result


def client_server(f):
    # Client subjects are driven against the independent OpenSSH server.
    original = f.reference
    f.reference = True
    f.config()
    f.reference = original
    return f.start(force_reference=True)


def pty_case(f):
    result = f.observations
    result['server-ready'] = client_server(f)
    if not result['server-ready']:
        return result
    argv = (f.argv(None, ['-tt']) if f.reference else
            [f.shell, '--noprofile', '--norc', '-c', CONNECT_SHELL,
             'interactive', str(PORT), str(HOME / 'client')])
    result.update(PtyClient(f, argv, 'interactive').observe(True))
    result['server-stopped'] = f.stop()
    return result


def control(f, path, operation):
    argv = (['/usr/bin/ssh', '-F', '/dev/null', '-p', str(PORT), '-S', str(path),
             '-O', operation, 'parity@127.0.0.1'] if f.reference else
            [f.shell, '--noprofile', '--norc', '-c', 'ssh -O "$1" -S "$2"',
             'control', operation, str(path)])
    return f.run(argv, 'master-' + operation)


def control_refused(f, path):
    p = control(f, path, 'check')
    phrase = b'Control socket connect' if f.reference else b'no live ControlMaster'
    return p.returncode in (1, 255) and not path.exists() and phrase in p.stderr


def master_start(f, path, persist):
    (HOME / (f.prefix + '-master.log')).write_bytes(b'')
    if f.reference:
        log = (HOME / (f.prefix + '-master.log')).open('wb'); f.handles.append(log)
        args = f.argv(None, ['-M', '-N', '-f', '-S', str(path), '-o', 'ControlMaster=yes',
                            '-o', 'ControlPersist=' + (str(persist) if persist else 'no')])
        p = subprocess.Popen(args, env=f.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        f.children.append(p); f.remember(p.pid, 'master-launcher')
        f.events.append({'label': 'master-launch', 'argv': args})
        wait_for(lambda: path.exists() or p.poll() is not None)
        started = path.exists()
    else:
        args = [f.shell, '--noprofile', '--norc', '-c',
                'ssh master 127.0.0.1 -p "$1" -l parity -i "$2" -S "$3" --persist "$4"',
                'master', str(PORT), str(HOME / 'client'), str(path), str(persist) if persist else 'yes']
        started = f.run(args, 'master-launch', timeout=8).returncode == 0
    check = control(f, path, 'check')
    match = re.search(rb'pid=([0-9]+)', check.stdout + check.stderr)
    if not started or check.returncode != 0 or not match:
        return None
    record = f.remember(int(match[1]), 'master', adopted=True)
    f.pin_master(record)
    f.events.append({'label': 'master-owned', 'identity': record, 'socket': str(path),
                     'socket_mode': stat.S_IMODE(path.stat().st_mode)})
    f.master_snapshot('adopted', record, path)
    return record


def one_transport(f, label):
    text = f.log_path.read_text(errors='replace')
    accepted = [l for l in text.splitlines() if 'Accepted publickey for parity from 127.0.0.1' in l]
    rows = tcp_rows(state='01')
    f.events.append({'label': label, 'accepted_publickey_lines': accepted, 'established_server_rows': rows})
    return len(accepted) == len(rows) == 1


def persistence_anchor(f, path, master):
    # OpenSSH10.0p2 uses integral monotime() (CLOCK_BOOTTIME on Linux);
    # BashOS uses integral time(NULL). Align the final control request just
    # after the selected clock's second boundary. The original2.75..5.5s
    # bounds then remain meaningful without rounding an early exit to pass.
    clock_id = time.CLOCK_BOOTTIME if f.reference else time.CLOCK_REALTIME
    for attempt in range(3):
        now = time.clock_gettime(clock_id)
        time.sleep(int(now) + 1.04 - now)
        clocks_before = clocks()
        before = time.clock_gettime(clock_id)
        check = control(f, path, 'check')
        anchored_at = time.monotonic()
        after = time.clock_gettime(clock_id)
        clocks_after = clocks()
        pid = re.search(rb'pid=([0-9]+)', check.stdout + check.stderr)
        valid = (check.returncode == 0 and pid is not None and
                 int(pid[1]) == master['pid'] and live(master) and path.exists() and
                 int(before) == int(after) and
                 .02 <= before - int(before) <= after - int(after) <= .20)
        f.events.append({'label': 'persistence-timing-anchor', 'attempt': attempt,
                         'clock': 'CLOCK_BOOTTIME' if f.reference else 'CLOCK_REALTIME',
                         'clock_before': before, 'clock_after': after,
                         'clocks_before': clocks_before, 'clocks_after': clocks_after,
                         'monotonic_anchor': anchored_at, 'owned_master_pid': master['pid'],
                         'reported_pid': int(pid[1]) if pid else None,
                         'valid': bool(valid)})
        if valid:
            return anchored_at
    return None


def mux_case(f, scenario):
    result = f.observations
    result['server-ready'] = client_server(f)
    if not result['server-ready']:
        return result
    directory = HOME / (f.prefix + '-control')
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / 'master.sock'
    master = master_start(f, path, 3 if scenario == 'master-persist' else None)
    result['master-start-and-check-owned-process'] = master is not None
    if master is None:
        return result
    result['one-authenticated-tcp-transport'] = one_transport(f, 'initial-transport')
    if scenario == 'master-persist':
        started = persistence_anchor(f, path, master)
        result['timing-anchor-owned-control'] = started is not None
        if started is None:
            return result  # No persistence conclusion without a valid anchor.
        # No more check clients while measuring: those reset idle time.
        f.master_snapshot('persist-before-wait', master, path)
        f.events.append({'label': 'persist-wait-start', 'anchor_monotonic_seconds': started,
                         'clock': clocks()})
        observed_live = live(master) and path.exists()
        ended = wait_for(lambda: not live(master) and not path.exists(), 6)
        elapsed = time.monotonic() - started
        f.events.append({'label': 'persist-wait-end', 'elapsed_seconds': elapsed,
                         'returned': bool(ended), 'clock': clocks()})
        f.master_snapshot('persist-after-wait', master, path)
        f.events.append({'label': 'idle-persist-duration', 'requested_seconds': 3,
                         'elapsed_seconds': elapsed, 'initially_live': observed_live,
                         'ended_without_signal': bool(ended), 'minimum_seconds': 2.75, 'maximum_seconds': 5.5})
        result['persist-three-seconds-then-exit'] = observed_live and bool(ended) and 2.75 <= elapsed <= 5.5
        result['expired-master-socket-removed'] = not path.exists() and not live(master)
        result['expired-master-check-refused'] = control_refused(f, path)
        f.master_snapshot('persist-after-refused-check', master, path)
    else:
        command = EXEC_MARKER
        argv = (f.argv(command, ['-S', str(path), '-o', 'ControlMaster=no']) if f.reference else
                [f.shell, '--noprofile', '--norc', '-c', 'ssh exec -S "$1" "$2"', 'exec', str(path), command])
        p = f.run(argv, 'mux-exec')
        result['exec-through-master-exact-bytes'] = p.returncode == 0 and p.stdout == b'mux-exec-ok\n'
        result['same-transport-after-exec'] = one_transport(f, 'after-exec-transport')
        argv = (f.argv(None, ['-tt', '-S', str(path), '-o', 'ControlMaster=no']) if f.reference else
                [f.shell, '--noprofile', '--norc', '-c', 'ssh shell -S "$1"', 'shell', str(path)])
        shell_result = PtyClient(f, argv, 'mux-shell').observe(False)
        result['shell-through-master-real-pty-command'] = all(shell_result.values())
        result['same-transport-after-shell'] = one_transport(f, 'after-shell-transport')
        local = HOME / (f.prefix + '-mux-upload')
        remote = HOME / (f.prefix + '-mux-remote')
        output = HOME / (f.prefix + '-mux-download')
        local.write_bytes(DATA)
        if f.reference:
            batch = HOME / (f.prefix + '-mux.batch')
            batch.write_text('put ' + str(local) + ' ' + str(remote) + '\nchmod 640 ' + str(remote) + '\nget ' + str(remote) + ' ' + str(output) + '\n')
            argv = ['/usr/bin/sftp', '-F', '/dev/null', '-b', str(batch), '-o', 'ControlPath=' + str(path),
                    '-o', 'ControlMaster=no', '-o', 'BatchMode=yes', '-P', str(PORT), 'parity@127.0.0.1']
            p = f.run(argv, 'mux-sftp', timeout=8)
            status = p.returncode
        else:
            put = f.run([f.shell, '--noprofile', '--norc', '-c',
                         'ssh sftp -S "$1" put "$2" "$3" --mode 0640', 'put', str(path), str(local), str(remote)], 'mux-sftp-put')
            get = f.run([f.shell, '--noprofile', '--norc', '-c',
                         'ssh sftp -S "$1" get "$2" "$3"', 'get', str(path), str(remote), str(output)], 'mux-sftp-get')
            status = put.returncode or get.returncode
        result['sftp-through-master-bytes-and-mode'] = (status == 0 and remote.exists() and output.exists() and
            remote.read_bytes() == output.read_bytes() == DATA and stat.S_IMODE(remote.stat().st_mode) == 0o640)
        result['same-transport-after-sftp'] = one_transport(f, 'after-sftp-transport')
        result['master-check-still-owned'] = control(f, path, 'check').returncode == 0 and live(master)
        f.master_snapshot('exit-before-request', master, path)
        f.events.append({'label': 'exit-request-start', 'clock': clocks()})
        result['master-exit-request-succeeds'] = control(f, path, 'exit').returncode == 0
        f.events.append({'label': 'exit-wait-start', 'clock': clocks()})
        result['master-exits-and-removes-socket'] = bool(wait_for(lambda: not live(master) and not path.exists()))
        f.events.append({'label': 'exit-wait-end', 'clock': clocks(),
                         'returned': result['master-exits-and-removes-socket']})
        f.master_snapshot('exit-after-wait', master, path)
        result['exited-master-check-refused'] = control_refused(f, path)
        f.master_snapshot('exit-after-refused-check', master, path)
    result['server-stopped'] = f.stop()
    return result


def evaluate(shell, scenario, reference=False, prefix='behavior'):
    f = Fixture(shell, reference, prefix)
    result = f.observations
    try:
        if scenario in ('pubkey-disabled', 'relative-include'):
            result.update(config_case(f, scenario))
        elif scenario in ('agent-identities', 'key-no-agent', 'match-user-agent', 'match-address-agent', 'match-all-agent'):
            result.update(agent_case(f, scenario))
        elif scenario in ('match-user-forward', 'match-address-forward', 'match-all-forward'):
            result.update(forward_case(f, scenario))
        elif scenario in ('match-user-tty', 'match-all-tty'):
            result.update(tty_policy_case(f, scenario))
        elif scenario == 'match-root':
            result.update(root_case(f))
        elif scenario == 'sftp-listing':
            result.update(sftp_case(f))
        elif scenario == 'pty-resize':
            result.update(pty_case(f))
        elif scenario in ('master-persist', 'master-routing'):
            result.update(mux_case(f, scenario))
        else:
            raise ValueError(scenario)
    finally:
        f.close()
        result['unforced-cleanup'] = not f.forced
        save(prefix + '-results.json', result)
        # The guest collector retains at most 1 MiB per file and 4 MiB total.
        # Missing logs on an early failure remain visibly missing in diagnostics.
        diagnostic_names = [side + '-' + suffix for side in ('control', 'behavior')
                            for suffix in ('results.json', 'transcripts.json', 'server.log', 'master.log')]
        total = 0
        for name in diagnostic_names:
            try:
                info = (HOME / name).lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 ** 2:
                raise RuntimeError('diagnostic file invalid or larger than collector limit: ' + name)
            total += info.st_size
        if total > 4 * 1024 ** 2:
            raise RuntimeError('diagnostics exceed collector aggregate limit')
    return result


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] not in ('setup', 'run'):
        raise RuntimeError('usage: setup|run SHELL master-persist|master-routing')
    verb, shell, scenario = sys.argv[1:4]
    guard(scenario)
    if verb == 'setup':
        prepare()
        controls = evaluate('/bin/bash', scenario, True, 'control')
        assert controls and all(controls.values()), controls
        print('independent-openssh-controls=verified')
    elif verb == 'run':
        result = evaluate(shell, scenario)
        for label, value in result.items():
            print(label + '=' + ('yes' if value else 'no'))
    else:
        raise ValueError(verb)
