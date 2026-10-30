#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only, independently accounted ncdu mount-boundary fixture."""
import base64
import ctypes
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import struct
import subprocess
import sys
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
HELPER = '/opt/bashos-parity/harness/helpers/ncdu-boundary-reviewed.py'
LIMIT = 256 * 1024
EVENT_LIMIT = 32 * 1024
IN_ACCESS, IN_OPEN = 0x00000001, 0x00000020
IN_UNMOUNT, IN_Q_OVERFLOW, IN_IGNORED = 0x00002000, 0x00004000, 0x00008000


def guard(inner=False):
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    uuid.UUID(marker)
    subprocess.run(['/usr/bin/python3', '/opt/bashos-parity/harness/helpers/ns_guest_identity_r1.py'],
                   check=True, timeout=5)
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU' or
        Path.cwd() != CASE or os.environ.get('HOME') != str(HOME)):
        raise RuntimeError('guest identity or scratch guard failed')
    ids = (os.getuid(), os.geteuid())
    if inner:
        if ids != (0, 0) or Path('/proc/self/uid_map').read_text().split() != ['0', '2000', '1']:
            raise RuntimeError('unexpected user namespace mapping')
    elif ids != (2000, 2000):
        raise RuntimeError('expected uid/euid 2000')


def records(data):
    """Parse complete du-style output, rejecting duplicates and malformed rows."""
    if not data or not data.endswith(b'\n'):
        raise ValueError('empty or incomplete listing')
    out = {}
    for row in data.splitlines():
        match = re.fullmatch(rb'([0-9]+)\t([^\t\r\n]+)', row)
        if not match:
            raise ValueError('malformed listing row')
        path = match.group(2).decode('ascii')
        if path in out:
            raise ValueError('duplicate listing path')
        out[path] = int(match.group(1))
    return out


def parser_selftest():
    if records(b'1\ttree/a\n2\ttree\n') != {'tree/a': 1, 'tree': 2}:
        raise RuntimeError('parser positive self-test failed')
    for data in (b'', b'1\ttree', b'1 tree\n', b'x\ttree\n',
                 b'1\ttree\n2\ttree\n', b'1\ttree\nextra\n'):
        try:
            records(data)
        except (ValueError, UnicodeError):
            continue
        raise RuntimeError('parser negative self-test failed')
    sample = struct.pack('=iIII', 4, IN_OPEN, 0, 0)
    parsed = event_records(sample, {4: 'foreign'})
    if len(parsed) != 1 or parsed[0]['mask'] != IN_OPEN or parsed[0]['name_base64']:
        raise RuntimeError('event parser positive self-test failed')
    for bad in (sample[:-1], sample + b'\0', struct.pack('=iIII', -1, IN_Q_OVERFLOW, 0, 0),
                struct.pack('=iIII', 4, IN_OPEN, 0, 4) + b'abcd',
                struct.pack('=iIII', 5, IN_OPEN, 0, 0)):
        try:
            event_records(bad, {4: 'foreign'})
        except RuntimeError:
            continue
        raise RuntimeError('event parser negative self-test failed')


def save(name, data):
    (HOME / ('ncdu-boundary-' + name)).write_bytes(data)


def command(argv, name, timeout=15):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        save(name + '.out', exc.stdout or b'')
        save(name + '.err', exc.stderr or b'')
        save(name + '.status', b'timeout\n')
        raise
    save(name + '.out', result.stdout)
    save(name + '.err', result.stderr)
    save(name + '.status', (str(result.returncode) + '\n').encode())
    return result


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


def event_records(raw, watches):
    events = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 16:
            raise RuntimeError('truncated inotify header')
        wd, mask, cookie, length = struct.unpack_from('=iIII', raw, offset)
        end = offset + 16 + length
        if end > len(raw) or (length and b'\0' not in raw[offset + 16:end]):
            raise RuntimeError('truncated inotify name')
        if mask & (IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED) or wd not in watches:
            raise RuntimeError('inotify watch lost or queue overflow')
        name = bytes(raw[offset + 16:end]).split(b'\0', 1)[0]
        events.append({'watch': watches[wd], 'wd': wd, 'mask': mask,
                       'cookie': cookie, 'name_base64': base64.b64encode(name).decode()})
        offset = end
    return events


class DirectoryObserver:
    """Fresh inotify watches; stat is silent while directory opens are visible."""
    def __init__(self, tree):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.inotify_init1.argtypes = [ctypes.c_int]
        self.libc.inotify_init1.restype = ctypes.c_int
        self.libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.libc.inotify_add_watch.restype = ctypes.c_int
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'inotify_init1')
        self.watches = {}
        self.raw = bytearray()
        self.closed = False
        try:
            for name in ('foreign', 'foreign/deep'):
                wd = self.libc.inotify_add_watch(self.fd, os.fsencode(tree / name), IN_OPEN | IN_ACCESS)
                if wd < 0:
                    raise OSError(ctypes.get_errno(), 'inotify_add_watch ' + name)
                if wd in self.watches:
                    raise RuntimeError('duplicate watch descriptor')
                self.watches[wd] = name
        except Exception:
            os.close(self.fd)
            raise

    def finish(self):
        raw = self.raw
        try:
            while True:
                try:
                    chunk = os.read(self.fd, 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    raise RuntimeError('unexpected inotify EOF')
                raw.extend(chunk)
                if len(raw) > EVENT_LIMIT:
                    raise RuntimeError('inotify observation exceeds limit')
        finally:
            os.close(self.fd)
            self.closed = True
        events = event_records(raw, self.watches)
        return {'complete': True, 'watches': self.watches, 'events': events,
                'raw_base64': base64.b64encode(raw).decode(), 'bytes': len(raw)}


def observation(tree, label, report, action):
    """Preserve stage and observer failures even when setup aborts."""
    item = {'state': 'starting', 'complete': False}
    report['observations'][label] = item
    save('observer.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    watcher = None
    try:
        watcher = DirectoryObserver(tree)
        item['state'] = 'running'
        save('observer.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
        outcome = action()
        item['outcome'] = outcome
        events = watcher.finish()
        watcher = None
        item.update(events)
        item['state'] = 'complete'
    except Exception as exc:
        item['state'] = 'error'
        item['error'] = type(exc).__name__ + ': ' + str(exc)
        if isinstance(exc, subprocess.TimeoutExpired):
            item['outcome'] = {'timeout': True,
                               'stdout_base64': base64.b64encode(exc.stdout or b'').decode(),
                               'stderr_base64': base64.b64encode(exc.stderr or b'').decode()}
        if watcher is not None and not watcher.closed:
            try:
                item['partial'] = watcher.finish()
            except Exception as inner:
                item['observer_error'] = type(inner).__name__ + ': ' + str(inner)
        if watcher is not None:
            item['raw_on_error_base64'] = base64.b64encode(watcher.raw).decode()
            item['raw_on_error_bytes'] = len(watcher.raw)
        raise
    finally:
        save('observer.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    return item


def touched(item, name):
    return any(event['watch'] == name and event['mask'] & (IN_OPEN | IN_ACCESS)
               for event in item['events'])


def opened(item, name):
    return any(event['watch'] == name and event['mask'] & IN_OPEN and
               not event['name_base64'] for event in item['events'])


def setup_inner(mode, outer_user, outer_mount):
    guard(True)
    parser_selftest()
    ns = {name: os.readlink('/proc/self/ns/' + name) for name in ('user', 'mnt')}
    if ns['user'] == outer_user or ns['mnt'] == outer_mount:
        raise RuntimeError('user or mount namespace was not isolated')
    tree = CASE / 'tree'
    (tree / 'local').mkdir(parents=True)
    (tree / 'foreign').mkdir()
    mount = command(['/usr/bin/mount', '-t', 'tmpfs', '-o', 'size=4m,nodev,nosuid',
                     'ncdu-boundary', str(tree / 'foreign')], 'mount')
    if mount.returncode:
        raise RuntimeError('private tmpfs mount failed')
    (tree / 'foreign' / 'deep').mkdir()
    for name, size in [('local/stay', 8192), ('foreign/deep/payload', 32768)]:
        with (tree / name).open('wb') as f:
            f.write(b'Q' * size)
            f.flush()
            os.fsync(f.fileno())
    paths = ['tree', 'tree/local', 'tree/local/stay', 'tree/foreign',
             'tree/foreign/deep', 'tree/foreign/deep/payload']
    stats = {}
    for name in paths:
        s = os.lstat(CASE / name)
        stats[name] = {'dev': s.st_dev, 'ino': s.st_ino, 'size': s.st_size,
                       'blocks': s.st_blocks, 'mode': s.st_mode, 'nlink': s.st_nlink}
    mount_lines = [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                   if line.split(' - ', 1)[0].split()[4] == str(tree / 'foreign')]
    save('control.json', (json.dumps({'mode': mode, 'namespaces': ns,
                                     'outer_user': outer_user, 'outer_mount': outer_mount,
                                     'stats': stats, 'mountinfo': mount_lines},
                                    sort_keys=True, indent=2) + '\n').encode())
    rootdev = stats['tree']['dev']
    if (stats['tree/local']['dev'] != rootdev or stats['tree/local/stay']['dev'] != rootdev or
        stats['tree/foreign']['dev'] == rootdev or
        any(stats[p]['dev'] != stats['tree/foreign']['dev'] for p in
            ('tree/foreign/deep', 'tree/foreign/deep/payload')) or
        stats['tree/local/stay']['size'] != 8192 or
        stats['tree/foreign/deep/payload']['size'] != 32768 or
        stats['tree/local/stay']['blocks'] <= 0 or stats['tree/foreign/deep/payload']['blocks'] <= 0 or
        any(stats[p]['nlink'] != 1 or not stat.S_ISREG(stats[p]['mode']) for p in
            ('tree/local/stay', 'tree/foreign/deep/payload')) or
        any(not stat.S_ISDIR(stats[p]['mode']) for p in
            ('tree', 'tree/local', 'tree/foreign', 'tree/foreign/deep')) or
        (tree / 'local/stay').read_bytes() != b'Q' * 8192 or
        (tree / 'foreign/deep/payload').read_bytes() != b'Q' * 32768 or
        len(mount_lines) != 1 or mount_lines[0].split(' - ', 1)[1].split()[0] != 'tmpfs' or
        any(x.startswith('shared:') for x in mount_lines[0].split(' - ', 1)[0].split()[6:])):
        raise RuntimeError('fixture device/content/allocation preconditions failed')
    # Calculate from individual lstat observations, independently of both tools.
    b = {p: stats[p]['blocks'] * 512 for p in paths}
    local = b['tree/local'] + b['tree/local/stay']
    deep = b['tree/foreign/deep'] + b['tree/foreign/deep/payload']
    foreign = b['tree/foreign'] + deep
    full = {'tree/local': local, 'tree/foreign/deep': deep,
            'tree/foreign': foreign, 'tree': b['tree'] + local + foreign}
    # The boundary inode itself may be listed by the candidate, but its contents
    # must not be counted; its zero allocation keeps either listing unambiguous.
    if b['tree/foreign'] != 0 or foreign <= 0 or full['tree'] <= b['tree'] + local:
        raise RuntimeError('boundary allocation does not permit an unambiguous oracle')
    one = {'tree/local': local, 'tree': b['tree'] + local}
    observer = {'version': 1, 'mode': mode, 'observations': {}}

    def metadata_control():
        result = subprocess.run(['/usr/bin/stat', '-c', '%d:%i', 'tree/foreign'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=False)
        return {'returncode': result.returncode,
                'stdout_base64': base64.b64encode(result.stdout).decode(),
                'stderr_base64': base64.b64encode(result.stderr).decode()}

    negative = observation(tree, 'metadata-only', observer, metadata_control)
    expected_stat = ('%d:%d\n' % (stats['tree/foreign']['dev'], stats['tree/foreign']['ino'])).encode()
    if (negative['outcome'] != {'returncode': 0,
                                 'stdout_base64': base64.b64encode(expected_stat).decode(),
                                 'stderr_base64': ''} or
        touched(negative, 'foreign') or touched(negative, 'foreign/deep')):
        raise RuntimeError('metadata-only observer control failed')

    for label, argv, expected in (
        ('du-x', ['/usr/bin/du', '-x', '-B1', 'tree'], one),
        ('du-full', ['/usr/bin/du', '-B1', 'tree'], full)):
        if label == 'du-full':
            def positive_control():
                result = command(argv, label)
                return {'returncode': result.returncode,
                        'stdout_base64': base64.b64encode(result.stdout).decode(),
                        'stderr_base64': base64.b64encode(result.stderr).decode()}
            positive = observation(tree, 'native-traversal', observer, positive_control)
            if not opened(positive, 'foreign') or not opened(positive, 'foreign/deep'):
                raise RuntimeError('native traversal observer control failed')
            outcome = positive['outcome']
            stdout = base64.b64decode(outcome['stdout_base64'], validate=True)
            stderr = base64.b64decode(outcome['stderr_base64'], validate=True)
            rc = outcome['returncode']
        else:
            result = command(argv, label)
            stdout, stderr, rc = result.stdout, result.stderr, result.returncode
        observed = records(stdout)
        allowed = dict(expected)
        if label == 'du-x' and 'tree/foreign' in observed:
            allowed['tree/foreign'] = 0
        if rc or stderr or observed != allowed:
            raise RuntimeError(label + ' native control disagrees with stat accounting')
    report = {'mode': mode, 'namespaces': ns, 'outer_user': outer_user,
              'outer_mount': outer_mount, 'stats': stats, 'mountinfo': mount_lines,
              'one': one, 'full': full,
              'parser_selftest': 'ok'}
    save('control.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    # The observed command is a fresh invocation of the selected frozen build.
    script = ('if [[ $(type -t ncdu) != builtin ]]; then printf "ncdu builtin missing\\n" >&2; exit 99; fi\n'
              + ('ncdu -p -x tree\n' if mode == 'x' else 'ncdu -p tree\n'))
    env = dict(os.environ, PATH='/empty', BASH_ENV='', ENV='')
    def candidate_call():
        with (HOME / 'ncdu-boundary-candidate.out').open('wb') as out, \
             (HOME / 'ncdu-boundary-candidate.err').open('wb') as err:
            proc = subprocess.Popen(['/opt/bashos-parity/candidate', '--noprofile', '--norc', '-c', script],
                                    stdout=out, stderr=err, env=env,
                                    preexec_fn=limits, start_new_session=True)
            try:
                status = {'returncode': proc.wait(timeout=15), 'timeout': False}
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                reaped = proc.wait(timeout=5)
                status = {'returncode': None, 'timeout': True, 'reaped_returncode': reaped}
            status.update(pid=proc.pid, group_empty=False)
            save('candidate.status', (json.dumps(status, sort_keys=True) + '\n').encode())
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                pass
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                raise RuntimeError('candidate left processes in its observation group')
            status['group_empty'] = True
            save('candidate.status', (json.dumps(status, sort_keys=True) + '\n').encode())
        return status
    observation(tree, 'candidate', observer, candidate_call)


def setup(mode):
    guard()
    parser_selftest()
    ns = [os.readlink('/proc/self/ns/' + name) for name in ('user', 'mnt')]
    result = command(['/usr/bin/unshare', '--user', '--map-root-user', '--mount',
                      '--propagation', 'private', '/usr/bin/python3', HELPER,
                      'inner', mode, *ns], 'setup', timeout=50)
    if result.returncode:
        raise RuntimeError('namespace, mount or native preflight failed; see setup diagnostics')


def verify(mode):
    guard()
    report = json.loads((HOME / 'ncdu-boundary-control.json').read_text())
    status = json.loads((HOME / 'ncdu-boundary-candidate.status').read_text())
    observer = json.loads((HOME / 'ncdu-boundary-observer.json').read_text())
    out = (HOME / 'ncdu-boundary-candidate.out').read_bytes()
    err = (HOME / 'ncdu-boundary-candidate.err').read_bytes()
    if report['mode'] != mode or report['parser_selftest'] != 'ok':
        raise RuntimeError('missing matching setup preconditions')
    if observer['version'] != 1 or observer['mode'] != mode:
        raise RuntimeError('missing matching observer preconditions')
    observations = observer['observations']
    if (set(observations) != {'metadata-only', 'native-traversal', 'candidate'} or
        any(item['state'] != 'complete' or item['complete'] is not True for item in observations.values()) or
        observations['candidate']['outcome'] != status):
        raise RuntimeError('incomplete observer records')
    candidate_events = observations['candidate']
    if mode == 'x' and (touched(candidate_events, 'foreign') or touched(candidate_events, 'foreign/deep')):
        raise ValueError('candidate traversed the foreign filesystem with -x')
    if mode == 'full' and (not opened(candidate_events, 'foreign') or
                           not opened(candidate_events, 'foreign/deep')):
        raise ValueError('candidate did not open the foreign directories')
    if (status.get('returncode') != 0 or status.get('timeout') is not False or
        status.get('group_empty') is not True or not isinstance(status.get('pid'), int) or err):
        raise ValueError('candidate failed, timed out, or produced diagnostics')
    if len(out) >= LIMIT or len(err) >= LIMIT:
        raise ValueError('candidate output hit capture limit')
    actual = records(out)
    expected = dict(report['one'] if mode == 'x' else report['full'])
    if mode == 'x' and 'tree/foreign' in actual:
        expected['tree/foreign'] = 0
    if actual != expected:
        raise ValueError('candidate directory accounting differs: actual=%r expected=%r' % (actual, expected))
    print('ncdu-boundary-' + mode + '-verified')


def main():
    if len(sys.argv) == 3 and sys.argv[1] == 'setup' and sys.argv[2] in ('x', 'full'):
        setup(sys.argv[2])
    elif len(sys.argv) == 5 and sys.argv[1] == 'inner' and sys.argv[2] in ('x', 'full'):
        setup_inner(*sys.argv[2:])
    elif len(sys.argv) == 3 and sys.argv[1] == 'verify' and sys.argv[2] in ('x', 'full'):
        verify(sys.argv[2])
    else:
        raise RuntimeError('invalid helper invocation')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        sys.exit(1)
