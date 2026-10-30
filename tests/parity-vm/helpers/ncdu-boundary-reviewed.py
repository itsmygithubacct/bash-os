#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only, independently accounted ncdu mount-boundary fixture."""
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
HELPER = '/opt/bashos-parity/harness/helpers/ncdu-boundary-reviewed.py'
LIMIT = 256 * 1024


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
    for label, argv, expected in (
        ('du-x', ['/usr/bin/du', '-x', '-B1', 'tree'], one),
        ('du-full', ['/usr/bin/du', '-B1', 'tree'], full)):
        result = command(argv, label)
        observed = records(result.stdout)
        allowed = dict(expected)
        if label == 'du-x' and 'tree/foreign' in observed:
            allowed['tree/foreign'] = 0
        if result.returncode or result.stderr or observed != allowed:
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
    with (HOME / 'ncdu-boundary-candidate.out').open('wb') as out, \
         (HOME / 'ncdu-boundary-candidate.err').open('wb') as err:
        try:
            proc = subprocess.run(['/opt/bashos-parity/candidate', '--noprofile', '--norc', '-c', script],
                                  stdout=out, stderr=err, env=env, timeout=15,
                                  preexec_fn=limits, check=False)
            status = {'returncode': proc.returncode, 'timeout': False}
        except subprocess.TimeoutExpired:
            status = {'returncode': None, 'timeout': True}
    save('candidate.status', (json.dumps(status, sort_keys=True) + '\n').encode())


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
    out = (HOME / 'ncdu-boundary-candidate.out').read_bytes()
    err = (HOME / 'ncdu-boundary-candidate.err').read_bytes()
    if report['mode'] != mode or report['parser_selftest'] != 'ok':
        raise RuntimeError('missing matching setup preconditions')
    if status != {'returncode': 0, 'timeout': False} or err:
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
