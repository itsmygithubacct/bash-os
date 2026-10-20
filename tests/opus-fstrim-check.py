#!/usr/bin/env python3
"""Production fstrim.c behind the closed filesystem fixture of opus-fstrim-shim.c.

The fixture supplies the mount tables (-a mountinfo, -A fstab, -I lists), a
fake sysfs tree for discard capability, /dev/disk tag links, the kernel
command line and a node table answering stat/access/statfs/realpath/open.
FITRIM requests are recorded and answered from the node plan. Nothing here
compiles; build the modules with tests/opus-fstrim-build.sh first.

    opus-fstrim-check.py --binary out/bash-opus-fstrim --module fstrim.so
        [--preload libasan.so]   (with --module fstrim-sanitize.so)
"""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

# st_dev 1:1 is the root filesystem the fixture reports for every ancestor.
NODES = [
    ('/', 'd', '259:6'),
    ('/dev/sda1', 'b', '0:5', 'rdev=8:1'),
    ('/dev/nvme0n1', 'b', '0:5', 'rdev=259:0'),
    ('/dev/nvme0n1p1', 'b', '0:5', 'rdev=259:1'),
    ('/dev/nvme0n1p2', 'b', '0:5', 'rdev=259:2'),
    ('/dev/md0', 'b', '0:5', 'rdev=9:0'),
    ('/mnt/a', 'd', '7:1', 'len=1610612736'),
    ('/mnt/sda', 'd', '7:2'),
    ('/mnt/ro-part', 'd', '7:3'),
    ('/mnt/dm', 'd', '7:4'),
    ('/mnt/md', 'd', '7:5', 'err=95'),
    ('/mnt/mapper', 'd', '7:6', 'err=5'),
    ('/mnt/unmounted', 'd', '1:1'),
    ('/mnt/file', 'f', '1:1'),
    ('/mnt/filemount', 'f', '7:7'),
    ('/mnt/autofs', 'd', '7:8', 'magic=0x0187'),
    ('/mnt/eacces', 'd', '7:9', 'w=13'),
    ('/mnt/erofs', 'd', '7:10', 'w=30'),
    ('/mnt/w-eio', 'd', '7:19', 'w=5', 'len=0'),
    ('/mnt/statfs-fail', 'd', '7:11', 'statfs=5'),
    ('/mnt/sub', 'd', '7:12'),
    ('/mnt/sub/inner', 'd', '7:12'),
    ('/mnt/sub/over', 'd', '7:13', 'len=1048575'),
    ('/mnt/sp ace', 'd', '7:14', 'len=4096'),
    ('/mnt/tab\tx', 'd', '7:15', 'len=1023'),
    ('/mnt/back\\slash', 'd', '7:16', 'len=1153'),
    ('/mnt/rp', 'd', '7:17', 'realpath=40'),
    ('/mnt/op', 'd', '7:18', 'open=13'),
    ('/mnt/eperm', 'd', '7:20', 'err=1'),
    ('/mnt/ebadf', 'd', '7:21', 'err=9'),
    ('/mnt/unplanned', 'd', '7:22'),
]

def mi(target, typ, src, vfs='rw,relatime', fso='rw'):
    esc = target.replace('\\', '\\134').replace(' ', '\\040').replace('\t', '\\011')
    src = src.replace(' ', '\\040')
    return f'36 1 7:1 / {esc} {vfs} shared:1 - {typ} {src} {fso}\n'


MOUNTINFO = ''.join([
    mi('/', 'ext4', '/dev/nvme0n1p6'),
    mi('/proc', 'proc', 'proc'),
    mi('/tmp', 'tmpfs', 'tmpfs'),
    mi('/mnt/a', 'ext4', '/dev/fx-old'),          # over-mounted below: the later entry wins
    mi('/mnt/sda', 'ext4', '/dev/sda1'),
    mi('/mnt/ro-part', 'ext4', '/dev/nvme0n1p2'),
    mi('/mnt/dm', 'xfs', '/dev/dm-7'),
    mi('/mnt/md', 'xfs', '/dev/md0'),
    mi('/mnt/mapper', 'ext4', '/dev/mapper/vg-lv'),
    mi('/mnt/unmounted', 'ext4', '/dev/fx1'),
    mi('/mnt/file', 'ext4', '/dev/fx2'),
    mi('/mnt/filemount', 'ext4', '/dev/fx3'),
    mi('/mnt/autofs', 'ext4', '/dev/fx4'),
    mi('/mnt/eacces', 'ext4', '/dev/fx5'),
    mi('/mnt/erofs', 'ext4', '/dev/fx6'),
    mi('/mnt/w-eio', 'ext4', '/dev/fx7'),
    mi('/mnt/statfs-fail', 'ext4', '/dev/fx8'),
    mi('/mnt/sub', 'ext4', '/dev/fx9', vfs='ro'),
    mi('/mnt/sub/inner', 'ext4', '/dev/fx10'),
    mi('/mnt/sub/over', 'ext4', '/dev/fx11'),
    mi('/mnt/sp ace', 'ext4', '/dev/fx12'),
    mi('/mnt/tab\tx', 'ext4', '/dev/fx13'),
    mi('/mnt/back\\slash', 'ext4', '/dev/fx14'),
    mi('/mnt/a', 'ext4', '/dev/nvme0n1p1'),
    mi('/mnt/missing', 'ext4', '/dev/fx15'),
    mi('/mnt/eperm', 'ext4', '/dev/fx16', fso='rw,X-fstrim.notrim'),
])

FSTAB = '''# /etc/fstab fixture
LABEL=data /mnt/a ext4 defaults 0 2
UUID=missing /mnt/sda ext4 defaults 0 2
PARTUUID=mdpart /mnt/md xfs defaults 0 2
/dev/fx12 /mnt/sp\\040ace ext4 defaults 0 2
/dev/fx3 /mnt/unmounted ext4 defaults 0 2
/dev/sdz9 none swap sw 0 0
tmpfs /tmp tmpfs defaults 0 0
'''


def sysfs(root):
    s = root / 'sys'
    def w(rel, text):
        p = s / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    w('devices/sda/queue/discard_granularity', '0\n'); w('devices/sda/ro', '0\n')
    w('devices/sda/sda1/partition', '1\n'); w('devices/sda/sda1/ro', '0\n')
    w('devices/nvme0n1/queue/discard_granularity', '512\n'); w('devices/nvme0n1/ro', '0\n')
    w('devices/nvme0n1/uevent', 'MAJOR=259\nMINOR=0\nDEVNAME=nvme0n1\n')
    for n, ro in ((1, 0), (2, 1), (6, 0)):
        w(f'devices/nvme0n1/nvme0n1p{n}/partition', f'{n}\n')
        w(f'devices/nvme0n1/nvme0n1p{n}/ro', f'{ro}\n')
        w(f'devices/nvme0n1/nvme0n1p{n}/uevent', f'MAJOR=259\nMINOR={n}\nDEVNAME=nvme0n1p{n}\n')
    w('devices/dm-7/ro', '0\n')                      # no queue attribute: cannot discard
    w('devices/md0/queue/discard_granularity', '4096\n'); w('devices/md0/ro', '0\n')
    links = {'8:0': 'sda', '8:1': 'sda/sda1', '259:0': 'nvme0n1', '259:1': 'nvme0n1/nvme0n1p1',
             '259:2': 'nvme0n1/nvme0n1p2', '259:6': 'nvme0n1/nvme0n1p6', '253:7': 'dm-7',
             '9:0': 'md0'}
    (s / 'dev/block').mkdir(parents=True)
    (s / 'class/block').mkdir(parents=True)
    for dev, target in links.items():
        os.symlink(f'../../devices/{target}', s / 'dev/block' / dev)
    for name, dev in (('dm-7', '253:7'), ('md0', '9:0'), ('nvme0n1p6', '259:6')):
        w(f'class/block/{name}/dev', dev + '\n')
    d = root / 'disk'
    for kind, tag, dev in (('by-label', 'data', '/dev/nvme0n1p1'), ('by-uuid', 'rootuuid', '/dev/nvme0n1'),
                           ('by-partuuid', 'mdpart', '/dev/md0')):
        (d / kind).mkdir(parents=True, exist_ok=True)
        os.symlink(dev, d / kind / tag)


def setup(module, root, cmdline):
    (root / 'cmdline').write_text(cmdline)
    lines = [f'enable -f {shlex.quote(str(module))} fstrim fstrim_fixture || exit 90',
             'PATH=', f'fstrim_fixture reset {shlex.quote(str(root))} || exit 91']
    for n in NODES:
        lines.append('fstrim_fixture node ' + shlex.join(n) + ' || exit 92')
    return '\n'.join(lines) + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--module', type=Path, required=True)
    ap.add_argument('--preload', type=Path)
    args = ap.parse_args()
    binary, module = args.binary.resolve(), args.module.resolve()
    env = dict(os.environ, LC_ALL='C')
    env.pop('BASH_ENV', None)
    if args.preload:
        env.update(LD_PRELOAD=str(args.preload), ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    tmp = Path(tempfile.mkdtemp(prefix='opus-fstrim-check.'))
    root = tmp / 'fx'
    root.mkdir()
    sysfs(root)
    (root / 'mountinfo').write_text(MOUNTINFO)
    (root / 'fstab').write_text(FSTAB)
    L = root / 'lists'
    L.mkdir()
    passed = failed = 0

    def check(name, body, out, status=0, err='', trace=None, cmdline='quiet root=UUID=rootuuid\n'):
        nonlocal passed, failed
        script = setup(module, root, cmdline) + body
        if trace is not None:
            script += '\nrc=$?\nprintf "<trace>\\n"; fstrim_fixture trace || echo "TRACE-STATUS $?"\nexit $rc\n'
        p = subprocess.run([str(binary), '--noprofile', '--norc', '-c', script], env=env,
                           capture_output=True, text=True)
        want = out + ('<trace>\n' + trace if trace is not None else '')
        problems = []
        if p.returncode != status:
            problems.append(f'status {p.returncode} != {status}')
        if p.stdout != want:
            problems.append(f'stdout\n--- got\n{p.stdout}--- want\n{want}---')
        if p.stderr != err:
            problems.append(f'stderr\n--- got\n{p.stderr}--- want\n{err}---')
        if problems:
            failed += 1
            print(f'FAIL {name}: ' + '\n'.join(problems))
        else:
            passed += 1
            print(f'PASS {name}')

    def oc(*paths):
        return ''.join(f'open {p}\nclose {p}\n' for p in paths)

    def trim(p, start=0, length=18446744073709551615, minlen=0):
        return f'open {p}\nFITRIM {p} {start} {length} {minlen}\nclose {p}\n'

    # --- -a over the injected mount table -------------------------------
    kept_a = ['/mnt/a', '/mnt/back\\slash', '/mnt/tab\tx', '/mnt/sp ace', '/mnt/sub/over',
              '/mnt/w-eio', '/mnt/mapper', '/mnt/md', '/']
    srcs = {'/mnt/a': '/dev/nvme0n1p1', '/mnt/back\\slash': '/dev/fx14', '/mnt/tab\tx': '/dev/fx13',
            '/mnt/sp ace': '/dev/fx12', '/mnt/sub/over': '/dev/fx11', '/mnt/w-eio': '/dev/fx7',
            '/mnt/mapper': '/dev/mapper/vg-lv', '/mnt/md': '/dev/md0', '/': '/dev/nvme0n1p6'}
    check('-a dry run keeps only mounted, writable, discard-capable local filesystems',
          'fstrim -n -a',
          ''.join(f'{t}: 0 B (dry run) trimmed on {srcs[t]}\n' for t in kept_a),
          trace=oc(*kept_a))
    check('-a -t xfs selects by type', 'fstrim -n -a -t xfs', '/mnt/md: 0 B (dry run) trimmed on /dev/md0\n',
          trace=oc('/mnt/md'))
    check('-a -t noext4,xfs negates the whole list', 'fstrim -n -a -t noext4,xfs', '', trace='')
    check('-a FITRIM: verbose sizes, unsupported warning and partial failure exit 64',
          'fstrim -v -a',
          '/mnt/a: 1.5 GiB (1610612736 bytes) trimmed on /dev/nvme0n1p1\n'
          '/mnt/back\\slash: 1.1 KiB (1153 bytes) trimmed on /dev/fx14\n'
          '/mnt/tab\tx: 1023 B (1023 bytes) trimmed on /dev/fx13\n'
          '/mnt/sp ace: 4 KiB (4096 bytes) trimmed on /dev/fx12\n'
          '/mnt/sub/over: 1024 KiB (1048575 bytes) trimmed on /dev/fx11\n'
          '/mnt/w-eio: 0 B (0 bytes) trimmed on /dev/fx7\n',
          status=64,
          err='fstrim: /mnt/mapper: FITRIM ioctl failed: Input/output error\n'
              'fstrim: /mnt/md: the discard operation is not supported\n'
              'fstrim: /: the discard operation is not supported\n',
          trace=''.join(trim(t) for t in kept_a))
    check('-a --quiet-unsupported with -o/-l/-m passed to every request',
          'fstrim -a --quiet-unsupported -o 1M -l 2G -m 64k',
          '', status=64, err='fstrim: /mnt/mapper: FITRIM ioctl failed: Input/output error\n',
          trace=''.join(trim(t, 1048576, 2147483648, 65536) for t in kept_a))

    # --- -A: fstab with tag resolution and the guessed root ---------------
    check('-A resolves tags, skips unresolvable and unmounted entries, adds the root device',
          'fstrim -n -A',
          '/: 0 B (dry run) trimmed on /dev/nvme0n1\n'
          '/mnt/sp ace: 0 B (dry run) trimmed on /dev/fx12\n'
          '/mnt/md: 0 B (dry run) trimmed on /dev/md0\n'
          '/mnt/a: 0 B (dry run) trimmed on /dev/nvme0n1p1\n',
          trace=oc('/', '/mnt/sp ace', '/mnt/md', '/mnt/a'))
    check('-A without root= guesses the device holding /', 'fstrim -n -A',
          '/: 0 B (dry run) trimmed on /dev/nvme0n1p6\n'
          '/mnt/sp ace: 0 B (dry run) trimmed on /dev/fx12\n'
          '/mnt/md: 0 B (dry run) trimmed on /dev/md0\n'
          '/mnt/a: 0 B (dry run) trimmed on /dev/nvme0n1p1\n',
          cmdline='quiet splash\n', trace=oc('/', '/mnt/sp ace', '/mnt/md', '/mnt/a'))
    check('-I does not resolve tags or add the root', f'fstrim -n -I {root}/fstab',
          '/mnt/sp ace: 0 B (dry run) trimmed on /dev/fx12\n', trace=oc('/mnt/sp ace'))
    saved = (root / 'fstab').read_text()
    (root / 'fstab').write_text('/dev/nvme0n1p1 / ext4 defaults\n/dev/fx12 /mnt/sp\\040ace ext4\n')
    check('-A keeps an explicit root entry instead of guessing', 'fstrim -n -A',
          '/mnt/sp ace: 0 B (dry run) trimmed on /dev/fx12\n/: 0 B (dry run) trimmed on /dev/nvme0n1p1\n',
          trace=oc('/mnt/sp ace', '/'))
    (root / 'fstab').write_text(saved)

    # --- -I: ordinary files, unmounted directories, nested paths ---------------
    (L / 'notmounted').write_text(
        '/dev/fx1 /mnt/file ext4 defaults\n/dev/fx2 /mnt/unmounted ext4 defaults\n'
        '/dev/fx3 /mnt/sub/inner ext4 defaults\n/dev/fx4 /mnt/filemount ext4 defaults\n'
        '/dev/fx5 /mnt/nonexistent ext4 defaults\n/dev/fx6 /etc/passwd ext4 defaults\n'
        '/dev/fx7 mnt/a ext4 defaults\n')
    check('-I never treats a stat-able file or unmounted directory as a mountpoint',
          f'fstrim -n -I {L}/notmounted', '', trace='')
    check('-I non-dry on the same list issues no FITRIM', f'fstrim -v -I {L}/notmounted', '', trace='')
    (L / 'dups').write_text(
        '/dev/fx1 /mnt/a ext4\n/dev/fx2 /mnt/a/ ext4\n/dev/fx3 /mnt//sub/over ext4\n'
        '/dev/fx3 /mnt/sp\\040ace ext4\n/dev/fx9 /mnt/tab\\011x ext4\n/dev/fx9 /mnt/back\\134slash ext4\n'
        '/dev/fx4 /mnt/w-eio tmpfs\n/dev/fx4 /mnt/mapper ext4\n')
    check('-I duplicates: last target wins, first source wins, escapes decoded',
          f'fstrim -n -I {L}/dups',
          '/mnt/mapper: 0 B (dry run) trimmed on /dev/fx4\n'
          '/mnt/tab\tx: 0 B (dry run) trimmed on /dev/fx9\n'
          '/mnt//sub/over: 0 B (dry run) trimmed on /dev/fx3\n'
          '/mnt/a/: 0 B (dry run) trimmed on /dev/fx2\n',
          trace=oc('/mnt/mapper', '/mnt/tab\tx', '/mnt/sub/over', '/mnt/a'))
    (L / 'fail').write_text('/dev/fx1 /mnt/rp ext4\n/dev/fx2 /mnt/op ext4\n/dev/fx3 /mnt/eperm ext4\n'
                            '/dev/fx4 /mnt/ebadf ext4\n/dev/fx5 /mnt/unplanned ext4\n')
    check('-I failures: realpath, open, EPERM fail; EBADF and ENOTTY are unsupported',
          f'fstrim -I {L}/fail', '', status=64,
          err='fstrim: /mnt/unplanned: the discard operation is not supported\n'
              'fstrim: /mnt/ebadf: the discard operation is not supported\n'
              'fstrim: /mnt/eperm: FITRIM ioctl failed: Operation not permitted\n'
              'fstrim: cannot open /mnt/op: Permission denied\n'
              'fstrim: cannot get realpath: /mnt/rp: Too many levels of symbolic links\n',
          trace=trim('/mnt/unplanned') + trim('/mnt/ebadf') + trim('/mnt/eperm') + 'open /mnt/op\n')
    (L / 'allfail').write_text('/dev/fx1 /mnt/rp ext4\n/dev/fx3 /mnt/eperm ext4\n')
    check('-I where every trim fails exits 32', f'fstrim -I {L}/allfail', '', status=32,
          err='fstrim: /mnt/eperm: FITRIM ioctl failed: Operation not permitted\n'
              'fstrim: cannot get realpath: /mnt/rp: Too many levels of symbolic links\n',
          trace=trim('/mnt/eperm'))
    (L / 'empty').write_text('# nothing\n\n')
    check('-I list of only missing, empty and non-regular files',
          f'fstrim -n -I {L}/missing:{L}/empty:{L}; echo "rc=$?"; fstrim -n -I {L}/missing:{L}; echo "rc=$?";'
          f' fstrim -n -I {L}/empty:{L}/missing:{L}/dups',
          'rc=255\nrc=32\n/mnt/mapper: 0 B (dry run) trimmed on /dev/fx4\n'
          '/mnt/tab\tx: 0 B (dry run) trimmed on /dev/fx9\n'
          '/mnt//sub/over: 0 B (dry run) trimmed on /dev/fx3\n'
          '/mnt/a/: 0 B (dry run) trimmed on /dev/fx2\n',
          trace=oc('/mnt/mapper', '/mnt/tab\tx', '/mnt/sub/over', '/mnt/a'))
    (L / 'unreadable').write_text('/dev/fx1 /mnt/a ext4\n')
    os.chmod(L / 'unreadable', 0)
    if os.geteuid() != 0:
        check('-I unreadable list file', f'fstrim -n -I {L}/unreadable', '', status=32,
              err=f'fstrim: failed to parse {L}/unreadable: Permission denied\n', trace='')

    # --- single mountpoint -------------------------------------------------
    check('single target: ranges, verbose size', 'fstrim -v -o 1.5K -l 0x10 -m 1KB /mnt/a',
          '/mnt/a: 1.5 GiB (1610612736 bytes) trimmed\n', trace=trim('/mnt/a', 1536, 16, 1000))
    check('single target: a plain directory is accepted as util-linux does',
          'fstrim -n /mnt/unmounted', '/mnt/unmounted: 0 B (dry run) trimmed\n', trace=oc('/mnt/unmounted'))
    check('single target: not a directory', 'fstrim -n /mnt/file', '', status=1,
          err='fstrim: /mnt/file: not a directory\n', trace='')
    check('single target: missing', 'fstrim -n /mnt/missing', '', status=1,
          err='fstrim: stat of /mnt/missing failed: No such file or directory\n', trace='')
    check('single target: unsupported', 'fstrim /mnt/md; echo "rc=$?"; fstrim --quiet-unsupported /mnt/md',
          'rc=1\n', err='fstrim: /mnt/md: the discard operation is not supported\n',
          trace=trim('/mnt/md') * 2)
    check('single target: FITRIM failure', 'fstrim -v /mnt/eperm', '', status=1,
          err='fstrim: /mnt/eperm: FITRIM ioctl failed: Operation not permitted\n', trace=trim('/mnt/eperm'))
    check('single target: open failure', 'fstrim /mnt/op', '', status=1,
          err='fstrim: cannot open /mnt/op: Permission denied\n', trace='open /mnt/op\n')
    check('single target: -l 0 is passed through, default length is the maximum',
          'fstrim -l 0 /mnt/a; fstrim /mnt/a', '', trace=trim('/mnt/a', 0, 0) + trim('/mnt/a'))

    # --- usage, output failure, repeated calls ---------------------------------
    check('usage errors', 'fstrim; echo $?; fstrim -n /a /b; echo $?; fstrim -a -I x; echo $?;'
          ' fstrim -A /mnt/a; echo $?; fstrim -o 1Q /mnt/a; echo $?; fstrim -m; echo $?;'
          ' fstrim --length=-1 /mnt/a; echo $?; fstrim --lis=x --lis=y -n; echo $?; fstrim --l x; echo $?',
          '1\n1\n1\n1\n1\n1\n1\n32\n1\n',
          err='fstrim: no mountpoint specified\n'
              'fstrim: unexpected number of arguments\nTry \'fstrim --help\' for more information.\n'
              'fstrim: mutually exclusive arguments: --fstab --listed-in --all\n'
              'fstrim: unexpected number of arguments\nTry \'fstrim --help\' for more information.\n'
              'fstrim: failed to parse offset: \'1Q\': Invalid argument\n'
              'fstrim: option requires an argument -- \'m\'\nTry \'fstrim --help\' for more information.\n'
              'fstrim: failed to parse length: \'-1\': Invalid argument\n'
              'fstrim: option \'--l\' is ambiguous; possibilities: \'--listed-in\' \'--length\'\n'
              'Try \'fstrim --help\' for more information.\n',
          trace='')
    check('write error on stdout, then a clean repeat',
          'fstrim -n /mnt/a > /dev/full; echo "rc=$?"; fstrim -n -a -t xfs > /dev/full; echo "rc=$?";'
          ' fstrim -h > /dev/full; echo "rc=$?"; fstrim -n /mnt/a',
          'rc=1\nrc=1\nrc=1\n/mnt/a: 0 B (dry run) trimmed\n',
          err='fstrim: write error: No space left on device\n' * 3,
          trace=oc('/mnt/a', '/mnt/md', '/mnt/a'))
    loop = 'for i in 1 2 3 4 5 6 7 8 9 10; do fstrim -n -a -t xfs || exit 9; fstrim -v /mnt/a || exit 9; done'
    check('repeated calls in one shell with empty PATH', loop,
          ('/mnt/md: 0 B (dry run) trimmed on /dev/md0\n/mnt/a: 1.5 GiB (1610612736 bytes) trimmed\n') * 10,
          trace=(oc('/mnt/md') + trim('/mnt/a')) * 10)

    print(f'{passed} passed, {failed} failed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
