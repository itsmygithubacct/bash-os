#!/usr/bin/env python3
"""Native ext2 contracts; every mutating operand is an owned private regular image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import struct
import subprocess
import tempfile

U16 = lambda b, o: struct.unpack_from('<H', b, o)[0]
U32 = lambda b, o: struct.unpack_from('<I', b, o)[0]


def private_image(root, image):
    root, image = Path(root).resolve(), Path(image)
    assert image.parent.resolve() == root and not image.is_symlink(), image
    st = image.lstat()
    assert stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1, image
    return str(image)


def sparse_group(g):
    if g in (0, 1):
        return True
    for base in (3, 5, 7):
        n = g
        while n and n % base == 0:
            n //= base
        if n == 1:
            return True
    return False


def layout(image, bs, label=b'', percent=5):
    """Independent decoder: check every bitmap bit, inode and directory record."""
    size = Path(image).stat().st_size
    blocks, first, bpg = size // bs, int(bs == 1024), bs * 8
    groups = (blocks - first + bpg - 1) // bpg
    desc_blocks = (groups * 32 + bs - 1) // bs
    density = 8192 if blocks < 3072 else (4096 if blocks < 524288 else 16384)
    wanted = max(12, blocks * bs // density)
    ipg = max(16, min(bpg, (wanted + groups - 1) // groups))
    ipg = ((ipg * 128 + bs - 1) // bs) * (bs // 128)
    itblocks = ipg * 128 // bs
    lf = min(12, 16384 // bs)
    free_total = 0
    with open(image, 'rb') as f:
        def read(off, n):
            f.seek(off)
            b = f.read(n)
            assert len(b) == n
            return b
        sb = read(1024, 1024)
        assert U16(sb, 56) == 0xef53
        for off, expected in {0: ipg * groups, 4: blocks, 8: blocks * percent // 100,
                              16: ipg * groups - 11, 20: first, 24: {1024: 0, 2048: 1, 4096: 2}[bs],
                              28: {1024: 0, 2048: 1, 4096: 2}[bs], 32: bpg, 36: bpg,
                              40: ipg, 76: 1, 84: 11, 92: 32, 96: 2, 100: 1, 256: 0}.items():
            assert U32(sb, off) == expected, (off, U32(sb, off), expected)
        assert U16(sb, 58) == 1 and U16(sb, 88) == 128 and U16(sb, 90) == 0
        assert sb[120:136] == label[:16].ljust(16, b'\0')
        assert sb[110] >> 4 == 4 and sb[112] >> 6 == 2
        assert sb[208:236] == bytes(28), 'journal/orphan fields must be zero'
        assert sb[252] == 1 and sb[253:256] == bytes(3)
        assert sb[236:252] != bytes(16)
        gd = read((first + 1) * bs, desc_blocks * bs)
        for g in range(groups):
            start = first + g * bpg
            count = min(bpg, blocks - start)
            prefix = (1 + desc_blocks) if sparse_group(g) else 0
            bb, ib, it = start + prefix, start + prefix + 1, start + prefix + 2
            used = prefix + 2 + itblocks + (1 + lf if g == 0 else 0)
            free_total += count - used
            desc = gd[g * 32:(g + 1) * 32]
            assert struct.unpack_from('<IIIHHH', desc) == (bb, ib, it, count - used,
                                                            ipg - (11 if g == 0 else 0), 2 if g == 0 else 0)
            assert desc[18:] == bytes(14)
            for bitmap, allocated, valid in ((read(bb * bs, bs), used, count),
                                             (read(ib * bs, bs), 11 if g == 0 else 0, ipg)):
                expected = bytearray(bs)
                for bit in range(bs * 8):
                    if bit < allocated or bit >= valid:
                        expected[bit // 8] |= 1 << (bit % 8)
                assert bitmap == expected, ('bitmap', g)
            table = read(it * bs, itblocks * bs)
            for ino in range(ipg):
                if g == 0 and ino in (1, 10):
                    continue
                assert table[ino * 128:(ino + 1) * 128] == bytes(128), ('inode', g, ino + 1)
            if sparse_group(g):
                backup = read(1024 if g == 0 else start * bs, 1024)
                expected = bytearray(sb)
                struct.pack_into('<H', expected, 90, g)
                assert backup == expected, ('backup', g)
                assert read((start + 1) * bs, desc_blocks * bs) == gd
        assert U32(sb, 12) == free_total
        table0 = first + 1 + desc_blocks + 2
        root = table0 + itblocks
        for ino, mode, links, count, base in ((2, 0o40755, 3, 1, root), (11, 0o40700, 2, lf, root + 1)):
            inode = read(table0 * bs + (ino - 1) * 128, 128)
            assert U16(inode, 0) == mode and U16(inode, 26) == links
            assert U32(inode, 4) == count * bs and U32(inode, 28) == count * bs // 512
            assert [U32(inode, 40 + i * 4) for i in range(15)] == list(range(base, base + count)) + [0] * (15 - count)
        def entries(block):
            data = read(block * bs, bs)
            out, off = [], 0
            while off < bs:
                inode, rec, length, kind = struct.unpack_from('<IHBB', data, off)
                assert rec >= 8 and rec % 4 == 0 and off + rec <= bs and length <= rec - 8
                out.append((inode, data[off + 8:off + 8 + length], kind, rec))
                off += rec
            return out
        assert entries(root) == [(2, b'.', 2, 12), (2, b'..', 2, 12), (11, b'lost+found', 2, bs - 24)]
        assert entries(root + 1) == [(11, b'.', 2, 12), (2, b'..', 2, bs - 12)]
        for i in range(2, lf + 1):
            assert entries(root + i) == [(0, b'', 0, bs)]
    # Written bytes count the 128-byte inode overwrites as well.
    backups = sum(sparse_group(g) for g in range(groups))
    written = groups * (2 + itblocks) * bs + backups * (1024 + desc_blocks * bs) + 256 + (1 + lf) * bs
    return dict(blocks=blocks, groups=groups, inodes=ipg * groups, free_blocks=free_total,
                written_bytes=written, inode_table_blocks=itblocks * groups)


def references(image, bs, label):
    results = []
    for name, options in [('e2fsck', ['-fn']), ('dumpe2fs', ['-h']), ('debugfs', ['-R', 'ls -l /']),
                          ('blkid', ['-p', '-o', 'export'])]:
        tool = shutil.which(name) or (f'/sbin/{name}' if Path(f'/sbin/{name}').exists() else None)
        if not tool:
            results.append(dict(tool=name, status='unavailable'))
            continue
        p = subprocess.run([tool, *options, str(image)], capture_output=True, timeout=30)
        assert p.returncode == 0, (name, p.returncode, p.stdout, p.stderr)
        if name == 'debugfs':
            assert b'lost+found' in p.stdout
        if name == 'blkid':
            assert b'TYPE=ext2\n' in p.stdout and f'BLOCK_SIZE={bs}\n'.encode() in p.stdout
        results.append(dict(tool=tool, status='pass', stdout=p.stdout.decode(errors='replace'),
                            stderr=p.stderr.decode(errors='replace')))
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', default='out/bash-sol-mkfs')
    ap.add_argument('--module')
    ap.add_argument('--asan-lib')
    ap.add_argument('--report', required=True)
    args = ap.parse_args()
    binary = str(Path(args.binary).resolve())
    prelude = f'enable -f {shlex.quote(str(Path(args.module).resolve()))} mkfs; ' if args.module else ''
    cases = []
    with tempfile.TemporaryDirectory(prefix='sol-mkfs-') as tmp:
        root = Path(tmp)
        env = {**os.environ, 'MKFS_FIXTURE_ROOT': tmp}
        if args.asan_lib:
            env.update(LD_PRELOAD=args.asan_lib, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
        image = root / 'image'
        def reset(size, dirty=False):
            with image.open('wb') as f:
                if dirty:
                    f.write(b'\xa5' * size)
                else:
                    f.truncate(size)
            return private_image(root, image)
        def run(argv, rc=0, script=None, **kwargs):
            if image.exists():
                private_image(root, image)
            p = subprocess.run([binary, '--noprofile', '--norc', '-c', prelude + 'PATH=; ' +
                                (script or 'mkfs "$@"; r=$?; printf "status=%s\\n" "$r"; exit "$r"'),
                                '_', *map(str, argv)], capture_output=True, timeout=30, env=env, **kwargs)
            assert p.returncode == rc, (argv, p.returncode, p.stdout, p.stderr)
            return p
        for bs in (1024, 2048, 4096):
            for size in (60 * bs, 8 * 1024**2, 40 * 1024**2 + 123):
                reset(size, size == 8 * 1024**2)
                label, percent = b'0123456789abcdefEXTRA', 50 if size == 60 * bs else 0
                run([image, '-b', bs, '-m', percent, '-L', label.decode(), '-F'])
                work = layout(image, bs, label, percent)
                if size == 8 * 1024**2:
                    golden = {1024: (8192, 2048, 7918, 279808),
                              2048: (4096, 2048, 3955, 288000),
                              4096: (2048, 1024, 2007, 165120)}
                    assert tuple(work[k] for k in ('blocks', 'inodes', 'free_blocks', 'written_bytes')) == golden[bs]
                assert image.stat().st_size == size
                cases.append(dict(size=size, block_size=bs, work=work, references=references(image, bs, label)))
        reset(300 * 1024**2)
        run([image, '-L', 'fixture'])
        cases.append(dict(size=image.stat().st_size, block_size=1024, work=layout(image, 1024, b'fixture'),
                          references=references(image, 1024, b'fixture')))
        for label in ('', 'a b\'c', 'é' * 9, 'a' + 'é' * 8):
            reset(8 * 1024**2)
            run(['-L', label, '-m', '50', '-m', '5', image])
            layout(image, 1024, label.encode())
        reset(8 * 1024**2)
        before = hashlib.sha256(image.read_bytes()).hexdigest()
        run(['-n', image, '-L', 'dry'])
        assert hashlib.sha256(image.read_bytes()).hexdigest() == before
        bad = [[], ['-L'], ['-b'], ['-m'], ['-x', image], ['--bad', image],
               [image, image], [image, '8192'], [image, '-b', ''], [image, '-b', '1024x'], [image, '-b', '512'],
               [image, '-b', '-1024'], [image, '-m', ''], [image, '-m', '-0'],
               [image, '-m', ' 1'], [image, '-m', '+1'], [image, '-m', '51'],
               [image, '-m', '18446744073709551616'], [image, '-m', '1.5']]
        for argv in bad:
            run(argv, 2)
            assert hashlib.sha256(image.read_bytes()).hexdigest() == before, argv
        for size in (0, 59 * 1024, 8194 * 1024):
            reset(size)
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            for dry in ([], ['-n']):
                run([image, *dry], 1)
                assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
        # A sparse oversized file exercises the 32-bit count gate without
        # allocating or reading terabytes. No mutating format is attempted.
        reset((2**32) * 1024)
        run([image, '-n'], 1)
        assert image.stat().st_blocks == 0
        reset(8 * 1024**2)
        run([root / 'missing'], 1)
        run([root], 1)
        # Opening a FIFO must fail promptly, even with -F; no writer/reader needed.
        fifo = root / 'fifo'; os.mkfifo(fifo)
        run([fifo, '-F'], 1)
        before = hashlib.sha256(image.read_bytes()).hexdigest()
        run([image], 1, script='mkfs "$@" 2>&-; r=$?; [[ $r != 0 ]] || exit 99; '
            'mkfs "$@" -n || exit 98; exit 1')
        assert hashlib.sha256(image.read_bytes()).hexdigest() == before
        # Same shell, including FD counts and an error between successful formats.
        run([image], script='before=(/proc/self/fd/*); for ((i=0;i<12;i++)); do '
            'mkfs "$1" -b 1024 -L again || exit; mkfs "$1" -b bad && exit 90; '
            'mkfs "$1" -b 4096 -m 0 -L final || exit; done; '
            'after=(/proc/self/fd/*); [[ ${#before[@]} == ${#after[@]} ]] || exit 91; echo survived')
        layout(image, 4096, b'final', 0)
        references(image, 4096, b'final')
        # -- permits a dash-prefixed path without treating unknown options as paths.
        dash = root / '-image'; image.rename(dash)
        p = subprocess.run([binary, '-c', prelude + 'PATH=; mkfs -- -image'], cwd=root,
                           capture_output=True, timeout=20, env=env)
        assert p.returncode == 0, p.stderr
        private_image(root, dash); layout(dash, 1024)
    report = dict(status='pass', cases=cases, parsing_cases=len(bad), repeated_formats=24,
                  safety='private regular image guard; no host devices or mounts', binary=binary,
                  binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                  module_sha256=hashlib.sha256(Path(args.module).read_bytes()).hexdigest() if args.module else None,
                  source_sha256=hashlib.sha256((Path(__file__).resolve().parents[1]/'loadables/mkfs.c').read_bytes()).hexdigest())
    Path(args.report).write_text(json.dumps(report, indent=2) + '\n')
    print(f'sol-mkfs: {len(cases)} layouts, {len(bad)} parse failures, repeat/FD/dry-run/shell checks passed')


if __name__ == '__main__':
    main()
