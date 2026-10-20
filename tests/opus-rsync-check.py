#!/usr/bin/env python3
"""Push-path parity for the rsync builtin against stock rsync.

Every scenario builds the same private fixture tree twice, runs the same
command sequence with stock rsync in one copy and with the builtin in the
other, and after each step compares the exit status, the `skipping ...`
lines and the complete resulting tree: type, mode, size, SHA-256, symlink
target and whether each mtime is a preserved fixture time or a fresh one.
Temporary files left behind by an interrupted copy would show up as extra
tree entries.

The builtin side is one bash-os shell per transport, fed every step of every
scenario over stdin with an empty PATH, so the checks also cover repeated
calls in one shell; the shell's open descriptors are compared before and
after. Two transports are checked:

  local  `rsync ARGS SRC... DEST`: the builtin's native syscall copy
  rsh    `rsync -e ./rshshim ARGS SRC... :DEST`: the shell-command
         transport (stock rsync runs `rsync --server` through the same shim)

Usage: tests/opus-rsync-check.py BASH [--load RSYNC.so] [--stock rsync]
"""
import argparse
import hashlib
import os
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

T0 = 1_000_000_000          # fixture mtimes sit just after this second
NS = 123_456_789            # sub-second part, for the native transport


def build(root, spec):
    """Create spec entries under root. spec: list of tuples, in order:
       ('f', path, data, mode, k) file; ('d', path, mode, k) directory;
       ('l', path, target, k) symlink. k picks the fixture mtime T0+k."""
    dirs = []
    for e in spec:
        p = os.path.join(root, e[1])
        os.makedirs(os.path.dirname(p) or root, exist_ok=True)
        if e[0] == 'f':
            with open(p, 'wb') as fh:
                fh.write(e[2])
            os.chmod(p, e[3])
            os.utime(p, ns=((T0 + e[4]) * 10**9 + NS,) * 2)
        elif e[0] == 'd':
            os.makedirs(p, exist_ok=True)
            dirs.append((p, e[2], e[3]))
        elif e[0] == 'l':
            os.symlink(e[2], p)
            os.utime(p, ns=((T0 + e[3]) * 10**9 + NS,) * 2, follow_symlinks=False)
    for p, mode, k in reversed(dirs):    # contents first, then the directory
        os.utime(p, ns=((T0 + k) * 10**9 + NS,) * 2)
        os.chmod(p, mode)


def snapshot(root, coarse, fresh_after):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root)
            if rel == 'rshshim':
                continue
            st = os.lstat(p)
            t = st.st_mtime_ns
            if T0 * 10**9 <= t < (T0 + 100000) * 10**9:
                when = 'fixture:%d' % (t // 10**9) if coarse else 'fixture:%d' % t
            elif t >= fresh_after:
                when = 'fresh'
            else:
                when = 'other:%d' % t
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ('l', os.readlink(p), when)
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ('d', oct(st.st_mode & 0o7777), when)
            else:
                try:
                    with open(p, 'rb') as fh:
                        digest = hashlib.sha256(fh.read()).hexdigest()[:16]
                except PermissionError:
                    digest = 'unreadable'
                out[rel] = ('f', oct(st.st_mode & 0o7777), st.st_size, digest, when)
    return out


def unlock(root):
    """Make a tree removable again after permission fixtures."""
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            p = os.path.join(dirpath, name)
            if not os.path.islink(p):
                os.chmod(p, 0o755)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if not os.path.islink(p):
                os.chmod(p, 0o644)


BIG = bytes(range(256)) * 8192             # 2 MiB, for the interrupted copy

BASE = [
    ('f', 'f', b'hi\n', 0o644, 1),
    ('f', 'g', b'yo there\n', 0o600, 2),
    ('f', 'x.sh', b'#!/bin/sh\n', 0o755, 3),
    ('d', 'd', 0o755, 10),
    ('f', 'd/a', b'alpha\n', 0o640, 11),
    ('d', 'd/sub', 0o750, 12),
    ('f', 'd/sub/b', b'beta\n' * 1000, 0o444, 13),
    ('l', 'd/sub/up', '../a', 14),
    ('l', 'lnk', 'f', 4),
    ('l', 'dangling', 'nowhere', 5),
]
RO = BASE + [('d', 'rod', 0o555, 20), ('f', 'rod/inner', b'in\n', 0o644, 21)]
EXISTING = BASE + [('d', 'e', 0o755, 30), ('f', 'e/f', b'older\n', 0o666, 31),
                   ('f', 'e/stale', b'stale\n', 0o644, 32), ('d', 'e/sub', 0o700, 33),
                   ('f', 'e/sub/b', b'x', 0o644, 34)]
BIGFIX = BASE + [('f', 'big', BIG, 0o644, 40), ('f', 'old', b'old contents\n', 0o644, 41)]


def rs(*args):
    return ('rsync', list(args))


def sh(fn):
    return ('py', fn)


def chmod(path, mode):
    return sh(lambda root: os.chmod(os.path.join(root, path), mode))


def write(path, data, k):
    def go(root):
        p = os.path.join(root, path)
        with open(p, 'wb') as fh:
            fh.write(data)
        os.utime(p, ns=((T0 + k) * 10**9 + NS,) * 2)
    return sh(go)


def limited(blocks, *args):
    return ('limited', blocks, list(args))


# (name, fixture, steps). A destination argument is written as '@PATH' and
# becomes PATH (local) or :PATH (rsh); '@' alone is the empty destination.
SCENARIOS = [
    # single file, every destination shape
    ('file-to-new-file', BASE, [rs('-a', 'f', '@new'), rs('-a', 'f', '@new')]),
    ('file-to-new-slash', BASE, [rs('-a', 'f', '@new/'), rs('-a', 'f', '@new/')]),
    ('file-to-dir', BASE, [rs('-a', 'f', '@d'), rs('-a', 'g', '@d/')]),
    ('file-over-file', BASE, [rs('-a', 'f', '@g'), rs('-a', 'f', '@g')]),
    ('file-over-file-slash', BASE, [rs('-a', 'f', '@g/')]),
    ('file-under-file', BASE, [rs('-a', 'f', '@g/x')]),
    ('file-missing-parent', BASE, [rs('-a', 'f', '@a/b'), rs('-a', 'f', '@a/b/')]),
    ('file-over-symlink', BASE, [rs('-a', 'g', '@lnk')]),
    ('file-into-dir-symlink', BASE + [('l', 'dl', 'd', 6)], [rs('-a', 'f', '@dl')]),
    ('relative-file-path', BASE, [rs('-a', 'd/a', '@new'), rs('-a', 'd/sub/b', '@d')]),
    # several sources
    ('many-to-new', BASE, [rs('-a', 'f', 'g', '@new'), rs('-a', 'f', 'g', '@new')]),
    ('many-to-file', BASE, [rs('-a', 'f', 'x.sh', '@g')]),
    ('many-mixed', BASE, [rs('-a', 'f', 'd', 'lnk', '@m/'), rs('-a', 'd/', 'g', '@m')]),
    ('missing-source-only', BASE, [rs('-a', 'missing', '@new')]),
    ('missing-plus-file', BASE, [rs('-a', 'missing', 'f', '@new')]),
    ('missing-plus-two', BASE, [rs('-a', 'missing', 'f', 'g', '@new')]),
    # directories
    ('dir-to-new', BASE, [rs('-a', 'd', '@new'), rs('-a', 'd', '@new')]),
    ('dir-contents-to-new', BASE, [rs('-a', 'd/', '@new'), rs('-a', 'd/', '@new/')]),
    ('dir-contents-existing', EXISTING, [rs('-a', 'd/', '@e')]),
    ('dir-over-file', BASE, [rs('-a', 'd', '@g'), rs('-a', 'd/', '@g')]),
    ('dir-missing-parent', BASE, [rs('-a', 'd', '@n/a/b/')]),
    ('dir-dotdot', BASE, [rs('-a', 'd/sub/..', '@dotcopy'), rs('-a', 'd/.', '@dotcopy2')]),
    ('dir-into-itself-sub', BASE, [rs('-a', 'd/sub', '@d/sub2')]),
    ('dir-into-dir-symlink', BASE + [('l', 'dl', 'd', 6)], [rs('-a', 'd/sub/', '@dl'),
                                                            rs('-a', 'g', '@dl/')]),
    ('nonrecursive', BASE, [rs('f', 'd', '@new'), rs('d', '@new2'), rs('-r', 'f', 'lnk', '@n3')]),
    ('recursive-no-links', BASE, [rs('-r', 'd', '@new')]),
    ('replace-file-with-dir', BASE + [('d', 'e', 0o755, 30), ('f', 'e/d', b'f\n', 0o644, 31)],
     [rs('-a', 'd', '@e')]),
    # metadata
    ('times-only', BASE, [rs('-rt', 'd', 'x.sh', '@new')]),
    ('perms-only', BASE, [rs('-rp', 'd', 'x.sh', '@new')]),
    ('readonly-source-dir', RO, [rs('-a', 'rod', '@new'), rs('-a', 'rod', '@new'),
                                 write('rod/inner', b'changed\n', 22), rs('-a', 'rod', '@new')]),
    ('perm-fix-same-content', EXISTING + [('f', 'e/g', b'yo there\n', 0o666, 2)],
     [rs('-a', 'g', '@e/')]),
    ('existing-mode-kept-without-p', EXISTING, [rs('-r', 'f', '@e/')]),
    # dry run
    ('dry-run-shapes', EXISTING, [rs('-an', 'f', '@new'), rs('-an', 'd', '@new'),
                                  rs('-an', 'd/', '@e'), rs('-an', '--delete', 'd/', '@e'),
                                  rs('-an', 'f', 'g', '@n/a/')]),
    # --delete
    ('delete-extras', EXISTING, [rs('-a', '--delete', 'd/', '@e'), rs('-a', '--delete', 'd/', '@e')]),
    # repeated, with source edits between the calls
    ('repeat-edits', BASE, [rs('-a', 'd', '@new'), write('d/a', b'alpha two\n', 50),
                            rs('-a', 'd', '@new'), chmod('d/sub/b', 0o640),
                            rs('-a', 'd', '@new'), rs('-a', 'd', '@new')]),
    # failures
    ('readonly-dest', BASE + [('d', 'ro', 0o555, 7)], [rs('-a', 'f', '@ro/'), rs('-a', 'f', 'd', '@ro/')]),
    ('unreadable-source', BASE, [chmod('g', 0), rs('-a', 'f', 'g', 'x.sh', '@new'), chmod('g', 0o600)]),
    ('empty-dest', BASE, [rs('-a', 'f', '@')]),
    # an interrupted atomic copy: the write fails at RLIMIT_FSIZE
    ('interrupted-over-existing', BIGFIX, [limited(256, '-a', 'big', '@old'),
                                           rs('-a', 'big', '@old')]),
    ('interrupted-new', BIGFIX, [limited(256, '-a', 'big', 'f', '@new/')]),
]

# Exit statuses that knowingly differ: usage errors return 2 like every bash
# builtin, where stock rsync returns 1.
STATUS_MAP = {'empty-dest': {1: 2}}
# ':' is not an empty destination (it names the remote's working directory).
LOCAL_ONLY = {'empty-dest'}


class Shell:
    def __init__(self, binary, load, errlog, preload=None):
        self.errlog = errlog
        env = {'PATH': '', 'LC_ALL': 'C', 'HOME': '/nonexistent'}
        if preload:
            env.update(LD_PRELOAD=preload, UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1',
                       ASAN_OPTIONS='detect_leaks=0:halt_on_error=1:abort_on_error=1')
        self.p = subprocess.Popen([binary, '--norc', '--noprofile'], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=errlog, env=env)
        os.umask(0o022)
        if load and self.run('enable -f %s rsync' % shlex.quote(load))[0] != 0:
            raise RuntimeError('enable -f %s failed' % load)
        self.run('umask 022')

    def run(self, line):
        self.p.stdin.write(('%s; echo "__RC__ $?"\n' % line).encode())
        self.p.stdin.flush()
        out = []
        while True:
            raw = self.p.stdout.readline()
            if not raw:
                raise RuntimeError('bash-os shell exited during: ' + line)
            s = raw.decode(errors='replace').rstrip('\n')
            if s.startswith('__RC__ '):
                return int(s.split()[1]), out
            out.append(s)

    def fds(self):
        rc, out = self.run('fds=(/proc/$$/fd/*); echo "${#fds[@]}"')
        return int(out[-1])

    def close(self):
        self.p.stdin.close()
        return self.p.wait()


def dest(arg, mode):
    if not arg.startswith('@'):
        return arg
    return arg[1:] if mode == 'local' else ':' + arg[1:]


def full_args(args, mode):
    out = [dest(a, mode) for a in args]
    return out if mode == 'local' else ['-e', './rshshim'] + out


def stock_run(stock, args, cwd, blocks=None):
    def pre():
        if blocks is not None:
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (blocks * 1024, resource.RLIM_INFINITY))
    p = subprocess.run([stock] + args, cwd=cwd, capture_output=True, preexec_fn=pre,
                       env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    return p.returncode, p.stdout.decode(errors='replace').splitlines(), p.stderr.decode(errors='replace')


def skipping(lines):
    return [l for l in lines if l.startswith('skipping ')]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('--load', help='rsync loadable object to enable -f first')
    ap.add_argument('--stock', default=shutil.which('rsync') or '/usr/bin/rsync')
    ap.add_argument('--mode', action='append', choices=['local', 'rsh'])
    ap.add_argument('--only', action='append')
    ap.add_argument('--keep', action='store_true')
    ap.add_argument('--preload', help='LD_PRELOAD for the bash-os shell (the ASan runtime for an --load asan object)')
    a = ap.parse_args()
    binary = os.path.realpath(a.binary)
    load = os.path.realpath(a.load) if a.load else None
    sh_path = shutil.which('sh', path='/usr/bin:/bin')
    version = subprocess.run([a.stock, '--version'], capture_output=True, text=True).stdout.splitlines()[0]
    print('stock:', a.stock, '|', version)
    print('bash-os:', binary, '| load:', load)
    top = tempfile.mkdtemp(prefix='opus-rsync-check.')
    failures = checks = 0
    try:
        for mode in a.mode or ['local', 'rsh']:
            errlog = open(os.path.join(top, 'bashos-%s.stderr' % mode), 'wb')
            shell = Shell(binary, load, errlog, a.preload)
            fd_before = shell.fds()
            for name, fixture, steps in SCENARIOS:
                if a.only and name not in a.only:
                    continue
                if mode != 'local' and name in LOCAL_ONLY:
                    continue
                roots = {}
                for side in ('stock', 'bashos'):
                    r = os.path.join(top, mode, name, side, 'w')
                    os.makedirs(r)
                    build(r, fixture)
                    with open(os.path.join(r, 'rshshim'), 'w') as fh:
                        fh.write('#!%s\nexec %s -c "PATH=/usr/bin:/bin; $*"\n' % (sh_path, sh_path))
                    os.chmod(os.path.join(r, 'rshshim'), 0o755)
                    roots[side] = r
                fresh = time.time_ns() - 2 * 10**9
                for i, step in enumerate(steps):
                    label = '%s/%s#%d' % (mode, name, i)
                    if step[0] == 'py':
                        for r in roots.values():
                            step[1](r)
                        continue
                    blocks = step[1] if step[0] == 'limited' else None
                    args = full_args(step[-1], mode)
                    src, sout, serr = stock_run(a.stock, args, roots['stock'], blocks)
                    cmd = 'cd %s && rsync %s' % (shlex.quote(roots['bashos']),
                                                 ' '.join(shlex.quote(x) for x in args))
                    if blocks is not None:
                        cmd = ("trap '' XFSZ; ulimit -S -f %d; %s; r=$?; ulimit -S -f unlimited; "
                               "trap - XFSZ; (exit $r)" % (blocks, cmd))
                    errlog.write(('=== %s: %s\n' % (label, cmd)).encode()); errlog.flush()
                    brc, bout = shell.run(cmd)
                    want = STATUS_MAP.get(name, {}).get(src, src)
                    snap_s = snapshot(roots['stock'], mode == 'rsh', fresh)
                    snap_b = snapshot(roots['bashos'], mode == 'rsh', fresh)
                    problems = []
                    if brc != want:
                        problems.append('status stock=%d (expect %d) bash-os=%d' % (src, want, brc))
                    if skipping(sout) != skipping(bout):
                        problems.append('skip lines stock=%r bash-os=%r' % (skipping(sout), skipping(bout)))
                    if snap_s != snap_b:
                        for k in sorted(set(snap_s) | set(snap_b)):
                            if snap_s.get(k) != snap_b.get(k):
                                problems.append('%s: stock=%r bash-os=%r' % (k, snap_s.get(k), snap_b.get(k)))
                    checks += 1
                    print('%s %s: rsync %s -> %d%s' % ('ok  ' if not problems else 'FAIL', label,
                                                      ' '.join(args), brc,
                                                      '' if not serr else ' (stock stderr: %s)' % serr.strip().splitlines()[-1][:90]))
                    for pr in problems:
                        print('      ', pr)
                    failures += bool(problems)
                for r in roots.values():
                    unlock(os.path.dirname(r))
            fd_after = shell.fds()
            checks += 1
            if fd_after != fd_before:
                failures += 1
                print('FAIL %s: shell descriptors %d before, %d after' % (mode, fd_before, fd_after))
            else:
                print('ok   %s: shell descriptors unchanged (%d) across all calls' % (mode, fd_after))
            rc = shell.close()
            errlog.close()
            with open(errlog.name, 'rb') as fh:
                text = fh.read().decode(errors='replace')
            for marker in ('AddressSanitizer', 'runtime error:', 'LeakSanitizer'):
                checks += 1
                if marker in text:
                    failures += 1
                    print('FAIL %s: sanitizer report (%s) in bash-os stderr:' % (mode, marker))
                    print(text[text.index(marker) - 200:][:3000])
            checks += 1
            if rc != 0:
                failures += 1
                print('FAIL %s: bash-os shell exited %d' % (mode, rc))
    finally:
        if a.keep:
            print('kept', top)
        else:
            unlock(top)
            shutil.rmtree(top, ignore_errors=True)
    print('%d checks, %d failures' % (checks, failures))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
