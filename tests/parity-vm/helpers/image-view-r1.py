#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only: run a script with the image-owned helpers at /bash-os.

The installer bl-pkg.sh, its library and jq.sh belong to the bashy.box image,
not to this repository.  A qualification run stages the image's own copies
under the reference data; this helper checks them against the pinned digests
and shows them at their real default path, /bash-os, to one command through
an unprivileged mount namespace.  The guest image itself is not changed.

  image-view-r1.py run SHELL SCRIPT [ARG...]
  image-view-r1.py fixture NAME RELPATH TEXT    add package NAME to ./repo
"""
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path

STAGE = Path('/opt/bashos-parity/reference-data/image-helpers/bash-os')
LOCK = Path(__file__).with_name('image-view-r1.lock.json')


def fail(message):
    print('CONTROL-FAILED ' + message, file=sys.stderr)
    raise SystemExit(98)


def guard():
    if os.geteuid() != 2000 or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
        fail('requires the unprivileged case user in a QEMU guest')


def staged():
    """Copy the pinned helpers to a private directory with their image modes."""
    lock = json.loads(LOCK.read_text())
    top = Path(os.environ['HOME']) / 'image-view'
    if top.exists():
        shutil.rmtree(top)
    dest = top / 'bash-os'
    for rel, want in sorted(lock['files'].items()):
        source = STAGE / rel
        if source.is_symlink() or not source.is_file():
            fail('image helper unavailable: ' + rel)
        data = source.read_bytes()
        if len(data) != want['bytes'] or hashlib.sha256(data).hexdigest() != want['sha256']:
            fail('image helper digest: ' + rel)
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        out.chmod(int(want['mode'], 8))
    return dest


def run(shell, script, args):
    if os.path.lexists('/bash-os'):
        fail('/bash-os already exists in the guest')
    dest = staged()
    argv = ['/usr/bin/bwrap']
    for name in sorted(os.listdir('/')):
        path = '/' + name
        if os.path.islink(path):
            argv += ['--symlink', os.readlink(path), path]
        elif name == 'dev':
            argv += ['--dev-bind', path, path]
        else:
            argv += ['--bind', path, path]
    # In the image the helpers' interpreter, /bin/bash, is the shell under
    # test; show it at that path so a helper started by its own name runs
    # under the same shell as there.
    interpreter = os.path.realpath('/bin/bash')
    if os.path.realpath(shell) != interpreter:
        argv += ['--ro-bind', os.path.realpath(shell), interpreter]
    argv += ['--ro-bind', str(dest), '/bash-os', '--chdir', os.getcwd(), '--',
             shell, '--noprofile', '--norc', script] + args
    os.execv(argv[0], argv)


def fixture(name, relpath, text):
    """A real one-file package in the installer's repository format."""
    if relpath.startswith('/') or '..' in relpath.split('/'):
        fail('fixture path')
    data = text.encode()
    member = tarfile.TarInfo(relpath)
    member.size, member.mode, member.mtime = len(data), 0o644, 0
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(member, io.BytesIO(data))
    blob = buffer.getvalue()
    package = 'pool/%s_1_x86_64.tar' % name
    Path('repo/pool').mkdir(parents=True, exist_ok=True)
    Path('repo', package).write_bytes(blob)
    with open('repo/INDEX', 'a') as index:
        index.write('blpkg-v1 name=%s version=1 arch=x86_64 type=payload sha256=%s size=%d package=%s\n'
                    % (name, hashlib.sha256(blob).hexdigest(), len(blob), package))


def main():
    guard()
    args = sys.argv[1:]
    if len(args) >= 3 and args[0] == 'run':
        run(args[1], args[2], args[3:])
    elif len(args) == 4 and args[0] == 'fixture':
        fixture(args[1], args[2], args[3])
    else:
        fail('usage')


if __name__ == '__main__':
    main()
