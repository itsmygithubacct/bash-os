#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual sudo editor/copyback observations, only in an attested disposable guest."""
import argparse
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time
sys.dont_write_bytecode = True


def require(value, reason):
    if not value: raise RuntimeError(reason)


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protected(path, pin):
    value = Path(path).lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o022 and sha(path) == pin,
            'unprotected/mismatched fixture input')


def states(paths):
    result = []
    for path in paths:
        st = path.lstat()
        result.append({'path': str(path), 'dev': st.st_dev, 'ino': st.st_ino, 'uid': st.st_uid, 'gid': st.st_gid,
                       'mode': stat.S_IMODE(st.st_mode), 'links': st.st_nlink,
                       'data_hex': path.read_bytes().hex() if stat.S_ISREG(st.st_mode) else None,
                       'symlink': os.readlink(path) if stat.S_ISLNK(st.st_mode) else None,
                       'xattrs': {name: os.getxattr(path, name, follow_symlinks=False).hex()
                                  for name in os.listxattr(path, follow_symlinks=False)}})
    return result


def identity(pid):
    fields = dict(line.split(':', 1) for line in Path('/proc', str(pid), 'status').read_text().splitlines() if ':' in line)
    return {key: [int(x) for x in fields[key].split()] for key in ('Pid', 'PPid', 'Uid', 'Gid', 'Groups')}


def descriptors(pid):
    return {path.name: os.readlink(path) for path in Path('/proc', str(pid), 'fd').iterdir()}


def private_editor_paths(base, row, count):
    paths = [Path(os.fsdecode(bytes.fromhex(value))) for value in row['paths_hex']]
    base.check(len(paths) == count and len(set(p.parent for p in paths)) == 1 and
               all(re.fullmatch(r'/tmp/bashos-edit-v2\.[A-Za-z0-9]{6}/copy-[0-9]{2}', str(p)) for p in paths) and
               [p.name for p in paths] == ['copy-%02d' % i for i in range(count)], 'invalid private editor vector')
    return paths


def reset_case(rt, count=16, password=False, fail_index=-1, allowed=16):
    base = rt.base
    if rt.loaded:
        result = rt.command(['/usr/sbin/rmmod', base.MODULE]); require(result.returncode == 0, 'module unload failed')
        rt.loaded = False
    for i, path in enumerate(rt.targets):
        if os.path.lexists(path): path.unlink()
        rt.install(path, ('original-%02d\n' % i).encode(), 0o600)
    # Policy is changed only while the authority is unloaded, then explicitly
    # pinned in a new instance. There is no implied on-disk policy hot reload.
    lines = ['Defaults timestamp_timeout=0', 'Defaults:pcv2caller timestamp_timeout=0']
    # An untagged rule requires a password in the shared project parser.
    for path in rt.targets[:allowed]:
        lines.append('pcv2caller ALL = (root) %ssudoedit %s' % ('' if password else 'NOPASSWD: ', path))
    (rt.root / 'policy').write_text('\n'.join(lines) + '\n')
    argv = ['/usr/sbin/insmod', rt.artifacts / (base.MODULE + '.ko'), 'test_only=1', 'test_edit_fail_index=' + str(fail_index)]
    for name in ('accounts', 'groups', 'profiles', 'policy', 'verifier', 'executor'):
        argv += [name + '_path=' + str(rt.root / name), name + '_sha256=' + sha(rt.root / name)]
    result = rt.command(argv); rt.loaded = result.returncode == 0 and Path('/sys/module', base.MODULE).exists()
    require(rt.loaded, 'safeedit module load failed')
    require(Path('/sys/module', base.MODULE, 'parameters/test_edit_fail_index').read_text().strip() == str(fail_index),
            'selected denial-only fault configuration differs')
    for _ in range(100):
        if os.path.lexists(base.DEVICE): break
        time.sleep(.01)
    require(os.path.lexists(base.DEVICE), 'qualification device missing')
    return rt.targets[:count]


def fill_audit(rt):
    base = rt.base
    fd = os.open(base.DEVICE, os.O_RDWR | os.O_CLOEXEC)
    rows = 0
    try:
        # Root is denied by the actual pinned policy. Each response contributes
        # a real deny record; no event insertion/mock interface is used.
        for _ in range(128):
            try:
                prepared = base.prepare(fd, rt.nopass, user='root', uid=0)
                base.check(prepared.decision == 1, 'root unexpectedly authorized while filling audit')
                rows += 1
            except OSError as e:
                require(e.errno == errno.ENOSPC, 'unexpected audit fill failure')
                break
        else: raise RuntimeError('audit capacity bound not reached')
        info = bytearray(40); fcntl.ioctl(fd, base.AUDIT_INFO, info, True)
        epoch, next_seq, oldest, denials, available, reserved = struct.unpack('<QQQQII', info)
        require(rows and available > 0 and denials > 0, 'real audit backpressure not observed')
        return {'deny_records_added': rows, 'epoch': epoch, 'next_sequence': next_seq, 'oldest_sequence': oldest,
                'backpressure_denials': denials, 'records': available, 'reserved': reserved}
    finally: os.close(fd)


def prepare_edit(base, fd, paths, sealed_digest=None):
    argv_blob = b''.join(os.fsencode(path) + b'\0' for path in paths)
    argv = base.C.create_string_buffer(argv_blob)
    p = base.Prepare(); p.size = base.C.sizeof(p); p.version = 2
    r = p.request; r.size = base.C.sizeof(r); r.mode = 6; r.non_interactive = 1
    r.caller_uid = r.caller_gid = base.CALLER; r.target_uid = r.target_gid = 0
    r.caller_user = b'pcv2caller'; r.target_user = b'root'; r.cwd = os.fsencode(os.getcwd())
    r.argc = len(paths); r.argv_bytes = len(argv_blob); r.argv_user_ptr = base.C.addressof(argv) if argv_blob else 0
    # Existing wire domain is exactly 16 bytes, without the literal's final '1'.
    frame = b'bashos-privcmd-v' + struct.pack('<11I', r.mode, r.flags, r.non_interactive,
        r.caller_uid, r.caller_gid, r.target_uid, r.target_gid, r.argc, r.envc, r.argv_bytes, r.env_bytes)
    for value in (r.caller_user, r.target_user, r.cwd): frame += struct.pack('<I', len(value)) + value
    r.request_digest[:] = hashlib.sha256(frame + argv_blob).digest()
    result = base.ioctl_struct(fd, base.PREPARE, p)
    base.check(result.decision == 3 and bytes(result.request.request_digest) ==
               (sealed_digest if sealed_digest is not None else bytes(r.request_digest)),
               'actual edit preparation did not return expected grant/digest')
    return result


def edit_wire(base, fd, prepared, copies, commit=False, count=None, corrupt=False, seal=False):
    value = bytearray(184)
    digest = bytearray(prepared.request.request_digest)
    if corrupt: digest[0] ^= 1
    struct.pack_into('<IIIIQ32s', value, 0, 184, 2, len(copies) if count is None else count, 0,
                     prepared.request_id, bytes(digest))
    for i, copy in enumerate(copies): struct.pack_into('<I', value, 56 + 4 * i, copy)
    fcntl.ioctl(fd, base.ioc(3, 9 if seal else 8 if commit else 7, 184), value, True)
    result, committed, failed, error, cleanup, reserved = struct.unpack_from('<6I', value, 120)
    base.check(not reserved and struct.unpack_from('<Q', value, 176)[0] and not cleanup,
               'edit response framing/audit/cleanup differs')
    return result, committed, failed, error, bytes(value[144:176])


def raw_edit_case(rt, name):
    base = rt.base; reset_case(rt); before = states(rt.targets)
    def body():
        fd = os.open(base.DEVICE, os.O_RDWR | os.O_CLOEXEC); opened = []
        try:
            with tempfile.TemporaryDirectory(prefix='safeedit-api-', dir=rt.work) as temporary:
                path = Path(temporary) / 'copy'; copy = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                opened.append(copy); p = prepare_edit(base, fd, rt.targets[:1])
                if name in ('zero-count', 'seventeen-count', 'bad-request-digest'):
                    base.rejects(lambda: edit_wire(base, fd, p, [copy],
                        count=0 if name == 'zero-count' else 17 if name == 'seventeen-count' else None,
                        corrupt=name == 'bad-request-digest'), {errno.EKEYREJECTED})
                    base.rejects(lambda: edit_wire(base, fd, p, [copy]), {errno.EKEYREJECTED})
                    return
                if name == 'commit-before-open':
                    base.rejects(lambda: edit_wire(base, fd, p, [copy], True), {errno.EKEYREJECTED})
                    return
                if name == 'foreign-task':
                    child = os.fork()
                    if child == 0:
                        try: base.rejects(lambda: edit_wire(base, fd, p, [copy]), {errno.EPERM}); os._exit(0)
                        except BaseException: os._exit(97)
                    waited, status = os.waitpid(child, 0)
                    base.check(waited == child and status == 0, 'foreign task operated parent context')
                row = edit_wire(base, fd, p, [copy])
                base.check(row[0] == 8 and row[1] == row[3] == 0 and os.pread(copy, 64, 0) == b'original-00\n',
                           'actual kernel safe-open did not produce expected private copy')
                if name == 'foreign-task': return
                if name == 'open-grant-reuse':
                    base.rejects(lambda: edit_wire(base, fd, p, [copy], True), {errno.EKEYREJECTED})
                    return
                os.ftruncate(copy, 0); base.check(os.write(copy, b'raw-edited\n') == 11, 'private edit write incomplete')
                os.close(copy); opened.remove(copy)
                copy = os.open(path, os.O_RDWR if name == 'readwrite-upload' else os.O_RDONLY); opened.append(copy)
                if name == 'writable-alias': opened.append(os.open(path, os.O_WRONLY))
                if name == 'unsealed-reprepare':
                    base.rejects(lambda: prepare_edit(base, fd, rt.targets[:1]), {errno.EKEYREJECTED})
                    return
                if name == 'cancelled-session':
                    fcntl.ioctl(fd, base.CANCEL)
                    base.rejects(lambda: edit_wire(base, fd, p, [copy], seal=True), {errno.EKEYREJECTED})
                    return
                original_digest = bytes(p.request.request_digest)
                row = edit_wire(base, fd, p, [copy], seal=True)
                if name in ('writable-alias', 'readwrite-upload'):
                    base.check(row[0] == 10 and row[1] == 0 and row[3] ==
                               (errno.ETXTBSY if name == 'writable-alias' else errno.EBADF), 'seal accepted writable source')
                    return
                expected = hashlib.sha256(b'bashos-safeedit-v2' + original_digest + struct.pack('<I', 1) +
                    hashlib.sha256(b'original-00\n').digest() + hashlib.sha256(b'raw-edited\n').digest() + struct.pack('<Q', 11)).digest()
                base.check(row[0] == 11 and row[1] == row[3] == 0 and row[4] == expected,
                           'sealed transaction does not match independent bytes/digest')
                if name == 'post-seal-writer-denied':
                    base.rejects(lambda: os.open(path, os.O_WRONLY), {errno.ETXTBSY})
                    return
                if name == 'seal-replay':
                    row = edit_wire(base, fd, p, [copy], seal=True)
                    base.check(row[0] == 10 and row[3] == errno.EINVAL, 'seal replay accepted')
                    writer = os.open(path, os.O_WRONLY); os.close(writer)
                    return
                if name == 'last-close-releases-seal':
                    os.close(fd); fd = -1
                    writer = os.open(path, os.O_WRONLY); os.close(writer)
                    return
                if name == 'different-target':
                    base.rejects(lambda: prepare_edit(base, fd, rt.targets[1:2]), {errno.EKEYREJECTED})
                    writer = os.open(path, os.O_WRONLY); os.close(writer)
                    return
                p = prepare_edit(base, fd, rt.targets[:1], expected)
                if name == 'old-grant-digest':
                    p.request.request_digest[:] = original_digest
                    base.rejects(lambda: edit_wire(base, fd, p, [copy], True), {errno.EKEYREJECTED})
                    return
                if name == 'fd-substitution':
                    replacement = Path(temporary) / 'replacement'; replacement.write_bytes(b'substitute\n'); replacement.chmod(0o600)
                    copy = os.open(replacement, os.O_RDONLY); opened.append(copy)
                if name == 'reset-revokes-grant':
                    second = os.open(base.DEVICE, os.O_RDWR | os.O_CLOEXEC)
                    try: base.reset(second)
                    finally: os.close(second)
                if name == 'copy-fault-terminal':
                    base.C.set_errno(0); result = base.LIBC.ioctl(fd, base.ioc(3, 8, 184), base.C.c_void_p(1))
                    base.check(result == -1 and base.C.get_errno() == errno.EFAULT, 'copy fault did not fail')
                    p = prepare_edit(base, fd, rt.targets[:1])
                    base.rejects(lambda: edit_wire(base, fd, p, [copy], True), {errno.EKEYREJECTED})
                    return
                if name == 'expired-fresh-grant': time.sleep(5.1)
                row = edit_wire(base, fd, p, [copy], True)
                errors = {'fd-substitution': errno.EKEYREJECTED, 'expired-fresh-grant': errno.EKEYEXPIRED,
                          'reset-revokes-grant': errno.EKEYREVOKED}
                if name == 'commit-replay':
                    base.check(row[0] == 9 and row[1] == 1 and row[3] == 0, 'real copyback failed')
                else:
                    base.check(row[0] == 10 and row[1] == 0 and row[3] == errors[name],
                               'negative copyback result differs: %s' % (row,))
                base.rejects(lambda: edit_wire(base, fd, p, [copy], True), {errno.EKEYREJECTED})
        finally:
            for value in opened: os.close(value)
            if fd >= 0: os.close(fd)
    details = rt.child('api-' + name, body)
    after = states(rt.targets)
    if name == 'commit-replay':
        base.check(after[0]['data_hex'] == b'raw-edited\n'.hex() and after[0]['ino'] != before[0]['ino'] and
                   after[1:] == before[1:], 'actual replay-control filesystem outcome differs')
    else: base.check(after == before, 'negative device case changed original files')
    base.check(not list(rt.work.glob('safeedit-api-*')) and not list((rt.root / 'edit-targets').glob('.bashos-v2-edit-*')),
               'device case left caller or privileged staging files')
    records = rt.audit_drain(); (rt.args.output / ('api-' + name + '-audit.bin')).write_bytes(b''.join(records))
    details.update(before=before, after=after, audit_records=len(records), role='negative mechanics; separate from consumer credit')
    return details


def consumer(rt, name, paths, expected_status, editor_count, passwords=(), behavior='write', on_editor=None, sealed_event=None,
             cwd=None):
    base = rt.base
    master = slave = None; data = bytearray(); passwords_sent = 0; started = continued = released = False
    actor = editor_actor = event = after_seal = None; observed_paths = []; starting_temps = set(Path('/tmp').glob('bashos-edit-v2.*'))
    initial_fds = final_fds = editor_fds = None
    env = dict(rt.env, SUDO_EDITOR=str(rt.root / 'safeedit-editor'), SAFEEDIT_BEHAVIOR=behavior,
               SAFEEDIT_WAIT='1', SAFEEDIT_ORIGINAL=str(rt.targets[0]))
    script = 'sudo --authority-v2-qualification -e ' + ('-n ' if not passwords else '') + '-- ' + ' '.join(shlex.quote(str(p)) for p in paths)
    wrapped = ('builtin printf "PCV2_BEFORE\\n"\nbuiltin read -r begin || exit 96\n{\n' + script +
               '\n}\nstatus=$?\nbuiltin printf "\\nPCV2_AFTER %s\\n" "$status"\n'
               'builtin read -r release || exit 96\nexit "$status"\n')
    if passwords: master, slave = pty.openpty()
    def setup():
        if slave is not None: os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        os.setgroups([base.CALLER, base.SHARED]); os.setresgid(base.CALLER, base.CALLER, base.CALLER)
        os.setresuid(base.CALLER, base.CALLER, base.CALLER)
    process = subprocess.Popen([str(rt.args.bash), '--noprofile', '--norc', '-c', wrapped], cwd=cwd or rt.work, env=env,
        stdin=slave if slave is not None else subprocess.PIPE, stdout=slave if slave is not None else subprocess.PIPE,
        stderr=slave if slave is not None else subprocess.STDOUT, close_fds=True, preexec_fn=setup)
    try:
        reader = master if master is not None else process.stdout.fileno()
        writer = master if master is not None else process.stdin.fileno()
        deadline = time.monotonic() + 45
        while process.poll() is None:
            require(time.monotonic() < deadline and len(data) < 1048576, 'owned safeedit actor timeout/output bound')
            if select.select([reader], [], [], .05)[0]:
                try: chunk = os.read(reader, 65536)
                except OSError as e:
                    if e.errno != errno.EIO: raise
                    chunk = b''
                data.extend(chunk)
            if not started and b'PCV2_BEFORE' in data:
                initial_fds = descriptors(process.pid); os.write(writer, b'begin\n'); started = True
            prompts = data.count(b'Password: ')
            if prompts > passwords_sent:
                base.check(prompts == passwords_sent + 1 and passwords_sent < len(passwords), 'unexpected password prompt count')
                base.check(slave is not None and not termios.tcgetattr(slave)[3] & termios.ECHO, 'password echo enabled')
                if prompts == 2 and sealed_event:
                    rows = [json.loads(line.split(b'PCV2_EDITOR ', 1)[1]) for line in data.splitlines() if line.startswith(b'PCV2_EDITOR ')]
                    base.check(len(rows) == 1, 'editor report missing before fresh verification')
                    sealed_paths = private_editor_paths(base, rows[0], len(paths))
                    directory = os.open(sealed_paths[0].parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        st = os.fstat(directory)
                        base.check(st.st_uid == base.CALLER and stat.S_IMODE(st.st_mode) == 0o700, 'private directory ownership changed')
                        for path in sealed_paths:
                            try: probe = os.open(path.name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                            except OSError as error: base.check(error.errno == errno.ETXTBSY, 'unexpected sealed writer error')
                            else: os.close(probe); base.check(False, 'sealed bytes remained writable before fresh password')
                        if sealed_event == 'replace-path':
                            for path in sealed_paths:
                                os.rename(path.name, path.name + '.held', src_dir_fd=directory, dst_dir_fd=directory)
                                target = os.open(path.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                                try: os.write(target, b'must-not-replace-sealed-bytes\n'); os.fchown(target, base.CALLER, base.CALLER)
                                finally: os.close(target)
                    finally: os.close(directory)
                    after_seal = {'kind': sealed_event, 'write_denial_observed_before_second_password': True,
                                  'paths': [str(path) for path in sealed_paths]}
                os.write(writer, passwords[passwords_sent] + b'\n'); passwords_sent += 1
            if not continued and b'PCV2_EDITOR_WAIT' in data:
                rows = [json.loads(line.split(b'PCV2_EDITOR ', 1)[1]) for line in data.splitlines() if line.startswith(b'PCV2_EDITOR ')]
                base.check(len(rows) == 1, 'editor report missing before live observation')
                private_editor_paths(base, rows[0], len(paths))
                pid = rows[0]['pid']; base.check(type(pid) is int and pid > 1, 'invalid editor pid')
                editor_actor = identity(pid); editor_fds = descriptors(pid)
                base.check(editor_actor['PPid'] == [process.pid] and editor_actor['Uid'] == editor_actor['Gid'] == [base.CALLER] * 4 and
                           sorted(editor_actor['Groups']) == [base.CALLER, base.SHARED], 'live editor lineage/IDs differ')
                base.check(sha(Path('/proc', str(pid), 'exe')) == sha(rt.root / 'safeedit-editor'), 'live editor executable differs')
                base.check(set(editor_fds) == {'0', '1', '2'}, 'editor inherited non-stdio descriptors')
                if on_editor: event = on_editor()
                os.write(writer, b'edit\n'); continued = True
            if not released and b'PCV2_AFTER ' in data:
                actor = identity(process.pid)
                final_fds = descriptors(process.pid)
                base.check(actor['Uid'] == actor['Gid'] == [base.CALLER] * 4 and
                           sorted(actor['Groups']) == [base.CALLER, base.SHARED], 'invoking Bash changed IDs')
                base.check(started and final_fds == initial_fds, 'invoking Bash leaked or changed descriptors')
                os.write(writer, b'release\n'); released = True
        while select.select([reader], [], [], .05)[0]:
            try: chunk = os.read(reader, 65536)
            except OSError as e:
                if e.errno != errno.EIO: raise
                break
            if not chunk: break
            data.extend(chunk)
        base.check(released and actor is not None and (continued and editor_actor is not None if editor_count else not continued),
                   'live actor/editor gate not observed')
        base.check(process.returncode == expected_status, 'safeedit returned %s expected %s' % (process.returncode, expected_status))
        base.check(passwords_sent == len(passwords), 'fresh authentication prompt missing')
        base.check(not sealed_event or after_seal is not None, 'sealed-byte observation missing')
        if passwords:
            base.check(termios.tcgetattr(slave)[3] & termios.ECHO and all(p not in data for p in passwords),
                       'password disclosure or terminal restoration failure')
        editors = [json.loads(line.split(b'PCV2_EDITOR ', 1)[1]) for line in data.splitlines() if line.startswith(b'PCV2_EDITOR ')]
        base.check(len(editors) == editor_count, 'editor invocation count differs')
        for row in editors:
            base.check(row['uid'] == row['gid'] == [base.CALLER] * 4 and sorted(row['groups']) == [base.CALLER, base.SHARED],
                       'editor did not run with actual caller IDs/groups')
            observed_paths = private_editor_paths(base, row, len(paths))
        leftovers = set(Path('/tmp').glob('bashos-edit-v2.*')) - starting_temps
        base.check(not leftovers and not any(os.path.lexists(p) for p in observed_paths), 'temporary copies/directories remain')
        return {'exit_code': process.returncode, 'password_prompts': passwords_sent, 'editor': editors,
                'invoking_actor_after': actor, 'controlled_editor_event': event,
                'live_editor_actor': editor_actor,
                'initial_bash_fds': initial_fds, 'final_bash_fds': final_fds, 'live_editor_fds': editor_fds,
                'controlled_sealed_event': after_seal,
                'log_sha256': hashlib.sha256(data).hexdigest()}
    finally:
        if process.poll() is None: process.kill(); process.wait()
        (rt.args.output / (name + '.log')).write_bytes(data)
        if master is not None: os.close(master); os.close(slave)
        else: process.stdin.close(); process.stdout.close()
        # Preserve the failure observation before cleaning only new caller-owned
        # fixture directories. Never sweep an existing guest directory.
        for directory in set(Path('/tmp').glob('bashos-edit-v2.*')) - starting_temps:
            st = directory.lstat()
            if stat.S_ISDIR(st.st_mode) and st.st_uid == base.CALLER: shutil.rmtree(directory)


def observe_case(rt, name, count, *, committed=0, editor_count=1, behavior='write', password=False,
                 wrong_second=False, fail_index=-1, allowed=16, drift=False, backpressure=False,
                 xattr=False, duplicate=False, invalid=None, sealed_event=None, relative=False):
    base = rt.base
    paths = reset_case(rt, count, password, fail_index, allowed)
    if duplicate: paths = [paths[0], paths[0]]
    if invalid == 'seventeen': paths += [paths[0]]
    if invalid == 'parent-traversal': paths = ['../file-00']
    if relative: paths = [('./' if relative == 'dot' else '') + p.name for p in paths]
    if xattr: os.setxattr(paths[0], 'user.fixture', b'preserve-me')
    before = states(rt.targets)
    def change_original():
        paths[0].write_bytes(b'external-change\n')
        return {'kind': 'independent-admin-original-change', 'target': str(paths[0]), 'sha256': sha(paths[0])}
    on_editor = change_original if drift else (lambda: fill_audit(rt)) if backpressure else None
    passwords = (base.PASSWORD, b'wrong-copyback-password' if wrong_second else base.PASSWORD) if password else ()
    success = committed == count and count > 0 and fail_index < 0 and not invalid
    details = consumer(rt, name, paths, 2 if invalid else 0 if success else 1,
                       editor_count, passwords, behavior, on_editor, sealed_event,
                       cwd=rt.root / 'edit-targets' if relative else None)
    after = states(rt.targets)
    for i, (old, new) in enumerate(zip(before, after)):
        if i < committed:
            base.check(new['data_hex'] == ('edited-%02d\n' % i).encode().hex() and new['ino'] != old['ino'],
                       'committed target data or atomic replacement inode differs')
            base.check(all(new[k] == old[k] for k in ('dev', 'uid', 'gid', 'mode', 'links', 'xattrs')), 'target metadata changed')
        elif drift and i == 0:
            base.check(new['data_hex'] == b'external-change\n'.hex() and new['ino'] == old['ino'], 'external change overwritten')
        else: base.check(new == old, 'uncommitted target changed at index %s' % i)
    base.check(not list((rt.root / 'edit-targets').glob('.bashos-v2-edit-*')), 'privileged staging file remains')
    records = rt.audit_drain()
    (rt.args.output / (name + '-audit.bin')).write_bytes(b''.join(records))
    if success or fail_index >= 0:
        outcomes = [struct.unpack_from('<I', row, 64)[0] for row in records]
        opens = [row for row in records if struct.unpack_from('<I', row, 64)[0] == 9 and struct.unpack_from('<I', row, 96)[0] == 8]
        seals = [row for row in records if struct.unpack_from('<I', row, 64)[0] == 9 and struct.unpack_from('<I', row, 96)[0] == 11]
        intents = [row for row in records if struct.unpack_from('<I', row, 64)[0] == 10]
        results = [row for row in records if struct.unpack_from('<I', row, 64)[0] == 11]
        base.check(len(opens) == len(seals) == len(results) == 1 and outcomes.count(4) == 2 and
                   outcomes.index(4) < records.index(opens[0]) < records.index(seals[0]) < max(i for i, x in enumerate(outcomes) if x == 4) <
                   outcomes.index(10) < outcomes.index(11), 'fresh authorization/open/commit audit order differs')
        # Independently hash observed original bytes and the editor's exact
        # defined output. The original request digest comes from the prior
        # authenticated OPEN record, before the transaction digest exists.
        frame = b'bashos-safeedit-v2' + opens[0][112:144] + struct.pack('<I', count)
        for i in range(count):
            edited = ('edited-%02d\n' % i).encode()
            frame += hashlib.sha256(bytes.fromhex(before[i]['data_hex'])).digest()
            frame += hashlib.sha256(edited).digest() + struct.pack('<Q', len(edited))
        digest = hashlib.sha256(frame).digest()
        fresh = [row for row in records[records.index(seals[0]) + 1:] if struct.unpack_from('<I', row, 64)[0] in (2, 4)]
        base.check(fresh and all(row[112:144] == digest for row in [*seals, *fresh, *intents, *results]),
                   'transaction digest differs from independent content oracle')
        base.check(len(intents) == (count if success else fail_index + 1) and
                   [struct.unpack_from('<I', row, 96)[0] for row in intents] == list(range(len(intents))),
                   'per-target intent prefix differs')
        base.check(struct.unpack_from('<II', results[0], 104) == (count, committed), 'audit committed count differs')
        details['transaction_digest_sha256'] = digest.hex()
    if invalid: base.check(not records, 'usage validation reached the authority')
    if fail_index >= 0:
        output = (rt.args.output / (name + '.log')).read_bytes()
        base.check(('committed=%d/%d' % (committed, count)).encode() in output, 'client did not report exact committed prefix')
        results = [row for row in records if struct.unpack_from('<I', row, 64)[0] == 11]
        base.check(len(results) == 1 and struct.unpack_from('<II', results[0], 104) == (count, committed),
                   'real audit prefix differs from independently observed files')
    details.update(before=before, after=after, committed=committed, audit_records=len(records),
                   selected_intent_fault_index=fail_index, copyback_authority='real device; no mock grants')
    return details


def race_or_fault_case(rt, name):
    """Independent root fixture actions at the live editor gate, never mock grants."""
    base = rt.base
    paths = reset_case(rt, 2)
    before = states(rt.targets)
    auxiliary = rt.root / ('event-' + name)
    held = None
    read_only = False
    event = None

    def at_editor():
        nonlocal held, read_only, event
        path = paths[0]
        if name in ('inode-replaced', 'original-symlink'):
            path.rename(auxiliary)
            if name == 'inode-replaced': rt.install(path, bytes.fromhex(before[0]['data_hex']), 0o600)
            else: path.symlink_to(auxiliary)
        elif name == 'original-hardlink': os.link(path, auxiliary)
        elif name == 'original-mode-change': path.chmod(0o644)
        elif name == 'original-owner-change': os.chown(path, base.CALLER, base.CALLER)
        elif name == 'original-open-writer': held = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        elif name == 'filesystem-enospc':
            require(os.stat(rt.root).st_dev != os.stat(rt.root.parent).st_dev, 'private tmpfs mount missing')
            vfs = os.statvfs(rt.root)
            require(0 < vfs.f_blocks * vfs.f_frsize <= 32 * 1024 * 1024,
                    'bounded fixture filesystem differs')
            held = os.open(auxiliary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
            block = bytes(65536); total = 0
            for _ in range(514):
                try: written = os.write(held, block)
                except OSError as error:
                    require(error.errno == errno.ENOSPC, 'unexpected independent fill failure')
                    break
                require(written > 0, 'zero write while filling owned tmpfs'); total += written
            else: raise RuntimeError('owned tmpfs did not reach bounded ENOSPC')
            require(os.statvfs(rt.root).f_bavail == 0, 'independent filesystem full observation missing')
        elif name == 'filesystem-readonly':
            require(os.stat(rt.root).st_dev != os.stat(rt.root.parent).st_dev, 'private tmpfs mount missing')
            require(base.LIBC.mount(None, os.fsencode(rt.root), None, 32 | 1 | 2 | 4, None) == 0,
                    'owned tmpfs read-only remount failed')
            read_only = True
            base.check(os.statvfs(rt.root).f_flag & os.ST_RDONLY, 'read-only mount flag missing')
        else: raise RuntimeError('unknown independent event')
        event = {'kind': name, 'originals_after_event': states(rt.targets),
                 'auxiliary_after_event': states([auxiliary]) if auxiliary.exists() and name != 'filesystem-enospc' else [],
                 'fill_bytes': total if name == 'filesystem-enospc' else None,
                 'open_writer': held is not None, 'readonly': read_only,
                 'free_blocks': os.statvfs(rt.root).f_bavail}
        return event

    try:
        details = consumer(rt, name, paths, 1, 1, on_editor=at_editor)
        base.check(event is not None, 'independent event not reached')
        after = states(rt.targets)
        base.check(after == event['originals_after_event'], 'copyback overwrote independently changed originals')
        if event['auxiliary_after_event']:
            base.check(states([auxiliary]) == event['auxiliary_after_event'], 'copyback changed independent event artifact')
        base.check(not list((rt.root / 'edit-targets').glob('.bashos-v2-edit-*')),
                   'rejected race/fault left privileged staging files')
        rows = rt.audit_drain()
        (rt.args.output / (name + '-audit.bin')).write_bytes(b''.join(rows))
        results = [row for row in rows if struct.unpack_from('<I', row, 64)[0] == 11]
        base.check(len(results) == 1 and struct.unpack_from('<II', results[0], 104) == (2, 0),
                   'race/fault committed prefix not exactly zero')
        kind, code = struct.unpack_from('<II', results[0], 96)
        base.check(kind == 10 and 0 < code <= 4095, 'race/fault did not return a bounded EDIT_ERROR')
        if name in ('filesystem-enospc', 'filesystem-readonly', 'original-open-writer'):
            expected = {'filesystem-enospc': errno.ENOSPC, 'filesystem-readonly': errno.EROFS,
                        'original-open-writer': errno.ETXTBSY}[name]
            base.check(struct.unpack_from('<I', results[0], 100)[0] == expected,
                       'real filesystem/alias errno differs')
        details.update(before=before, after=after, audit_records=len(rows),
                       independent_event=event, committed=0, synthesized_allow=False)
        return details
    finally:
        if read_only:
            require(base.LIBC.mount(None, os.fsencode(rt.root), None, 32 | 2 | 4, None) == 0,
                    'owned tmpfs writable restoration failed')
            require(not os.statvfs(rt.root).f_flag & os.ST_RDONLY, 'owned tmpfs restoration not observed')
        if held is not None: os.close(held)
        if os.path.lexists(auxiliary): auxiliary.unlink()


def relative_boundary_case(rt, name):
    base = rt.base; directory = rt.root / 'edit-targets'
    if name == 'relative-length-255':
        original = rt.targets[0]
        path = directory / ('b' * (255 - len(os.fsencode(directory)) - 1))
        require(len(os.fsencode(path)) == 255 and len(os.fsencode(path.name)) <= 255,
                'exact path boundary fixture unavailable')
        rt.targets[0] = path
        try: return observe_case(rt, name, 1, committed=1, relative=True)
        finally:
            rt.targets[0] = original
            if os.path.lexists(path): path.unlink()
    reset_case(rt, 2)
    if name == 'relative-symlink-before-open':
        rt.targets[0].unlink(); rt.targets[0].symlink_to(rt.targets[1].name)
        # Both lexical path and symlink destination are policy-allowed. A
        # client realpath shortcut would therefore edit the second file and
        # be caught by the zero-editor and unchanged-files observations.
        operand, expected, wanted_records = './' + rt.targets[0].name, 1, True
    else:
        require(name == 'relative-length-256', 'unknown relative boundary control')
        operand = 'b' * (256 - len(os.fsencode(directory)) - 1)
        require(len(os.fsencode(directory / operand)) == 256 and len(os.fsencode(operand)) <= 255,
                'over-boundary fixture unavailable')
        expected, wanted_records = 2, False
    before = states(rt.targets)
    details = consumer(rt, name, [operand], expected, 0, cwd=directory)
    after = states(rt.targets)
    base.check(after == before, 'relative denial changed original files')
    rows = rt.audit_drain(); (rt.args.output / (name + '-audit.bin')).write_bytes(b''.join(rows))
    base.check(bool(rows) == wanted_records, 'relative boundary authority admission differs')
    base.check(not list(directory.glob('.bashos-v2-edit-*')), 'relative denial left privileged staging')
    details.update(before=before, after=after, audit_records=len(rows), operand=operand)
    return details


def main():
    parser = argparse.ArgumentParser()
    for name in ('receipt', 'bash', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('receipt-sha256', 'bash-sha256', 'expected-uuid'): parser.add_argument('--' + name, required=True)
    args = parser.parse_args(); protected(args.receipt, args.receipt_sha256)
    receipt = json.loads(args.receipt.read_text())
    require(receipt['schema'] == 1 and receipt['kind'] == 'authority-privcmd-v2-build-only', 'build receipt differs')
    for name, record in receipt['files'].items():
        require(Path(name).name == name, 'invalid artifact name'); protected(args.receipt.parent / name, record['sha256'])
        require((args.receipt.parent / name).stat().st_size == record['bytes'], 'artifact length differs')
    require(sha(__file__) == receipt['files']['guest-safeedit-controls.py']['sha256'], 'guest controls source differs')
    spec = importlib.util.spec_from_file_location('privcmd_base', args.receipt.parent / 'guest-privcmd-controls.py')
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    base.guard(args.expected_uuid, receipt['kernel_release']); protected(args.bash, args.bash_sha256)
    require(args.receipt.is_absolute() and args.bash.is_absolute() and args.output.is_absolute() and
            args.output.resolve().is_relative_to(base.HOME) and not args.output.exists(), 'fresh private absolute output required')
    args.output.mkdir(mode=0o700); rt = base.Runtime(args, receipt); rt.base = base
    rt.report.update(scope='actual sudo safeedit and real filesystem observations',
                     blocking_gaps=['interactive login/session requirements', 'complete original matrix', 'actual qualification'],
                     fault_scope='one denial-only kernel intent callback control; all policy, grants and filesystem effects real')
    before = rt.command(['/usr/bin/dmesg', '--raw']); require(before.returncode == 0, 'kernel log unavailable')
    (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        rt.setup(); (rt.root / 'edit-targets').mkdir(mode=0o755)
        rt.targets = [rt.root / 'edit-targets' / ('file-%02d' % i) for i in range(16)]
        rt.install(rt.root / 'safeedit-editor', (rt.artifacts / 'safeedit-editor').read_bytes(), 0o755)
        cases = [('one-target', 1, {'committed': 1}), ('two-targets', 2, {'committed': 2}),
                 ('sixteen-targets', 16, {'committed': 16}),
                 ('editor-replaces-private-inode', 2, {'committed': 2, 'behavior': 'replace'}),
                 ('editor-backup-cleanup', 2, {'committed': 2, 'behavior': 'backup'}),
                 ('editor-failure-cleanup', 2, {'behavior': 'fail'}),
                 ('edited-copy-symlink-denied', 2, {'behavior': 'symlink'}),
                 ('original-drift-denied', 2, {'drift': True}),
                 ('fresh-password-success', 2, {'committed': 2, 'password': True}),
                 ('sealed-bytes-before-second-password', 2, {'committed': 2, 'password': True, 'sealed_event': 'deny-writer'}),
                 ('sealed-path-substitution-keeps-pinned-bytes', 2, {'committed': 2, 'password': True, 'sealed_event': 'replace-path'}),
                 ('fresh-password-failure', 2, {'password': True, 'wrong_second': True}),
                 ('preverification-seal-audit-backpressure', 2, {'backpressure': True}),
                 ('late-denial-reports-committed-prefix', 3, {'committed': 1, 'fail_index': 1}),
                 ('every-target-policy-required', 2, {'allowed': 1, 'editor_count': 0}),
                 ('duplicate-target-denied', 2, {'duplicate': True, 'editor_count': 0}),
                 ('unsupported-xattr-denied', 1, {'xattr': True, 'editor_count': 0}),
                 ('zero-targets-usage', 0, {'invalid': 'zero', 'editor_count': 0}),
                 ('seventeen-targets-usage', 16, {'invalid': 'seventeen', 'editor_count': 0}),
                 ('relative-parent-traversal-usage', 1, {'invalid': 'parent-traversal', 'editor_count': 0}),
                 ('relative-one-target', 1, {'committed': 1, 'relative': True}),
                 ('relative-dot-two-targets', 2, {'committed': 2, 'relative': 'dot'})]
        for name, count, options in cases:
            rt.note(name, lambda n=name, c=count, o=options: observe_case(rt, n, c, **o),
                    'actual-consumer-with-denial-only-intent-fault' if options.get('fail_index', -1) >= 0 else 'actual-consumer')
        for name in ('inode-replaced', 'original-symlink', 'original-hardlink', 'original-mode-change',
                     'original-owner-change', 'original-open-writer', 'filesystem-enospc', 'filesystem-readonly'):
            rt.note(name, lambda n=name: race_or_fault_case(rt, n), 'actual-consumer-independent-filesystem-event')
        for name in ('relative-length-255', 'relative-length-256', 'relative-symlink-before-open'):
            rt.note(name, lambda n=name: relative_boundary_case(rt, n), 'actual-consumer-relative-path-boundary')
        for name in ('zero-count', 'seventeen-count', 'bad-request-digest', 'commit-before-open', 'foreign-task',
                     'open-grant-reuse', 'writable-alias', 'readwrite-upload', 'cancelled-session', 'different-target',
                     'reset-revokes-grant', 'copy-fault-terminal', 'commit-replay', 'unsealed-reprepare',
                     'post-seal-writer-denied', 'seal-replay', 'fd-substitution', 'old-grant-digest',
                     'last-close-releases-seal', 'expired-fresh-grant'):
            rt.note('api-' + name, lambda n=name: raw_edit_case(rt, n), 'actual-device-binding-controls')
        require(len(rt.cases) == 53 and all(r['status'] == 'PASS' for r in rt.cases), 'safeedit matrix incomplete')
        rt.report.update(status='PASS', all_nine_topics_qualified=False, production_features_enabled=False)
    except AssertionError as error: rt.report.update(status='FAIL', reason=str(error))
    except Exception as error: rt.report.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error))
    finally:
        try:
            rt.cleanup(); after = rt.command(['/usr/bin/dmesg', '--raw'])
            require(after.returncode == 0 and after.stdout.startswith(before.stdout), 'kernel log lost/wrapped')
            delta = after.stdout[len(before.stdout):]
            (args.output / 'dmesg-after.txt').write_bytes(after.stdout); (args.output / 'dmesg-delta.txt').write_bytes(delta)
            require(not any(word in delta.lower() for word in (b'warning:', b'bug:', b'kasan:', b'kcsan:', b'ubsan:',
                b'held lock', b'oops:', b'possible recursive locking', b'inconsistent lock state',
                b'general protection fault', b'info: task ')), 'kernel warning/fault evidence')
        except Exception as error: rt.report.update(status='ERROR', cleanup_or_kernel_error=repr(error))
        (args.output / 'commands.json').write_text(json.dumps(rt.commands, indent=2) + '\n')
        (args.output / 'report.json').write_text(json.dumps(rt.report, indent=2) + '\n')
    print(json.dumps({'status': rt.report['status'], 'report': str(args.output / 'report.json')}))
    return 0 if rt.report['status'] == 'PASS' else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error: print('safeedit preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
