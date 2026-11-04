#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Per-side syscall filter for disposable parity-VM fixtures (unprivileged).

Usage: clamp-system-sequence-r2.py [RULE...] -- PROGRAM [ARG...]

Rules (repeatable):
  --kill NAME[:COND]            SIGSYS-kill the whole process if NAME is called.
  --errno NAME:ERRNO[:COND]     make NAME fail with ERRNO (e.g. EIO, ENOTTY or 5).
  --notify NAME[:COND]          stop NAME at a user-notification listener in
                                this helper, which records it and answers.
  --reply NAME=VALUE|ERRNO      answer for notified NAME: an integer return
                                value, an errno name, or "continue" (the
                                default: let the kernel run the real call).
  --reply-seq NAME=A,B,...      successive replies for that syscall, across
                                all filtered descendants; then continue.
  --log FILE                    append one JSON line per notified call.
  --log-args NAME=I[,J]         record these integer arguments (masked 32-bit
                                unless suffixed with "q") for notified NAME.
  --log-string NAME=I           record argument I as a NUL-terminated string
                                read from the caller (at most 4096 bytes).
  --log-mem NAME=I:LEN          record LEN bytes at pointer argument I as hex
                                (1..4096 bytes; one buffer per syscall).
COND is ARG=VALUE[,ARG=VALUE] compared on the low 32 bits.

The filter is installed with no_new_privs in a forked child, which then
executes PROGRAM. Install it around a fresh shell (for example "$BASH" -c
...) so that the builtin under test runs in the filtered process. Rules stack
on top of any outer filter; the kernel applies the most restrictive action
(KILL > ERRNO > NOTIFY > ALLOW), so --notify cannot override an outer ERRNO
rule. Between loading the filter and execve the helper itself only calls
sendmsg and fcntl, so notified records come from PROGRAM. The helper exits with PROGRAM's status, or 128+signal, and always
reaps it. It never grants privilege: the kernel keeps enforcing permissions
on every call that is allowed or continued.

This is a separate helper so existing fixtures retain their pinned observer.
Sequence positions count notifications, not completed kernel calls. In
particular a synthetic successful return does not perform I/O or change an
output buffer. Memory observations precede the reply and are diagnostic data,
not an authority check; fixtures must own their child and its mutable memory.
"""
import ctypes
import errno
import fcntl
import json
import os
import select
import signal
import socket
import struct
import sys
from pathlib import Path
import time
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from clamp_r2_support import atomic
from clamp_r2_guard import verify

ALLOW = 0x7fff0000
KILL_PROCESS = 0x80000000
NOTIFY = 0x7fc00000
CMP_MASKED_EQ = 7
NOTIF_RECV = 0xc0502100      # _IOWR('!', 0, struct seccomp_notif), 80 bytes
NOTIF_SEND = 0xc0182101      # _IOWR('!', 1, struct seccomp_notif_resp), 24 bytes
FLAG_CONTINUE = 1


class ArgCmp(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]


def fail(message):
    sys.stderr.write("system-sequence: " + message + "\n")
    sys.exit(125)


def parse_errno(text):
    if text.isdigit():
        return int(text)
    value = getattr(errno, text, None)
    if not isinstance(value, int):
        fail("unknown errno: " + text)
    return value


def parse_cond(text):
    conds = []
    for item in filter(None, text.split(",")):
        index, _, value = item.partition("=")
        if not index.isdigit() or int(index) > 5 or not value:
            fail("invalid condition: " + item)
        conds.append((int(index), int(value, 0) & 0xffffffff))
    return conds


def parse_answer(text):
    if text == "continue":
        return ("continue", 0)
    if text.lstrip("-").isdigit():
        value = int(text)
        if not -(2**63) <= value < 2**63:
            fail("reply outside signed 64-bit range")
        return ("value", value)
    return ("errno", parse_errno(text))


def parse(argv):
    rules, replies, sequences, logargs, logstr, logmem, log = [], {}, {}, {}, {}, {}, None
    i = 0
    while i < len(argv) and argv[i] != "--":
        option = argv[i]
        if i + 1 >= len(argv):
            fail("missing value for " + option)
        value = argv[i + 1]
        i += 2
        if option == "--kill":
            name, _, cond = value.partition(":")
            rules.append((name, KILL_PROCESS, parse_cond(cond)))
        elif option == "--errno":
            parts = value.split(":", 2)
            if len(parts) < 2:
                fail("--errno needs NAME:ERRNO")
            rules.append((parts[0], 0x00050000 | (parse_errno(parts[1]) & 0xffff),
                          parse_cond(parts[2] if len(parts) > 2 else "")))
        elif option == "--notify":
            name, _, cond = value.partition(":")
            rules.append((name, NOTIFY, parse_cond(cond)))
        elif option == "--reply":
            name, separator, value_text = value.partition("=")
            if not name or not separator or not value_text:
                fail("--reply needs NAME=VALUE|ERRNO")
            replies[name] = parse_answer(value_text)
        elif option == "--reply-seq":
            name, separator, values = value.partition("=")
            parts = values.split(",")
            if not name or not separator or not all(parts) or len(parts) > 4096:
                fail("--reply-seq needs NAME=A,B,... (1..4096 replies)")
            sequences[name] = [parse_answer(item) for item in parts]
        elif option == "--log":
            log = value
        elif option == "--log-args":
            name, _, indexes = value.partition("=")
            logargs[name] = [(int(x.rstrip("q")), x.endswith("q")) for x in indexes.split(",") if x]
        elif option == "--log-string":
            name, _, index = value.partition("=")
            logstr[name] = int(index)
        elif option == "--log-mem":
            name, separator, spec = value.partition("=")
            index, colon, length = spec.partition(":")
            if (not name or not separator or not colon or not index.isdigit()
                    or not length.isdigit() or not 0 <= int(index) <= 5
                    or not 1 <= int(length) <= 4096):
                fail("--log-mem needs NAME=I:LEN (argument 0..5, length 1..4096)")
            if name in logmem:
                fail("duplicate --log-mem for " + name)
            logmem[name] = (int(index), int(length))
        else:
            fail("unknown option: " + option)
    if i >= len(argv) or i + 1 >= len(argv):
        fail("missing -- PROGRAM")
    if set(replies) & set(sequences):
        fail("--reply and --reply-seq cannot name the same syscall")
    for indexes in logargs.values():
        if any(not 0 <= index <= 5 for index, _wide in indexes):
            fail("--log-args index outside 0..5")
    if any(not 0 <= index <= 5 for index in logstr.values()):
        fail("--log-string index outside 0..5")
    return rules, replies, sequences, logargs, logstr, logmem, log, argv[i + 1:]


def install(lib, rules):
    ctx = lib.seccomp_init(ALLOW)
    if not ctx:
        fail("seccomp_init failed")
    for name, action, conds in rules:
        number = lib.seccomp_syscall_resolve_name(name.encode())
        if number < 0:
            fail("unknown syscall: " + name)
        array = (ArgCmp * max(1, len(conds)))()
        for k, (index, value) in enumerate(conds):
            array[k] = ArgCmp(index, CMP_MASKED_EQ, 0xffffffff, value)
        if lib.seccomp_rule_add_array(ctx, ctypes.c_uint32(action), number, len(conds), array) != 0:
            fail("cannot add rule for " + name)
    if lib.seccomp_load(ctx) != 0:
        fail("seccomp_load failed")
    return ctx


def read_string(pid, address):
    try:
        with open("/proc/%d/mem" % pid, "rb", buffering=0) as mem:
            mem.seek(address)
            data = mem.read(4096)
    except OSError as exc:
        return {"unreadable": exc.strerror}
    return data.split(b"\0", 1)[0].decode("utf-8", "backslashreplace")


def read_memory(pid, address, length):
    try:
        with open("/proc/%d/mem" % pid, "rb", buffering=0) as mem:
            data = os.pread(mem.fileno(), length, address)
    except (OSError, OverflowError) as exc:
        return {"requested": length, "unreadable": str(exc)}
    return {"requested": length, "length": len(data), "hex": data.hex()}


def main():
    verify()
    if os.getuid() != 2000 or Path.cwd() != Path('/tmp/parity-case'):
        raise RuntimeError('notification observer outside fixture')
    argv = sys.argv[1:]
    target = None
    template = None
    for flag in ('--target-errno', '--synthetic-attr'):
        if flag in argv:
            i = argv.index(flag)
            value = argv[i + 1]
            del argv[i:i + 2]
            if flag == '--target-errno':
                target = int(value)
            else:
                target_text, data = value.split(':', 1)
                target, template = int(target_text), bytes.fromhex(data)
                if len(template) != 56:
                    raise RuntimeError('invalid synthetic sched_attr size')
    rules, replies, sequences, logargs, logstr, logmem, log, program = parse(argv)
    if not log or Path(log).parent != Path('/tmp/parity-home'):
        raise RuntimeError('notification log must be in fixture HOME')
    log = Path(log)
    receipt = {'schema': 'clamp-notification-r2', 'observer_status': 'incomplete',
               'exec_confirmed': False, 'program_status': None, 'reaped': False,
               'cleanup_complete': False, 'acknowledged_ids': [], 'program': program}
    atomic(str(log) + '.outcome.json', receipt)
    child = None
    listener = None
    parent = peer = None
    read = write = None
    wait = None
    rc = 125
    try:
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
            raise RuntimeError('cannot become observer child subreaper')
        lib = ctypes.CDLL('libseccomp.so.2')
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(ArgCmp)]
        lib.seccomp_load.argtypes = [ctypes.c_void_p]
        lib.seccomp_notify_fd.argtypes = [ctypes.c_void_p]
        lib.seccomp_syscall_resolve_num_arch.restype = ctypes.c_void_p
        lib.seccomp_syscall_resolve_num_arch.argtypes = [ctypes.c_uint32, ctypes.c_int]
        notifying = any(action == NOTIFY for _, action, _ in rules)
        parent, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        read, write = os.pipe2(os.O_CLOEXEC)
        os.set_blocking(read, False)
        child = os.fork()
        if child == 0:
            try:
                os.setsid()
                parent.close()
                os.close(read)
                ctx = install(lib, rules)
                if notifying:
                    fd = lib.seccomp_notify_fd(ctx)
                    os.set_inheritable(fd, False)
                    socket.send_fds(peer, [b'L'], [fd])
                else:
                    peer.send(b'E')
                # No extra writes after filter install: private sysctl fixtures
                # notify write(). CLOEXEC closes this pipe on successful exec.
                os.execv(program[0], program)
            except BaseException as error:
                # On filtered write(), the supervisor services this diagnostic too.
                os.write(write, (type(error).__name__ + ': ' + str(error)).encode()[:2048])
            os._exit(126)
        peer.close(); peer = None
        os.close(write); write = None
        deadline = time.monotonic() + 30
        if not select.select([parent], [], [], 8)[0]:
            raise RuntimeError('filter setup acknowledgment not delivered')
        if notifying:
            _, fds, _, _ = socket.recv_fds(parent, 16, 1)
            if len(fds) != 1:
                raise RuntimeError('filter listener missing')
            listener = fds[0]
        elif parent.recv(16) != b'E':
            raise RuntimeError('filter setup acknowledgment differs')
        positions = {}
        errors = bytearray()
        eof = False
        count = 0
        with log.open('x') as handle:
            while wait is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError('notification observer deadline')
                try:
                    data = os.read(read, 2049)
                    if data:
                        errors.extend(data)
                    else:
                        eof = True
                except BlockingIOError:
                    pass
                if errors:
                    raise RuntimeError('program exec/setup failed: ' + errors.decode(errors='replace'))
                done, status = os.waitpid(child, os.WNOHANG)
                if done:
                    wait = status
                    break
                if listener is None or not select.select([listener], [], [], .05)[0]:
                    if listener is None:
                        time.sleep(.01)
                    continue
                request = bytearray(80)
                try:
                    fcntl.ioctl(listener, NOTIF_RECV, request, True)
                except OSError as error:
                    if error.errno in (errno.ENOENT, errno.EINTR):
                        continue
                    raise
                ident, pid, _, nr, _, _ = struct.unpack_from('<QIIiIQ', request)
                args = struct.unpack_from('<6Q', request, 32)
                raw = lib.seccomp_syscall_resolve_num_arch(0, nr)
                name = ctypes.cast(raw, ctypes.c_char_p).value.decode() if raw else str(nr)
                row = {'id': ident, 'syscall': name, 'caller': pid}
                for index, wide in logargs.get(name, []):
                    row['arg%d' % index] = args[index] if wide else args[index] & 0xffffffff
                if name in logstr:
                    row['string%d' % logstr[name]] = read_string(pid, args[logstr[name]])
                if name in logmem:
                    index, length = logmem[name]
                    row['memory%d' % index] = read_memory(pid, args[index], length)
                position = positions.get(name, 0)
                if name in sequences:
                    values = sequences[name]
                    kind, value = values[position] if position < len(values) else ('continue', 0)
                    positions[name] = position + 1
                    row.update(sequence_index=position + 1, sequence_exhausted=position >= len(values))
                else:
                    kind, value = replies.get(name, ('continue', 0))
                if target is not None and args[0] & 0xffffffff == target:
                    if template is None and name == 'sched_getattr':
                        kind, value = 'errno', errno.ESRCH
                    elif template is not None and name == 'sched_getattr':
                        with open('/proc/%d/mem' % pid, 'r+b', buffering=0) as mem:
                            if os.pwrite(mem.fileno(), template, args[1]) != len(template):
                                raise RuntimeError('short synthetic getattr')
                        row['synthetic_output_hex'] = template.hex()
                        kind, value = 'value', 0
                    elif template is not None and name == 'sched_setattr':
                        row['input'] = read_memory(pid, args[1], 56)
                        kind, value = 'value', 0
                row['reply'] = kind if kind == 'continue' else '%s:%d' % (kind, value)
                handle.write(json.dumps(row, sort_keys=True) + '\n'); handle.flush()
                count += 1
                if count > 4096:
                    raise RuntimeError('notification limit exceeded')
                response = struct.pack('<QqiI', ident, value if kind == 'value' else 0,
                                       -value if kind == 'errno' else 0, FLAG_CONTINUE if kind == 'continue' else 0)
                fcntl.ioctl(listener, NOTIF_SEND, response)
                receipt['acknowledged_ids'].append(ident)
        # Drain the CLOEXEC error pipe after wait; a failed exec is never a
        # candidate exit 126. A supervisor exception never uses the child status.
        data = os.read(read, 2049)
        errors.extend(data)
        eof = eof or data == b''
        if errors or not eof:
            raise RuntimeError('exec confirmation incomplete')
        receipt.update(exec_confirmed=True, reaped=True, cleanup_complete=True,
                       exec_confirmation='CLOEXEC error pipe closed without setup/exec error',
                       program_status=os.waitstatus_to_exitcode(wait) if os.WIFEXITED(wait) else 128 + os.WTERMSIG(wait),
                       wait_status=wait, termination='exit' if os.WIFEXITED(wait) else 'signal',
                       signal=None if os.WIFEXITED(wait) else os.WTERMSIG(wait),
                       observer_status='completed')
        rc = receipt['program_status']
    except BaseException as error:
        receipt['observer_error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if child is not None and wait is None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child, 0)
                receipt['reaped'] = True
            except ChildProcessError:
                pass
        # Reparented descendants are ours because PR_SET_CHILD_SUBREAPER was set
        # before fork. Their sessions may differ; do not rely only on killpg.
        remaining = []
        for attempt in range(100):
            remaining = []
            for path in Path('/proc').glob('[0-9]*/stat'):
                try:
                    fields = path.read_text().rsplit(')', 1)[1].split()
                    pid = int(path.parent.name)
                    if int(fields[1]) == os.getpid():
                        if fields[0] == 'Z':
                            os.waitpid(pid, os.WNOHANG)
                        else:
                            remaining.append(pid)
                            os.kill(pid, signal.SIGKILL)
                except (OSError, ValueError, ChildProcessError):
                    continue
            if not remaining:
                break
            receipt['descendants_required_kill'] = True
            time.sleep(.02)
        if remaining or receipt.get('descendants_required_kill'):
            receipt.update(cleanup_complete=False,
                           cleanup_error='program left descendants', remaining_pids=remaining)
            rc = 125
        for fd in (read, write, listener):
            if fd is not None:
                os.close(fd)
        for sock in (parent, peer):
            if sock is not None:
                sock.close()
        atomic(str(log) + '.outcome.json', receipt)
    return rc


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('clamp observer incomplete: ' + str(error), file=sys.stderr)
        raise SystemExit(125)

