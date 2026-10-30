#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Per-side syscall filter for disposable parity-VM fixtures (unprivileged).

Usage: system-sequence.py [RULE...] -- PROGRAM [ARG...]

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
import platform
from pathlib import Path
import time
import uuid
import errno
import fcntl
import json
import os
import select
import signal
import socket
import struct
import sys

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


def supervise(lib, listener, child, replies, sequences, logargs, logstr, logmem, log):
    handle = open(log, "a") if log else None
    status = None
    positions = {}
    try:
        while status is None:
            # A listener stays readable after its last filtered process exits.
            # RECV then returns ENOENT; reap before retrying instead of spinning
            # until the supervisor exhausts its CPU limit.
            done, wait = os.waitpid(child, os.WNOHANG)
            if done:
                status = wait
                break
            ready, _, _ = select.select([listener], [], [], 0.05)
            if ready:
                request = bytearray(80)
                try:
                    fcntl.ioctl(listener, NOTIF_RECV, request, True)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.EINTR):
                        continue
                    raise
                ident, pid, _flags, nr, _arch, _ip = struct.unpack_from("<QIIiIQ", request)
                args = struct.unpack_from("<6Q", request, 32)
                raw = lib.seccomp_syscall_resolve_num_arch(0, nr)
                name = ctypes.cast(raw, ctypes.c_char_p).value.decode() if raw else str(nr)
                record = {"syscall": name}
                for index, wide in logargs.get(name, []):
                    record["arg%d" % index] = args[index] if wide else args[index] & 0xffffffff
                if name in logstr:
                    record["string%d" % logstr[name]] = read_string(pid, args[logstr[name]])
                if name in logmem:
                    index, length = logmem[name]
                    record["memory%d" % index] = read_memory(pid, args[index], length)
                if name in sequences:
                    position = positions.get(name, 0)
                    values = sequences[name]
                    kind, value = values[position] if position < len(values) else ("continue", 0)
                    positions[name] = position + 1
                    record["sequence_index"] = position + 1
                    record["sequence_exhausted"] = position >= len(values)
                else:
                    kind, value = replies.get(name, ("continue", 0))
                record["reply"] = kind if kind == "continue" else "%s:%d" % (kind, value)
                if handle:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
                    handle.flush()
                if kind == "continue":
                    response = struct.pack("<QqiI", ident, 0, 0, FLAG_CONTINUE)
                elif kind == "value":
                    response = struct.pack("<QqiI", ident, value, 0, 0)
                else:
                    response = struct.pack("<QqiI", ident, 0, -value, 0)
                try:
                    fcntl.ioctl(listener, NOTIF_SEND, response)
                except OSError as exc:
                    if exc.errno != errno.ENOENT:  # caller died meanwhile
                        raise
    finally:
        if handle:
            handle.close()
        if status is None:
            os.kill(child, signal.SIGKILL)
            status = os.waitpid(child, 0)[1]
    return status


# This bootstrap is separate from the frozen generic helper. The device peers
# replace supervise() before invoking main(). All filter construction and the
# SCM_RIGHTS message are built before the filter is installed.
CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
BOOTSTRAP_LOG=None


class SockFilter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(SockFilter))]


class IOVec(ctypes.Structure):
    _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]


class MsgHdr(ctypes.Structure):
    _fields_=[('name',ctypes.c_void_p),('namelen',ctypes.c_uint),('iov',ctypes.POINTER(IOVec)),
              ('iovlen',ctypes.c_size_t),('control',ctypes.c_void_p),('controllen',ctypes.c_size_t),('flags',ctypes.c_int)]


class CmsgHdr(ctypes.Structure):
    _fields_=[('length',ctypes.c_size_t),('level',ctypes.c_int),('type',ctypes.c_int)]


def guest_guard():
    if not __debug__:raise SystemExit(125)
    import importlib.util
    path='/opt/bashos-parity/harness/helpers/farm600-passwd-prompts-reviewed-guard.py'
    spec=importlib.util.spec_from_file_location('passwd_guest_guard',path)
    guard_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard_module)
    guard_module.verify()
    if os.getuid()!=2000 or os.geteuid()!=2000 or platform.machine()!='x86_64':
        raise SystemExit(125)


def exported_filter(lib,rules):
    ctx=lib.seccomp_init(ALLOW)
    if not ctx:raise RuntimeError('seccomp_init failed')
    try:
        for name,action,conds in rules:
            number=lib.seccomp_syscall_resolve_name(name.encode())
            if number<0:raise RuntimeError('unknown syscall '+name)
            array=(ArgCmp*max(1,len(conds)))()
            for k,(index,value) in enumerate(conds):array[k]=ArgCmp(index,CMP_MASKED_EQ,0xffffffff,value)
            if lib.seccomp_rule_add_array(ctx,ctypes.c_uint32(action),number,len(conds),array)!=0:
                raise RuntimeError('cannot add rule '+name)
        fd=os.memfd_create('auth-filter-bpf',os.MFD_CLOEXEC)
        try:
            if lib.seccomp_export_bpf(ctx,fd)!=0:raise RuntimeError('seccomp_export_bpf failed')
            os.lseek(fd,0,os.SEEK_SET);blob=os.read(fd,8*4097)
        finally:os.close(fd)
    finally:lib.seccomp_release(ctx)
    if not blob or len(blob)%8 or len(blob)//8>4096:raise RuntimeError('invalid exported BPF size')
    array=(SockFilter*(len(blob)//8)).from_buffer_copy(blob)
    return array,SockFprog(len(array),array),blob


def main():
    guest_guard()
    rules,replies,sequences,logargs,logstr,logmem,log,program=parse(sys.argv[1:])
    if not any(action==NOTIFY for _,action,_ in rules):raise RuntimeError('listener requires a notify rule')
    logpath=Path(BOOTSTRAP_LOG or (HOME/'auth-bootstrap.jsonl')).resolve()
    if not logpath.is_relative_to(HOME):raise RuntimeError('bootstrap log outside private HOME')
    lib=ctypes.CDLL('libseccomp.so.2',use_errno=True)
    lib.seccomp_init.restype=ctypes.c_void_p;lib.seccomp_init.argtypes=[ctypes.c_uint32]
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]
    lib.seccomp_rule_add_array.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(ArgCmp)]
    lib.seccomp_export_bpf.argtypes=[ctypes.c_void_p,ctypes.c_int];lib.seccomp_release.argtypes=[ctypes.c_void_p]
    lib.seccomp_syscall_resolve_num_arch.restype=ctypes.c_void_p
    lib.seccomp_syscall_resolve_num_arch.argtypes=[ctypes.c_uint32,ctypes.c_int]
    filters,prog,blob=exported_filter(lib,rules)
    # The objects and libc entry points needed after seccomp are all resolved
    # before filtering: prctl -> raw seccomp syscall -> fcntl -> sendmsg -> exec.
    libc=ctypes.CDLL(None,use_errno=True);raw_seccomp=libc.syscall;raw_seccomp.restype=ctypes.c_long
    raw_prctl=libc.prctl;raw_prctl.restype=ctypes.c_int
    raw_fcntl=libc.fcntl;raw_fcntl.restype=ctypes.c_int
    raw_sendmsg=libc.sendmsg;raw_sendmsg.argtypes=[ctypes.c_int,ctypes.POINTER(MsgHdr),ctypes.c_int];raw_sendmsg.restype=ctypes.c_ssize_t
    payload=ctypes.create_string_buffer(b'L',1);iov=IOVec(ctypes.addressof(payload),1)
    control=ctypes.create_string_buffer(socket.CMSG_SPACE(ctypes.sizeof(ctypes.c_int)))
    header=CmsgHdr.from_buffer(control);header.length=socket.CMSG_LEN(ctypes.sizeof(ctypes.c_int));header.level=socket.SOL_SOCKET;header.type=socket.SCM_RIGHTS
    fd_cell=ctypes.c_int.from_buffer(control,ctypes.sizeof(CmsgHdr))
    message=MsgHdr(None,0,ctypes.pointer(iov),1,ctypes.addressof(control),len(control),0)
    message_ref=ctypes.byref(message);prog_ref=ctypes.byref(prog)
    nr=ctypes.c_long(317);operation=ctypes.c_ulong(1);new_listener=ctypes.c_ulong(8)
    parent,peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    rfd,wfd=os.pipe2(os.O_CLOEXEC);status=None;child=None
    with logpath.open('w') as bootstrap:
        def emit(stage,**kw):
            bootstrap.write(json.dumps({'stage':stage,**kw},sort_keys=True)+'\n');bootstrap.flush()
        emit('prepared',filter_bytes=len(blob),filter_rules=[x[0] for x in rules],supervisor_pid=os.getpid())
        child=os.fork()
        if child==0:
            try:
                parent.close();os.close(rfd);write=os.write
                write(wfd,b'C')
                if raw_prctl(38,1,0,0,0)!=0:
                    write(wfd,b'N!');os._exit(126)
                write(wfd,b'N')
                listener=raw_seccomp(nr,operation,new_listener,prog_ref)
                if listener<0:
                    write(wfd,b'K!');os._exit(126)
                write(wfd,b'L')
                if raw_fcntl(listener,fcntl.F_SETFD,fcntl.FD_CLOEXEC)<0:
                    write(wfd,b'F!');os._exit(126)
                fd_cell.value=listener;write(wfd,b'S')
                if raw_sendmsg(peer.fileno(),message_ref,0)!=1:
                    write(wfd,b'M!');os._exit(126)
                write(wfd,b'H');write(wfd,b'E')
                os.execv(program[0],program)
            except BaseException:
                try:os.write(wfd,b'X')
                except BaseException:pass
                os._exit(126)
        peer.close();os.close(wfd);os.set_blocking(rfd,False)
        stages=bytearray();listener=None;deadline=time.monotonic()+10;pipe_open=True
        try:
            while listener is None and time.monotonic()<deadline:
                waiting=[parent]+([rfd] if pipe_open else [])
                ready,_,_=select.select(waiting,[],[],max(0,deadline-time.monotonic()))
                if rfd in ready:
                    try:chunk=os.read(rfd,256)
                    except BlockingIOError:chunk=b''
                    if chunk:stages.extend(chunk);emit('child-stages',raw_ascii=chunk.decode('ascii','replace'))
                    else:pipe_open=False
                if parent in ready:
                    _,fds,_,_=socket.recv_fds(parent,16,1)
                    if not fds:raise RuntimeError('listener handoff had no descriptor')
                    listener=fds[0];emit('listener-received',listener_fd=listener,child_pid=child,stages_ascii=stages.decode('ascii','replace'))
            if listener is None:
                emit('listener-timeout',child_pid=child,stages_ascii=stages.decode('ascii','replace'))
                os.kill(child,signal.SIGKILL);os.waitpid(child,0);child=None
                fail('listener bootstrap timed out; inspect '+str(logpath))
            try:
                try:
                    chunk=os.read(rfd,256)
                    if chunk:stages.extend(chunk);emit('child-stages',raw_ascii=chunk.decode('ascii','replace'))
                except BlockingIOError:pass
                status=supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,log)
                child=None;emit('supervision-complete',wait_status=status)
            finally:os.close(listener)
        finally:
            os.close(rfd);parent.close()
            if child is not None:
                try:os.kill(child,signal.SIGKILL)
                except ProcessLookupError:pass
                try:os.waitpid(child,0)
                except ChildProcessError:pass
    sys.exit(os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 128+os.WTERMSIG(status))


if __name__=='__main__':main()
