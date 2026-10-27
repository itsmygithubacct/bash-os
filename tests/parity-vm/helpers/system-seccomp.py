#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Per-side syscall filter for disposable parity-VM fixtures (unprivileged).

Usage: system-seccomp.py [RULE...] -- PROGRAM [ARG...]

Rules (repeatable):
  --kill NAME[:COND]            SIGSYS-kill the whole process if NAME is called.
  --errno NAME:ERRNO[:COND]     make NAME fail with ERRNO (e.g. EIO, ENOTTY or 5).
  --notify NAME[:COND]          stop NAME at a user-notification listener in
                                this helper, which records it and answers.
  --reply NAME=VALUE|ERRNO      answer for notified NAME: an integer return
                                value, an errno name, or "continue" (the
                                default: let the kernel run the real call).
  --log FILE                    append one JSON line per notified call.
  --log-args NAME=I[,J]         record these integer arguments (masked 32-bit
                                unless suffixed with "q") for notified NAME.
  --log-string NAME=I           record argument I as a NUL-terminated string
                                read from the caller (at most 4096 bytes).
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
    sys.stderr.write("system-seccomp: " + message + "\n")
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


def parse(argv):
    rules, replies, logargs, logstr, log = [], {}, {}, {}, None
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
            name, _, answer = value.partition("=")
            if answer == "continue":
                replies[name] = ("continue", 0)
            elif answer.lstrip("-").isdigit():
                replies[name] = ("value", int(answer))
            else:
                replies[name] = ("errno", parse_errno(answer))
        elif option == "--log":
            log = value
        elif option == "--log-args":
            name, _, indexes = value.partition("=")
            logargs[name] = [(int(x.rstrip("q")), x.endswith("q")) for x in indexes.split(",") if x]
        elif option == "--log-string":
            name, _, index = value.partition("=")
            logstr[name] = int(index)
        else:
            fail("unknown option: " + option)
    if i >= len(argv) or i + 1 >= len(argv):
        fail("missing -- PROGRAM")
    return rules, replies, logargs, logstr, log, argv[i + 1:]


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


def supervise(lib, listener, child, replies, logargs, logstr, log):
    handle = open(log, "a") if log else None
    status = None
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


def main():
    rules, replies, logargs, logstr, log, program = parse(sys.argv[1:])
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                           ctypes.c_uint, ctypes.POINTER(ArgCmp)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_notify_fd.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_num_arch.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_num_arch.argtypes = [ctypes.c_uint32, ctypes.c_int]
    notifying = any(action == NOTIFY for _, action, _ in rules)
    parent, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    child = os.fork()
    if child == 0:
        try:
            parent.close()
            ctx = install(lib, rules)
            if notifying:
                listener = lib.seccomp_notify_fd(ctx)
                # No close() between filter load and exec: a notified close
                # would be recorded. Python descriptors are close-on-exec.
                os.set_inheritable(listener, False)
                socket.send_fds(peer, [b"L"], [listener])
            os.execv(program[0], program)
        except BaseException as exc:  # never return into the parent's code
            sys.stderr.write("system-seccomp: %s\n" % exc)
        os._exit(126)
    peer.close()
    if notifying:
        ready, _, _ = select.select([parent], [], [], 10)
        if not ready:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            fail("child did not install the filter")
        _, fds, _, _ = socket.recv_fds(parent, 16, 1)
        if not fds:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            fail("no listener descriptor")
        status = supervise(lib, fds[0], child, replies, logargs, logstr, log)
        os.close(fds[0])
    else:
        status = os.waitpid(child, 0)[1]
    parent.close()
    sys.exit(os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))


if __name__ == "__main__":
    main()
