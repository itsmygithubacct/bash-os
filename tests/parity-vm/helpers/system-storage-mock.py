#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Syscall-contract mock for storage builtins in disposable parity-VM fixtures.

Builds on system-seccomp.py (same directory, imported unchanged) and adds
what block-device ioctl contracts need. Everything here is unprivileged: the
filter is installed with no_new_privs, and the supervisor only answers calls
made by its own child. A replied call never reaches the kernel, so results
from this helper are syscall-contract observations, never kernel effects.

Usage: system-storage-mock.py [RULE...] -- PROGRAM [ARG...]

  --notify NAME[:COND]       stop matching calls at this supervisor (COND as
                             in system-seccomp.py, e.g. ioctl:1=0x4c00).
  --kill NAME[:COND]         SIGSYS-kill the process on a matching call.
  --errno NAME:ERRNO[:COND]  fail matching calls in the kernel filter.
  --reply KEY=A[,B...]       successive answers for notified KEY; the last one
                             repeats. KEY is NAME or NAME:REQ (REQ compared
                             with the low 32 bits of argument 1, for ioctl).
                             An answer is "continue", an integer return
                             value, or an errno name/number.
  --write KEY=ARG:HEX        before answering KEY with a value, write the
                             bytes HEX at the address in argument ARG.
  --log FILE                 append one JSON line per recorded call.
  --log-args KEY=I[,J]       record these arguments (low 32 bits; "q" suffix
                             for all 64 bits).
  --log-mem KEY=ARG:LEN      record LEN bytes at the address in ARG as hex,
                             read before answering.
  --log-string KEY=I         record argument I as a NUL-terminated string.
  --fake-open PATH=STANDIN   when a notified open/openat names exactly PATH,
                             open STANDIN (relative to the helper's cwd) with
                             the caller's access mode and install that
                             descriptor as the call's result (SECCOMP ADDFD).
                             Other opens continue unchanged in the kernel.

A call is recorded when its KEY has a reply, write, log or fake-open entry.
Records hold only the configured fields, so logs are deterministic when the
fixture's inputs are. Exit status is PROGRAM's, or 128+signal.
"""
import ctypes
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys

spec = importlib.util.spec_from_file_location("system_seccomp", Path(__file__).with_name("system-seccomp.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

NOTIF_ADDFD = 0x40182103     # _IOW('!', 3, struct seccomp_notif_addfd), 24 bytes
ADDFD_FLAG_SEND = 2
O_ACCMODE = 3


def key_of(text):
    name, _, req = text.partition(":")
    return (name, int(req, 0) & 0xffffffff) if req else (name, None)


def answer(text):
    if text == "continue":
        return ("continue", 0)
    if text.lstrip("-").isdigit():
        return ("value", int(text))
    return ("errno", base.parse_errno(text))


def parse(argv):
    rules, cfg = [], {"reply": {}, "write": {}, "args": {}, "mem": {}, "string": {}, "fake": {}, "log": None}
    i = 0
    while i < len(argv) and argv[i] != "--":
        option = argv[i]
        if i + 1 >= len(argv):
            base.fail("missing value for " + option)
        value = argv[i + 1]
        i += 2
        if option in ("--kill", "--notify"):
            name, _, cond = value.partition(":")
            rules.append((name, base.KILL_PROCESS if option == "--kill" else base.NOTIFY, base.parse_cond(cond)))
        elif option == "--errno":
            parts = value.split(":", 2)
            if len(parts) < 2:
                base.fail("--errno needs NAME:ERRNO")
            rules.append((parts[0], 0x00050000 | (base.parse_errno(parts[1]) & 0xffff),
                          base.parse_cond(parts[2] if len(parts) > 2 else "")))
        elif option == "--log":
            cfg["log"] = value
        elif option == "--fake-open":
            path, _, standin = value.partition("=")
            if not path or not standin:
                base.fail("--fake-open needs PATH=STANDIN")
            cfg["fake"][path] = standin
        elif option in ("--reply", "--write", "--log-args", "--log-mem", "--log-string"):
            key, _, rest = value.partition("=")
            key = key_of(key)
            if option == "--reply":
                cfg["reply"][key] = [answer(x) for x in rest.split(",") if x]
            elif option == "--write":
                index, _, data = rest.partition(":")
                cfg["write"][key] = (int(index), bytes.fromhex(data))
            elif option == "--log-args":
                cfg["args"][key] = [(int(x.rstrip("q")), x.endswith("q")) for x in rest.split(",") if x]
            elif option == "--log-mem":
                index, _, length = rest.partition(":")
                cfg["mem"][key] = (int(index), int(length, 0))
            else:
                cfg["string"][key] = int(rest)
        else:
            base.fail("unknown option: " + option)
    if i + 1 >= len(argv):
        base.fail("missing -- PROGRAM")
    if not any(action == base.NOTIFY for _, action, _ in rules):
        base.fail("system-storage-mock needs at least one --notify rule")
    return rules, cfg, argv[i + 1:]


def lookup(table, name, req):
    if (name, req) in table:
        return (name, req)
    if (name, None) in table:
        return (name, None)
    return None


def memory(pid, address, length=None, data=None):
    with open("/proc/%d/mem" % pid, "r+b" if data is not None else "rb", buffering=0) as mem:
        mem.seek(address)
        if data is not None:
            mem.write(data)
            return None
        return mem.read(length)


def supervise(lib, listener, child, cfg):
    handle = open(cfg["log"], "a") if cfg["log"] else None
    used = {}
    status = None
    try:
        while status is None:
            ready, _, _ = select.select([listener], [], [], 0.05)
            if ready:
                request = bytearray(80)
                try:
                    fcntl.ioctl(listener, base.NOTIF_RECV, request, True)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.EINTR):
                        continue
                    raise
                ident, pid, _flags, nr, _arch, _ip = struct.unpack_from("<QIIiIQ", request)
                args = struct.unpack_from("<6Q", request, 32)
                raw = lib.seccomp_syscall_resolve_num_arch(0, nr)
                name = ctypes.cast(raw, ctypes.c_char_p).value.decode() if raw else str(nr)
                req = args[1] & 0xffffffff
                record = {"syscall": name}
                if name == "ioctl":
                    record["request"] = "0x%x" % req
                kind, value, recorded = "continue", 0, False
                if name in ("open", "openat") and cfg["fake"]:
                    path_arg = 0 if name == "open" else 1
                    try:
                        path = memory(pid, args[path_arg], 4096).split(b"\0", 1)[0].decode("utf-8", "surrogateescape")
                    except OSError:
                        path = None
                    if path in cfg["fake"]:
                        record["path"] = path
                        flags = args[path_arg + 1]
                        mode = (os.O_RDONLY, os.O_WRONLY, os.O_RDWR)[flags & O_ACCMODE] if flags & O_ACCMODE < 3 else os.O_RDWR
                        try:
                            standin = os.open(cfg["fake"][path], mode | os.O_CLOEXEC)
                        except OSError as exc:
                            kind, value = "errno", exc.errno
                            record["reply"] = "errno:%d" % exc.errno
                        else:
                            addfd = struct.pack("<QIIII", ident, ADDFD_FLAG_SEND, standin, 0,
                                                os.O_CLOEXEC if flags & os.O_CLOEXEC else 0)
                            try:
                                fcntl.ioctl(listener, NOTIF_ADDFD, addfd)
                                record["reply"] = "standin:" + cfg["fake"][path]
                                kind = "sent"
                            except OSError as exc:
                                if exc.errno != errno.ENOENT:
                                    raise
                                kind = "sent"
                            os.close(standin)
                        recorded = True
                key = lookup(cfg["args"], name, req)
                if key:
                    for index, wide in cfg["args"][key]:
                        record["arg%d" % index] = args[index] if wide else args[index] & 0xffffffff
                    recorded = True
                key = lookup(cfg["string"], name, req)
                if key:
                    index = cfg["string"][key]
                    try:
                        record["string%d" % index] = memory(pid, args[index], 4096).split(b"\0", 1)[0].decode(
                            "utf-8", "backslashreplace")
                    except OSError as exc:
                        record["string%d" % index] = {"unreadable": exc.strerror}
                    recorded = True
                key = lookup(cfg["mem"], name, req)
                if key:
                    index, length = cfg["mem"][key]
                    try:
                        record["mem%d" % index] = memory(pid, args[index], length).hex()
                    except OSError as exc:
                        record["mem%d" % index] = {"unreadable": exc.strerror}
                    recorded = True
                if kind != "sent":
                    key = lookup(cfg["reply"], name, req)
                    if key:
                        sequence = cfg["reply"][key]
                        position = used.get(key, 0)
                        kind, value = sequence[min(position, len(sequence) - 1)]
                        used[key] = position + 1
                        recorded = True
                    write = lookup(cfg["write"], name, req)
                    if write and kind == "value":
                        index, data = cfg["write"][write]
                        memory(pid, args[index], data=data)
                        record["wrote%d" % index] = data.hex()
                        recorded = True
                    if "reply" not in record:
                        record["reply"] = kind if kind == "continue" else "%s:%d" % (kind, value)
                    if kind == "continue":
                        response = struct.pack("<QqiI", ident, 0, 0, base.FLAG_CONTINUE)
                    elif kind == "value":
                        response = struct.pack("<QqiI", ident, value, 0, 0)
                    else:
                        response = struct.pack("<QqiI", ident, 0, -value, 0)
                    try:
                        fcntl.ioctl(listener, base.NOTIF_SEND, response)
                    except OSError as exc:
                        if exc.errno != errno.ENOENT:
                            raise
                if recorded and handle:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
                    handle.flush()
            done, wait = os.waitpid(child, os.WNOHANG)
            if done:
                status = wait
    finally:
        if handle:
            handle.close()
        if status is None:
            os.kill(child, signal.SIGKILL)
            status = os.waitpid(child, 0)[1]
    return status


def main():
    rules, cfg, program = parse(sys.argv[1:])
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                           ctypes.c_uint, ctypes.POINTER(base.ArgCmp)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_notify_fd.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_num_arch.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_num_arch.argtypes = [ctypes.c_uint32, ctypes.c_int]
    parent, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    child = os.fork()
    if child == 0:
        try:
            parent.close()
            ctx = base.install(lib, rules)
            listener = lib.seccomp_notify_fd(ctx)
            os.set_inheritable(listener, False)
            socket.send_fds(peer, [b"L"], [listener])
            os.execv(program[0], program)
        except BaseException as exc:
            sys.stderr.write("system-storage-mock: %s\n" % exc)
        os._exit(126)
    peer.close()
    ready, _, _ = select.select([parent], [], [], 10)
    fds = socket.recv_fds(parent, 16, 1)[1] if ready else []
    if not fds:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        base.fail("child did not install the filter")
    status = supervise(lib, fds[0], child, cfg)
    os.close(fds[0])
    parent.close()
    sys.exit(os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))


if __name__ == "__main__":
    main()
