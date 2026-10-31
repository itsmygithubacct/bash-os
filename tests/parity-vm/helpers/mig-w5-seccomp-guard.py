#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run a command under a seccomp filter that kills the process on any socket-creating or sending syscall."""
import ctypes
import os
import struct
import sys

PR_SET_NO_NEW_PRIVS = 38
SYS_SECCOMP = 317
AUDIT_ARCH_X86_64 = 0xC000003E
KILL_PROCESS = 0x80000000
ALLOW = 0x7FFF0000
# x86_64: socket connect accept sendto sendmsg bind listen socketpair accept4 sendmmsg
BLOCKED = (41, 42, 43, 44, 46, 49, 50, 53, 288, 307)


def ins(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


def program():
    out = [ins(0x20, 0, 0, 4),                       # ld arch
           ins(0x15, 1, 0, AUDIT_ARCH_X86_64),       # jeq x86_64 -> skip kill
           ins(0x06, 0, 0, KILL_PROCESS),
           ins(0x20, 0, 0, 0)]                       # ld nr
    for index, number in enumerate(BLOCKED):
        remaining = len(BLOCKED) - index - 1
        out.append(ins(0x15, remaining + 1, 0, number))   # equal: jump to the kill return
    out.append(ins(0x06, 0, 0, ALLOW))
    out.append(ins(0x06, 0, 0, KILL_PROCESS))
    return b"".join(out)


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        raise SystemExit("usage: mig-w5-seccomp-guard.py -- COMMAND [ARG...]")
    libc = ctypes.CDLL(None, use_errno=True)
    data = program()
    count = len(data) // 8
    array = ctypes.create_string_buffer(data, len(data))

    class Fprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    prog = Fprog(count, ctypes.cast(array, ctypes.c_void_p))
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SystemExit("no_new_privs failed")
    if libc.syscall(SYS_SECCOMP, 1, 0, ctypes.byref(prog)) != 0:
        raise SystemExit("seccomp failed: errno %d" % ctypes.get_errno())
    os.execv(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    main()
