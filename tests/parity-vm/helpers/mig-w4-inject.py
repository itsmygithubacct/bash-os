#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run a command under a seccomp filter that fails chosen x86-64 syscalls with an errno.

usage: mig-w4-inject.py NAME:ERRNO[,NAME:ERRNO...] -- COMMAND [ARG...]

The filter is installed with PR_SET_NO_NEW_PRIVS and SECCOMP_MODE_FILTER and is inherited
by every descendant of COMMAND, so a privileged candidate that forks a child before a
credential change sees a real kernel failure at the chosen call. Unlisted syscalls are
allowed; a non-x86-64 architecture is refused. Used only inside the disposable guest.
"""
import ctypes
import os
import platform
import struct
import sys

NUMBERS = {"setuid": 105, "setgid": 106, "setreuid": 113, "setregid": 114, "setgroups": 116,
           "setresuid": 117, "setresgid": 119, "setfsuid": 122, "setfsgid": 123}
ERRNOS = {"EPERM": 1, "EAGAIN": 11, "EINVAL": 22, "ENOMEM": 12}
AUDIT_ARCH_X86_64 = 0xC000003E
BPF_LD_W_ABS, BPF_JEQ_K, BPF_RET_K = 0x20, 0x15, 0x06
SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO = 0x80000000, 0x7FFF0000, 0x00050000


def insn(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


def main(argv):
    if len(argv) < 4 or argv[2] != "--" or platform.machine() != "x86_64":
        sys.stderr.write(__doc__)
        return 2
    rules = []
    for item in argv[1].split(","):
        name, _, err = item.partition(":")
        rules.append((NUMBERS[name], int(err) if err.isdigit() else ERRNOS[err or "EPERM"]))
    prog = [insn(BPF_LD_W_ABS, 0, 0, 4), insn(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
            insn(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS), insn(BPF_LD_W_ABS, 0, 0, 0)]
    for number, err in rules:
        prog += [insn(BPF_JEQ_K, 0, 1, number), insn(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | err)]
    prog.append(insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    blob = b"".join(prog)
    buf = ctypes.create_string_buffer(blob, len(blob))
    fprog = struct.pack("HxxxxxxP", len(prog), ctypes.addressof(buf))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
    holder = ctypes.create_string_buffer(fprog, len(fprog))
    if libc.prctl(22, 2, ctypes.addressof(holder), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP")
    os.execv(argv[3], argv[3:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
