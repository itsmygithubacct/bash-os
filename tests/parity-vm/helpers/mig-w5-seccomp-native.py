#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent seccomp(2) loader: sets no_new_privs, loads a raw sock_filter file, reports the kernel result."""
import ctypes
import os
import subprocess
import sys

SYS_SECCOMP = 317
SECCOMP_SET_MODE_FILTER = 1
PR_SET_NO_NEW_PRIVS = 38


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def status_field(name):
    for line in open("/proc/self/status"):
        if line.startswith(name + ":"):
            return line.split()[1]
    return "?"


def main():
    path = sys.argv[1]
    data = open(path, "rb").read()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SystemExit("cannot set no_new_privs")
    load = "ok"
    if len(data) % 8 or len(data) // 8 > 65535:
        load = "refused"
    else:
        count = len(data) // 8
        array = (SockFilter * max(count, 1)).from_buffer_copy(data + b"\0" * (8 if count == 0 else 0))
        prog = SockFprog(count, ctypes.cast(array, ctypes.POINTER(SockFilter)))
        ctypes.set_errno(0)
        rc = libc.syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(prog))
        if rc != 0:
            load = "refused"
    sys.stdout.flush()
    uname = subprocess.run(["/usr/bin/uname", "-s"], capture_output=True)
    print("native %s load=%s seccomp=%s filters=%s uname-rc=%d" % (
        os.path.basename(path), load, status_field("Seccomp"), status_field("Seccomp_filters"), uname.returncode))


if __name__ == "__main__":
    main()
