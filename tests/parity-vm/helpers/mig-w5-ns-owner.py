#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Namespace ownership observations through the kernel's NS_GET_USERNS ioctl."""
import fcntl
import os
import sys

NS_GET_USERNS = 0xB701


def owner(fd):
    try:
        handle = fcntl.ioctl(fd, NS_GET_USERNS, 0)
    except OSError as exc:
        return "errno=%d" % exc.errno
    try:
        return str(os.fstat(handle).st_ino)
    finally:
        os.close(handle)


def main():
    if len(sys.argv) != 3 or sys.argv[1] != "owner":
        raise SystemExit("usage: mig-w5-ns-owner.py owner FD")
    fd = int(sys.argv[2])
    own_user = os.open("/proc/self/ns/user", os.O_RDONLY)
    try:
        print("ns-ino=%d" % os.fstat(fd).st_ino)
        print("owner-ino=%s" % owner(fd))
        print("self-user-ino=%d" % os.fstat(own_user).st_ino)
        print("self-user-owner=%s" % owner(own_user))
    finally:
        os.close(own_user)


if __name__ == "__main__":
    main()
