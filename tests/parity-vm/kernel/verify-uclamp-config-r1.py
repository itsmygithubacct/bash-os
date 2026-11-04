#!/usr/bin/env python3
"""Data-only check of the merged bootable profile and inherited capabilities."""
import json
import re
import sys
from pathlib import Path


def config(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if re.fullmatch(r"CONFIG_\w+=.*", line):
            key, value = line.split("=", 1)
            values[key] = value
        elif re.fullmatch(r"# CONFIG_\w+ is not set", line):
            values[line.split()[1]] = "n"
    return values


def verify(base, actual, fragment):
    errors = []
    for key, value in fragment.items():
        if actual.get(key, "n") != value:
            errors.append(f"fragment mismatch: {key} expected {value}")
    # Do not silently strip the qualified cloud kernel into a test-only kernel.
    for key, value in base.items():
        if value in ("y", "m") and key not in fragment:
            if actual.get(key) not in ({"y"} if value == "y" else {"y", "m"}):
                errors.append(f"inherited capability lost: {key}={value}")
    required = "64BIT X86_64 SMP MULTIUSER FUTEX EPOLL SIGNALFD TIMERFD EVENTFD UNIX INET NET NAMESPACES UTS_NS IPC_NS USER_NS PID_NS NET_NS CGROUPS CGROUP_PIDS CGROUP_SCHED FAIR_GROUP_SCHED SECCOMP SECCOMP_FILTER PROC_FS SYSFS TMPFS TMPFS_POSIX_ACL UNIX98_PTYS DEVTMPFS BINFMT_ELF BINFMT_SCRIPT BLK_DEV_INITRD RD_GZIP RD_XZ RD_ZSTD PCI VIRTIO VIRTIO_PCI EXT4_FS SERIAL_8250 SERIAL_8250_CONSOLE DMI SYSCTL PROC_SYSCTL CHECKPOINT_RESTORE".split()
    for name in required:
        if actual.get("CONFIG_" + name) != "y":
            errors.append("missing built-in prerequisite: CONFIG_" + name)
    for name in ("VIRTIO_BLK", "VIRTIO_NET", "OVERLAY_FS"):
        if actual.get("CONFIG_" + name) not in ("y", "m"):
            errors.append("missing boot/runtime prerequisite: CONFIG_" + name)
    if actual.get("CONFIG_UCLAMP_TASK_GROUP") != "y":
        errors.append("task group clamp profile unavailable")
    return errors


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: verify-uclamp-config-r1.py BASE CONFIG FRAGMENT")
    problems = verify(*(config(p) for p in sys.argv[1:]))
    print(json.dumps({"profile": "uclamp-r1", "errors": problems}, sort_keys=True))
    raise SystemExit(1 if problems else 0)
