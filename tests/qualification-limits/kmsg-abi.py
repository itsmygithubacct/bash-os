#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded real /dev/kmsg prerequisite observer. Disposable guest root only.

No clear, console-level, sysctl, or module operations. These are real kernel
observations, not product PASS/FAIL. --target requires a separately qualified
kernel capable of the requested record size; it never fakes a kernel record.
"""
import argparse
import errno
import hashlib
import os
from pathlib import Path
import time
import uuid
from guest import entrypoint, guard, save


def receive(fd, tag):
    deadline = time.monotonic() + 2
    errors, seen = [], 0
    while time.monotonic() < deadline and seen < 4096 and len(errors) < 8:
        try:
            raw = os.read(fd,65536); seen += 1
            if tag in raw.partition(b";")[2]:
                return dict(hex=raw.hex(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),errors=errors)
        except BlockingIOError:
            time.sleep(.02)
        except OSError as e:
            errors.append(e.errno)
            if e.errno not in (errno.EPIPE,errno.EINTR): break
    return dict(hex=None,errors=errors,reason="tag not observed within bounded drain")


def main():
    p = argparse.ArgumentParser(); p.add_argument("output")
    p.add_argument("--target",type=int,choices=(8191,8192,8193))
    a = p.parse_args(); guard(root=True)
    tag = ("qualification-" + uuid.uuid4().hex).encode()
    rows = []
    # Each run uses at most eight writes, no rate-limit setting changes.
    reader = writer = small = None
    report = dict(scope="real-kernel prerequisites only",result="ERROR",kernel=os.uname().release,observations=rows)
    try:
        reader = os.open("/dev/kmsg",os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
        small = os.open("/dev/kmsg",os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
        writer = os.open("/dev/kmsg",os.O_WRONLY|os.O_CLOEXEC)
        os.lseek(reader,0,os.SEEK_END); os.lseek(small,0,os.SEEK_END)
        sizes = [128,900,976,992,1024,8191,8192,8193] if a.target is None else [a.target-32]*8
        reached = False
        for index, write_size in enumerate(sizes):
            marker = tag + ("-%d:" % index).encode()
            head = b"<14>"+marker
            # Escaping can expand wire size without increasing stored text size.
            fill = b"\\" if a.target is None and index == 1 else b"A"
            payload = head + fill*(write_size-len(head)-1)+b"\n"
            if len(payload) != write_size or not 64 <= write_size <= 16384:
                raise RuntimeError("calibration left its bounded input domain")
            row = dict(write_bytes=len(payload),input_sha256=hashlib.sha256(payload).hexdigest(),input_hex=payload.hex())
            rows.append(row)
            try: row["write_result"] = os.write(writer,payload)
            except OSError as e: row["write_errno"] = e.errno
            if row.get("write_result") == len(payload):
                row["record"] = receive(reader,marker)
                if row["record"]["hex"] is None:
                    report["reason"] = "successful write not observed; possible rate limit/truncation/setup gap"; break
                if index == 0:
                    try: row["one_byte_read_hex"] = os.read(small,1).hex()
                    except OSError as e: row["one_byte_read_errno"] = e.errno
                    # This may already have consumed the record on the target kernel.
                    try: row["small_reader_next_hex"] = os.read(small,65536).hex()
                    except OSError as e: row["small_reader_next_errno"] = e.errno
                if a.target:
                    actual = row["record"]["bytes"]
                    if actual == a.target: reached = True; break
                    if index+1 < len(sizes): sizes[index+1] = write_size+a.target-actual
            elif a.target or index == 0:
                report["reason"] = "kernel rejected the positive control/calibration input"; break
        else:
            if a.target is None: report["result"] = "OBSERVED"
        if a.target:
            report.update(target_record_size=a.target,target_reached=reached,
                          result="OBSERVED" if reached else "ERROR")
        report["max_record_bytes"] = max((r.get("record",{}).get("bytes",0) for r in rows),default=0)
        report["read_at_8192_prerequisite"] = any(r.get("record",{}).get("bytes") in (8191,8192,8193) for r in rows)
    finally:
        for fd in (reader,writer,small):
            if fd is not None: os.close(fd)
        save(a.output,report)
    return 0 if report["result"] == "OBSERVED" else 125


if __name__ == "__main__": entrypoint(main)
