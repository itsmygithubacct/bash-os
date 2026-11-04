#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic decoder controls, explicitly separate from real kernel framing."""
import argparse
import errno
from guest import digest, entrypoint, guard, run, save


def main():
    p = argparse.ArgumentParser(); p.add_argument("probe"); p.add_argument("output")
    a = p.parse_args(); guard()
    rows = []
    for size, mode in ((8191,"plain"),(8192,"plain"),(8193,"plain"),(65536,"plain"),
                       (65537,"plain"),(8192,"retry"),(8192,"fatal")):
        r = run([a.probe,str(size),mode])
        success = size <= 65536 and mode != "fatal"
        expected = (b"A"*(size-len(b"14,1,1000000,-;")-1)+b"\n") if success else b""
        trace = bytes.fromhex(r["stderr_hex"])
        expected_reads = (["read count=65536 errno=%d" % e for e in (errno.EINTR,errno.EPIPE)]
                          if mode == "retry" else [])
        if success:
            expected_reads += ["read count=65536 returned=%d" % size,
                               "read count=65536 errno=%d" % errno.EAGAIN]
        else:
            expected_reads += ["read count=65536 errno=%d" % (errno.EIO if mode == "fatal" else errno.EINVAL)]
        lines = trace.splitlines()
        actual_reads = [s for s in lines if s.startswith(b"read ")]
        footer = "result=%d emitted=%d reads=%d" % (0 if success else 1,int(success),len(expected_reads))
        # Exact calls, payload, and emitted count establish what was exercised.
        shape = (actual_reads == [s.encode() for s in expected_reads] and
                 bool(lines) and lines[-1] == footer.encode() and
                 any(s.startswith(b"diagnostic: read /dev/kmsg: ") for s in lines) == (not success))
        r.update(size=size,mode=mode,matches=(shape and r["status"] == (0 if success else 1) and r["stdout_hex"] == expected.hex()))
        rows.append(r)
    result = "PASS" if all(r["matches"] for r in rows) else "FAIL"
    if any(r["status"] in (125,126,127) for r in rows): result = "ERROR"
    save(a.output,dict(scope="0.1.4 decoder with synthetic read returns; no live-kernel claim",
                       result=result,binary_sha256=digest(a.probe),observations=rows))
    return {"PASS":0,"FAIL":1,"ERROR":125}[result]


if __name__ == "__main__": entrypoint(main)
