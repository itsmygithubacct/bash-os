#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Observe a real, independently sized record on two explicitly pinned builds.

Run only after kmsg-abi.py --target in an authorized disposable guest. This
reader writes no messages, clears no ring, and never substitutes a device.
Only the accepted kernel target can make this frozen-binary evidence.
"""
import argparse
import errno
import hashlib
import os
from pathlib import Path
import time
import json
import re
from guest import digest, entrypoint, guard, require_bash_5320, run, save

RELEASE = {
    "static": "11e4edf30b60abeab3318fedd5a4052f783d2500576a934b295bca451e5b6308",
    "dynamic": "090c95cd49df3478967c0acb73534d425ed099ba0ef55e5522745d30fec0c039",
}


def inventory(expected):
    fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    count = total = maximum = exact = 0
    deadline = time.monotonic() + 3
    hashes = hashlib.sha256()
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while count < 16384 and total < 4*1024*1024 and time.monotonic() < deadline:
            try:
                record = os.read(fd, 65536)
            except OSError as exc:
                if exc.errno == errno.EAGAIN:
                    return dict(records=count, bytes=total, max_record_bytes=maximum,
                                target_occurrences=exact, stream_sha256=hashes.hexdigest())
                # An overrun or incomplete drain cannot establish this prerequisite.
                raise RuntimeError("incomplete kernel inventory: errno %d" % exc.errno) from exc
            if not record:
                raise RuntimeError("unexpected EOF from /dev/kmsg")
            count += 1; total += len(record)
            maximum = max(maximum, len(record)); exact += record == expected
            hashes.update(len(record).to_bytes(4,"big")); hashes.update(record)
        raise RuntimeError("kernel inventory exceeded its bound")
    finally:
        os.close(fd)


def tagged_lines(observation, marker):
    return [s for s in bytes.fromhex(observation["stdout_hex"]).splitlines(keepends=True) if marker in s]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("seed_report"); p.add_argument("static_shell"); p.add_argument("dynamic_shell")
    p.add_argument("reference_dmesg"); p.add_argument("output")
    p.add_argument("--release",choices=("0.1.3","0.1.4"),default="0.1.3")
    p.add_argument("--static-sha256"); p.add_argument("--dynamic-sha256")
    a = p.parse_args(); guard(root=True)
    hashes = dict(RELEASE)
    if a.release == '0.1.4':
        hashes = {'static':a.static_sha256,'dynamic':a.dynamic_sha256}
        if any(not h or not re.fullmatch('[0-9a-f]{64}',h) for h in hashes.values()):
            raise RuntimeError('0.1.4 requires both reviewed build hashes')
        if any(h in RELEASE.values() for h in hashes.values()):
            raise RuntimeError('a frozen 0.1.3 binary cannot be relabeled as 0.1.4')
    elif a.static_sha256 or a.dynamic_sha256:
        raise RuntimeError('0.1.3 hashes are immutable')
    record_limit = 8192 if a.release == '0.1.3' else 16384
    report = dict(scope="explicitly pinned binaries on the separately identified real kernel",
                  release=a.release,
                  result="ERROR", kernel=os.uname().release, observations=[])
    try:
        for kind, path in (("static",a.static_shell),("dynamic",a.dynamic_shell)):
            if digest(path) != hashes[kind]:
                raise RuntimeError("release hash mismatch: " + kind)
        if a.release == '0.1.4':
            report['bash_versions'] = {kind:require_bash_5320(path) for kind,path in
                                       (('static',a.static_shell),('dynamic',a.dynamic_shell))}
        seed = json.loads(Path(a.seed_report).read_text())
        size = seed.get("target_record_size")
        sizes = (8191,8192) if a.release == '0.1.3' else (8191,8192,8193)
        if seed.get("result") != "OBSERVED" or not seed.get("target_reached") or size not in sizes:
            raise RuntimeError("requires a separately observed real boundary record")
        row = next(r for r in seed["observations"] if r.get("record",{}).get("bytes") == size)
        expected_record = bytes.fromhex(row["record"]["hex"])
        written = bytes.fromhex(row["input_hex"])
        header, sep, message = expected_record.partition(b";")
        if (len(expected_record) != size or not sep or header.split(b",")[0] != b"14" or
                not written.startswith(b"<14>qualification-") or message != written[4:] or
                hashlib.sha256(expected_record).hexdigest() != row["record"]["sha256"] or
                hashlib.sha256(written).hexdigest() != row["input_sha256"]):
            raise RuntimeError("seed report does not describe the required ASCII kernel record")
        marker = message.split(b":",1)[0] + b":"
        report.update(seed_sha256=digest(a.seed_report), target_bytes=size,
                      raw_record_hex=expected_record.hex(), expected_stdout_line_hex=message.hex(),
                      release_sha256=hashes, reference_sha256=digest(a.reference_dmesg))
        before = inventory(expected_record); report["before"] = before
        if before["target_occurrences"] != 1 or before["max_record_bytes"] > record_limit:
            raise RuntimeError("target missing/duplicated or an earlier oversized record would confound the drain")
        cases = (("plain",["-t"], [message]),
                 ("filter_in",["-t","-f","user","-l","info"], [message]),
                 ("filter_out",["-t","-l","emerg"], []))
        for side, shell in (("reference",None),("static",a.static_shell),("dynamic",a.dynamic_shell)):
            for name, args, expected in cases:
                argv = ([a.reference_dmesg] + args) if shell is None else [
                    shell,"--noprofile","--norc","-c",'builtin dmesg "$@"',"qualification"] + args
                observed = run(argv, timeout=20)
                observed.update(side=side, case=name, matches=(observed["status"] == 0 and
                    not observed["stderr_hex"] and tagged_lines(observed,marker) == expected))
                report["observations"].append(observed)
        after = inventory(expected_record); report["after"] = after
        if after["target_occurrences"] != 1 or after["max_record_bytes"] > record_limit:
            raise RuntimeError("kernel target changed or became confounded during observation")
        refs = [r for r in report["observations"] if r["side"] == "reference"]
        candidates = [r for r in report["observations"] if r["side"] != "reference"]
        if not all(r["matches"] for r in refs) or any(r["status"] in (125,126,127) for r in candidates):
            raise RuntimeError("reference or execution prerequisite failed")
        report["result"] = "PASS" if all(r["matches"] for r in candidates) else "FAIL"
        report["by_build"] = {kind:("PASS" if all(r["matches"] for r in candidates if r["side"] == kind)
                                          else "FAIL") for kind in RELEASE}
    except Exception as exc:
        report["error"] = str(exc)
    finally:
        save(a.output, report)
    return {"PASS":0,"FAIL":1,"ERROR":125}[report["result"]]


if __name__ == "__main__": entrypoint(main)
