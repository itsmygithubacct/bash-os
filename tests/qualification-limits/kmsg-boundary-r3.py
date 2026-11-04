#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Observe a real, independently sized record on two explicitly pinned builds.

Run only after kmsg-abi.py --target in an authorized disposable guest. This
reader writes no messages, clears no ring, and never substitutes a device.
This r3 observer accepts only new 0.1.4 builds. The raw-byte oracle is a
separate explicit review choice; it never invokes a changed utility as stock.
"""
import argparse
import errno
import hashlib
import os
from pathlib import Path
import time
import json
import re
import stat
import gzip
from guest import digest, entrypoint, guard, require_bash_5320, run, save

RELEASE = {
    "static": "11e4edf30b60abeab3318fedd5a4052f783d2500576a934b295bca451e5b6308",
    "dynamic": "090c95cd49df3478967c0acb73534d425ed099ba0ef55e5522745d30fec0c039",
}


def inventory(expected):
    fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISCHR(st.st_mode) or (os.major(st.st_rdev), os.minor(st.st_rdev)) != (1,11):
        os.close(fd)
        raise RuntimeError("requires the real kernel kmsg character device")
    marker = expected.partition(b";")[2].split(b":",1)[0] + b":"
    count = total = maximum = exact = marked = 0
    deadline = time.monotonic() + 3
    hashes = hashlib.sha256()
    try:
        os.lseek(fd, 0, os.SEEK_DATA)
        while count < 16384 and total < 4*1024*1024 and time.monotonic() < deadline:
            try:
                record = os.read(fd, 65536)
            except OSError as exc:
                if exc.errno == errno.EAGAIN:
                    return dict(records=count, bytes=total, max_record_bytes=maximum,
                                target_occurrences=exact, marker_occurrences=marked, start_seek="SEEK_DATA",
                                stream_sha256=hashes.hexdigest())
                # An overrun or incomplete drain cannot establish this prerequisite.
                raise RuntimeError("incomplete kernel inventory: errno %d" % exc.errno) from exc
            if not record:
                raise RuntimeError("unexpected EOF from /dev/kmsg")
            count += 1; total += len(record)
            maximum = max(maximum, len(record)); exact += record == expected
            marked += marker in record.partition(b";")[2]
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
    p.add_argument("--release", choices=("0.1.4",), default="0.1.4")
    p.add_argument("--oracle", choices=("util-linux", "raw-bytes"), required=True)
    p.add_argument("--kernel-manifest", required=True)
    p.add_argument("--kernel-manifest-sha256", required=True)
    p.add_argument("--reference-sha256")
    p.add_argument("--static-sha256"); p.add_argument("--dynamic-sha256")
    a = p.parse_args(); guard(root=True)
    if digest(a.kernel_manifest) != a.kernel_manifest_sha256:
        raise RuntimeError("reviewed kernel manifest hash differs")
    receipt = json.loads(Path(a.kernel_manifest).read_text())
    release = receipt.get("kernel_release", "")
    if (not re.fullmatch(r"6\.12\.113[-+][A-Za-z0-9_.+-]+", release) or
            release != os.uname().release or "+deb13" in release or
            release == "6.12.113-clamp-parity-r1" or
            receipt.get("source_deb_sha256") != "6ad4a0316ddefced87cef8cd9a25a268e0cdfe0a10adc5148401f49f90b336b5"):
        raise RuntimeError("requires the reviewed distinct Debian 6.12.113-1 derivative")
    config_hash = receipt.get("config_sha256", "")
    image_hash = receipt.get("kernel_image_sha256") or receipt.get("files",{}).get("boot/vmlinuz-" + release, "")
    if any(not re.fullmatch("[0-9a-f]{64}", h) for h in (config_hash,image_hash)):
        raise RuntimeError("kernel manifest lacks final config/image hashes")
    if (digest("/boot/config-" + release) != config_hash or
            digest("/boot/vmlinuz-" + release) != image_hash or
            hashlib.sha256(gzip.decompress(Path("/proc/config.gz").read_bytes())).hexdigest() != config_hash):
        raise RuntimeError("installed/embedded kernel config or installed image differs")
    if a.oracle == "raw-bytes":
        if a.reference_dmesg != "-" or a.reference_sha256:
            raise RuntimeError("raw-byte mode requires - and no utility reference pin")
    elif (not a.reference_sha256 or
          not re.fullmatch("[0-9a-f]{64}", a.reference_sha256) or
          digest(a.reference_dmesg) != a.reference_sha256):
        raise RuntimeError("utility mode requires the reviewed modified reference hash")
    hashes = dict(RELEASE)
    if a.release == '0.1.4':
        hashes = {'static':a.static_sha256,'dynamic':a.dynamic_sha256}
        if any(not h or not re.fullmatch('[0-9a-f]{64}',h) for h in hashes.values()):
            raise RuntimeError('0.1.4 requires both reviewed build hashes')
        if any(h in RELEASE.values() for h in hashes.values()):
            raise RuntimeError('a frozen 0.1.3 binary cannot be relabeled as 0.1.4')
    record_limit = 16384
    report = dict(scope="explicitly pinned binaries on the separately identified real kernel",
                  release=a.release, oracle=a.oracle,
                  kernel_manifest_sha256=digest(a.kernel_manifest),
                  kernel_manifest_header={k:v for k,v in receipt.items() if k != "files"},
                  kernel_config_sha256=config_hash, kernel_image_sha256=image_hash,
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
        sizes = (8191,8192,8193)
        if (seed.get("result") != "OBSERVED" or not seed.get("target_reached") or
                seed.get("kernel") != os.uname().release or size not in sizes):
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
        if (not re.fullmatch(rb"14,[0-9]+,[0-9]+,-", header) or
                not message.endswith(b"\n") or
                any(c < 32 or c > 126 for c in message[:-1])):
            raise RuntimeError("raw oracle requires one printable ASCII message and a canonical kernel header")
        # The kernel raw bytes and independent submitted ASCII payload agree;
        # facility=(14 >> 3)=user and level=(14 & 7)=info, independently of dmesg.
        marker = message.split(b":",1)[0] + b":"
        report.update(seed_sha256=digest(a.seed_report), target_bytes=size,
                      raw_record_hex=expected_record.hex(), expected_stdout_line_hex=message.hex(),
                      release_sha256=hashes, reference_sha256=(digest(a.reference_dmesg) if a.oracle == "util-linux" else None),
                      independent_oracle="actual /dev/kmsg framing, submitted ASCII bytes, priority14=user/info")
        before = inventory(expected_record); report["before"] = before
        if before["target_occurrences"] != 1 or before["marker_occurrences"] != 1 or before["max_record_bytes"] > record_limit:
            raise RuntimeError("target missing/duplicated or an earlier oversized record would confound the drain")
        cases = (("plain",["-t"], [message]),
                 ("filter_in",["-t","-f","user","-l","info"], [message]),
                 ("filter_out",["-t","-l","emerg"], []))
        sides = [("static",a.static_shell),("dynamic",a.dynamic_shell)]
        if a.oracle == "util-linux": sides.insert(0,("reference",None))
        for side, shell in sides:
            for name, args, expected in cases:
                argv = ([a.reference_dmesg] + args) if shell is None else [
                    shell,"--noprofile","--norc","-c",'builtin dmesg "$@"',"qualification"] + args
                observed = run(argv, timeout=20)
                observed.update(side=side, case=name, matches=(observed["status"] == 0 and
                    not observed["stderr_hex"] and tagged_lines(observed,marker) == expected))
                report["observations"].append(observed)
        after = inventory(expected_record); report["after"] = after
        if after["target_occurrences"] != 1 or after["marker_occurrences"] != 1 or after["max_record_bytes"] > record_limit:
            raise RuntimeError("kernel target changed or became confounded during observation")
        refs = [r for r in report["observations"] if r["side"] == "reference"]
        candidates = [r for r in report["observations"] if r["side"] != "reference"]
        if (a.oracle == "util-linux" and (len(refs) != 3 or not all(r["matches"] for r in refs))) or any(r["status"] in (125,126,127) for r in candidates):
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
