#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only controls for the original apropos query requirements.

Raw streams are retained. Only presentation spacing and grouping of distinct
aliases for the same source page are normalized in successful query results.
No-match cases bypass this parser and compare raw channels in the VM harness.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import uuid


PAGES = {
    "alpha": {"names": ["alpha", "aleph"], "description": "first apple"},
    "alpha-x": {"names": ["alpha-x"], "description": "longer name"},
    "beta": {"names": ["beta"], "description": "second berry"},
    "both": {"names": ["both"], "description": "alpha and beta together"},
    "dash": {"names": ["dash"], "description": "option -x feature"},
}
QUERIES = {
    "regex-dot": {"argv": ["--", "al.ha"], "pages": ["alpha", "alpha-x", "both"]},
    "regex-anchor": {"argv": ["--", "^alp"], "pages": ["alpha", "alpha-x", "both"]},
    "regex-alias-anchor": {"argv": ["--", "^aleph$"], "pages": ["alpha"]},
    "default-or": {"argv": ["--", "alpha", "beta"], "pages": ["alpha", "alpha-x", "beta", "both"]},
    "explicit-and": {"argv": ["-a", "--", "alpha", "beta"], "pages": ["both"]},
    "long-and": {"argv": ["--and", "--", "alpha", "beta"], "pages": ["both"]},
    "whole-alias": {"argv": ["-w", "--", "aleph"], "pages": ["alpha"]},
    "alias-glob": {"argv": ["-w", "--", "ale*"], "pages": ["alpha"]},
    "whole-hyphen-name": {"argv": ["-w", "--", "alpha-x"], "pages": ["alpha-x"]},
    "leading-dash": {"argv": ["--", "-x"], "pages": ["alpha-x", "dash"]},
}
HOME = Path("/tmp/parity-home")
WORK = Path("/tmp/parity-case")
CANDIDATE = "/opt/bashos-parity/candidate"
MAX_BYTES = 65536
SHELL_GUARD = '''[[ $EUID == 2000 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
export MANPATH="$PWD/man" BASHMAN_STALE_QUIET=1
apropos "$@"
'''


def require_guest():
    marker = Path("/etc/bashos-parity-vm")
    info = marker.lstat()
    token = marker.read_text("ascii").strip()
    # The root controller already attests DMI UUID and PID1 before fixtures.
    # product_uuid is root-readable on the guest; an unprivileged helper binds
    # the protected readable marker instead of attempting that privileged read.
    if (str(uuid.UUID(token)) != token.lower() or
            not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or
            Path("/sys/class/dmi/id/sys_vendor").read_text("ascii").strip() != "QEMU" or
            os.getuid() != 2000 or os.geteuid() != 2000 or Path.cwd() != WORK or
            os.environ.get("HOME") != str(HOME)):
        raise RuntimeError("refusing execution outside the unprivileged disposable parity VM")


def write(name, value):
    (HOME / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def capture(label, argv, timeout=8):
    """Bound process lifetime and file-backed streams; retain failures verbatim."""
    out, err = HOME / (label + ".out"), HOME / (label + ".err")
    timed_out = False
    with out.open("wb") as stdout, err.open("wb") as stderr:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                start_new_session=True)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=3)
    lengths = {"stdout": out.stat().st_size, "stderr": err.stat().st_size}
    truncated = any(size > MAX_BYTES for size in lengths.values())
    with out.open("rb") as stream:
        stdout = stream.read(MAX_BYTES)
    with err.open("rb") as stream:
        stderr = stream.read(MAX_BYTES)
    observation = {"argv": argv, "status": proc.returncode, "timeout": timed_out,
                   "truncated": truncated, "lengths": lengths,
                   "stdout_base64": base64.b64encode(stdout).decode(),
                   "stderr_base64": base64.b64encode(stderr).decode()}
    write(label + ".json", observation)
    if timed_out or truncated:
        raise RuntimeError("query observation incomplete: " + label)
    return observation, stdout, stderr


def parse_records(data):
    text = data.decode("utf-8", "strict")
    if text and not text.endswith("\n"):
        raise ValueError("unterminated result record")
    aliases = {name: page for page, entry in PAGES.items() for name in entry["names"]}
    rows, seen_names = [], set()
    for line in text.splitlines():
        match = re.fullmatch(r"([a-z][a-z0-9-]*(?:,\s*[a-z][a-z0-9-]*)*)\s+\(1\)\s+-\s+(.+)", line)
        if match is None:
            raise ValueError("unrecognized result record")
        names = re.split(r",\s*", match[1])
        if any(name not in aliases or name in seen_names for name in names) or len(names) != len(set(names)):
            raise ValueError("unknown or duplicate result name")
        pages = {aliases[name] for name in names}
        if len(pages) != 1:
            raise ValueError("record combines different source pages")
        page = pages.pop()
        if match[2] != PAGES[page]["description"]:
            raise ValueError("source description differs")
        seen_names.update(names)
        rows.append({"page": page, "names": names, "section": "1", "description": match[2]})
    return rows


def page_set(rows):
    return sorted({row["page"] for row in rows})


def parser_controls():
    sample = b"alpha, aleph (1) - first apple\nbeta (1) - second berry\n"
    intersection = b"both (1) - alpha and beta together\n"
    union = sample + b"alpha-x (1) - longer name\n" + intersection
    expected = ["alpha", "beta"]
    checks = {"grouped_aliases": page_set(parse_records(sample)) == expected,
              "split_aliases": page_set(parse_records(b"alpha (1) - first apple\naleph (1) - first apple\n")) == ["alpha"],
              "omitted_page_rejected": page_set(parse_records(sample.splitlines(keepends=True)[0])) != expected,
              "and_cannot_pass_as_or": page_set(parse_records(intersection)) != QUERIES["default-or"]["pages"],
              "or_cannot_pass_as_and": page_set(parse_records(union)) != QUERIES["explicit-and"]["pages"],
              "extra_page_rejected": page_set(parse_records(sample + b"dash (1) - option -x feature\n")) != expected}
    bad = {"duplicate": sample + sample.splitlines(keepends=True)[0],
           "unknown_name": sample.replace(b"beta", b"intruder"),
           "wrong_description": sample.replace(b"second berry", b"changed description"),
           "wrong_section": sample.replace(b"(1)", b"(2)"),
           "partial_record": sample[:-1], "garbage": sample + b"garbage\n"}
    for name, data in bad.items():
        try:
            parse_records(data)
        except (ValueError, UnicodeError):
            checks[name] = True
        else:
            checks[name] = False
    write("apropos-parser-controls.json", {"sample_base64": base64.b64encode(sample).decode(),
          "and_base64": base64.b64encode(intersection).decode(), "or_base64": base64.b64encode(union).decode(),
          "negative_inputs": {k: base64.b64encode(v).decode() for k, v in bad.items()}, "checks": checks})
    if not all(checks.values()):
        raise RuntimeError("parser control failure")


def setup():
    parser_controls()
    reference = HOME / "reference-man"
    (reference / "man1").mkdir(parents=True)
    pins = {}
    whatis = ""
    for page, entry in sorted(PAGES.items()):
        names = ", ".join(entry["names"])
        expected = (".TH " + page.upper() + " 1\n.SH NAME\n" + names + " \\- " + entry["description"] + "\n").encode()
        original = WORK / "pages" / (page + ".1")
        if original.read_bytes() != expected:
            raise RuntimeError("page corpus differs")
        copied = reference / "man1" / (page + ".1")
        copied.write_bytes(expected)
        pins[page + ".1"] = {"source_sha256": sha(expected), "reference_sha256": sha(copied.read_bytes())}
        whatis += names + " (1) - " + entry["description"] + "\n"
    if (WORK / "man/whatis").read_bytes() != whatis.encode():
        raise RuntimeError("candidate whatis corpus differs")
    write("apropos-corpus.json", {"pages": pins, "whatis_sha256": sha(whatis.encode()),
          "names_and_descriptions": PAGES, "uid": os.getuid(), "euid": os.geteuid(),
          "vm_uuid": Path("/etc/bashos-parity-vm").read_text().strip()})
    indexed, _, err = capture("apropos-mandb", ["/usr/bin/mandb", "-u", "-q", str(reference)], timeout=15)
    if indexed["status"] != 0 or err:
        raise RuntimeError("private man-db index setup failed")
    result, out, err = capture("apropos-preflight", ["/usr/bin/apropos", "-M", str(reference), "-w", "--", "aleph"])
    if result["status"] != 0 or err or page_set(parse_records(out)) != ["alpha"]:
        raise RuntimeError("private man-db alias preflight failed")
    miss, _, _ = capture("apropos-preflight-miss", ["/usr/bin/apropos", "-M", str(reference), "--", "nofixturehit"])
    if miss["status"] != 16:
        raise RuntimeError("private man-db no-match status is not 16")
    # Preserve the actual reference channels; neither historical labels nor
    # candidate output determine which channel is correct for this image.
    version, _, _ = capture("apropos-reference-version", ["/usr/bin/apropos", "--version"])
    if version["status"] != 0:
        raise RuntimeError("reference identity capture failed")


def query(side, mode):
    spec = QUERIES[mode]
    if side == "reference":
        argv = ["/usr/bin/apropos", "-M", str(HOME / "reference-man")] + spec["argv"]
    else:
        argv = [CANDIDATE, "--noprofile", "--norc", "-c", SHELL_GUARD, "apropos-requirement"] + spec["argv"]
    result, out, err = capture("apropos-query", argv)
    parsed, parse_error = [], None
    try:
        parsed = parse_records(out)
    except (ValueError, UnicodeError) as error:
        parse_error = str(error)
    checks = {"status_zero": result["status"] == 0, "stderr_empty": err == b"",
              "records_valid": parse_error is None, "exact_pages": page_set(parsed) == spec["pages"]}
    write("apropos-query-verdict.json", {"side": side, "mode": mode, "observation": result,
          "rows": parsed, "parse_error": parse_error, "expected_pages": spec["pages"], "checks": checks})
    if not all(checks.values()):
        print("query mismatch: " + json.dumps(checks, sort_keys=True), file=sys.stderr)
        return 1
    print(mode + ": ok")
    return 0


def main():
    require_guest()
    if sys.argv[1:] == ["setup"]:
        setup()
        return 0
    if len(sys.argv) == 3 and sys.argv[1] in ("candidate", "reference") and sys.argv[2] in QUERIES:
        return query(sys.argv[1], sys.argv[2])
    raise ValueError("invalid control invocation")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        try:
            write("apropos-observation-error.json", {"error": str(error)})
        except OSError:
            pass
        print("apropos observation error: " + str(error), file=sys.stderr)
        raise SystemExit(125)
