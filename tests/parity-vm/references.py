#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned normative reference corpora: host data tools and a VM-only evaluator.

On the host this module only downloads, hashes and parses data files
(fetch, verify, generate). It has no host operation that starts the
candidate. Inside the disposable VM, guest.py calls evaluate(ROOT, output)
after its own marker/identity checks; evaluate() repeats a marker check and
then runs ROOT/candidate as the unprivileged parity user.

Every expected value comes from the pinned corpus text (or vectors that were
generated as data and cross-checked against it), never from candidate output.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
DATA = HERE / "references"
REPO = HERE.parent.parent
UNICODE_LOCK = DATA / "unicode-17.lock.json"
MALFORMED = DATA / "utf8-malformed.json"
CONTEXT = DATA / "unicode-17-context.json"
RFC_LOCK = DATA / "rfc.lock.json"
RFC_VECTORS = DATA / "rfc-vectors.json"
WORKDIR = Path("/tmp/parity-reference")

PARITY_UID = 2000
TRUSTED_SHELLS = ("/opt/bash-5.3.15/bin/bash", "/bin/bash")   # argv probe only; never the oracle
BATCH_TUPLES = 4096
BATCH_ARG_BYTES = 768 * 1024
BATCH_TIMEOUT = 120
BATCH_OUTPUT = 48 * 1024**2
RERUN_BUDGET = 3000          # individual reruns per job when a batch loses framing
FAILURE_LOG_LIMIT = 50000    # per record; counts are always complete
FIRST_FAILURES = 20
TIME_BUDGET = 1100           # seconds for the whole reference group
ARCHIVE_LIMIT = 48 * 1024**2  # compressed raw batch output kept as evidence; hashes are always kept


# --------------------------------------------------------------------------
# Data handling (host and guest)

def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_lock(path=UNICODE_LOCK):
    return json.loads(path.read_text())


def verify_files(directory, lock):
    """Return (problems, verified) for every file in the lock."""
    problems, verified = [], {}
    for entry in lock["files"]:
        path = directory / entry["name"]
        if not path.is_file() or path.is_symlink():
            problems.append(entry["name"] + ": missing")
            continue
        size = path.stat().st_size
        digest = sha256(path)
        if size != entry["bytes"] or digest != entry["sha256"]:
            problems.append("%s: expected %s/%d bytes, found %s/%d bytes"
                            % (entry["name"], entry["sha256"], entry["bytes"], digest, size))
            continue
        header = entry.get("header")
        if header:
            with path.open(encoding="utf-8") as stream:
                if stream.readline().strip() != header:
                    problems.append(entry["name"] + ": header does not name the locked version")
                    continue
        verified[entry["name"]] = digest
    return problems, verified


def cps(field):
    return "".join(chr(int(item, 16)) for item in field.split())


def scalar_values():
    """Every Unicode scalar value except U+0000, which Bash argv cannot carry."""
    for cp in range(1, 0x110000):
        if not 0xD800 <= cp <= 0xDFFF:
            yield cp


def data_lines(path):
    with path.open(encoding="utf-8") as stream:
        for number, raw in enumerate(stream, 1):
            line = raw.split("#", 1)[0].strip()
            if line:
                yield number, line


def grapheme_tests(path):
    tests, declared = [], None
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.startswith("# Lines:"):
                declared = int(line.split(":", 1)[1])
    for number, line in data_lines(path):
        tokens = line.split()
        if tokens[0] != "÷" or tokens[-1] != "÷":
            raise ValueError("GraphemeBreakTest line %d lacks sot/eot breaks" % number)
        clusters, current = [], ""
        for token in tokens[1:]:
            if token == "÷":
                clusters.append(current)
                current = ""
            elif token != "×":
                current += chr(int(token, 16))
        tests.append((number, clusters))
    if declared is not None and declared != len(tests):
        raise ValueError("GraphemeBreakTest declares %d lines, parsed %d" % (declared, len(tests)))
    return tests


def normalization_tests(path):
    parts, part = {}, None
    with path.open(encoding="utf-8") as stream:
        for number, raw in enumerate(stream, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("@Part"):
                part = line[1:].split()[0]
                parts[part] = []
                continue
            columns = [cps(item) for item in line.split(";")[:5]]
            if len(columns) != 5 or part is None:
                raise ValueError("NormalizationTest line %d is malformed" % number)
            parts[part].append((number, columns))
    part1 = {ord(columns[0]) for _, columns in parts.get("Part1", []) if len(columns[0]) == 1}
    return parts, part1


def casefolding(path):
    full, statuses = {}, {}
    for _, line in data_lines(path):
        code, status, mapping = [item.strip() for item in line.split(";")[:3]]
        statuses[status] = statuses.get(status, 0) + 1
        if status in ("C", "F"):
            full[int(code, 16)] = cps(mapping)
    return full, statuses


def ranges(path, wanted):
    result = {name: set() for name in wanted}
    for _, line in data_lines(path):
        span, name = [item.strip() for item in line.split(";")[:2]]
        if name in result:
            low, _, high = span.partition("..")
            result[name].update(range(int(low, 16), int(high or low, 16) + 1))
    return result


class Casing:
    """Full case mappings for isolated scalars (Unicode 17 chapter 3, R1-R3)."""

    def __init__(self, directory):
        self.upper, self.lower, self.title = {}, {}, {}
        for _, line in data_lines(directory / "UnicodeData.txt"):
            fields = line.split(";")
            cp = int(fields[0], 16)
            if fields[12]:
                self.upper[cp] = chr(int(fields[12], 16))
            if fields[13]:
                self.lower[cp] = chr(int(fields[13], 16))
            if fields[14]:
                self.title[cp] = chr(int(fields[14], 16))
            elif fields[12]:
                self.title[cp] = self.upper[cp]  # UAX #44: empty titlecase = uppercase
        self.conditional = []
        for number, line in data_lines(directory / "SpecialCasing.txt"):
            fields = [item.strip() for item in line.split(";")]
            cp = int(fields[0], 16)
            if len(fields) > 4 and fields[4]:
                self.conditional.append({"line": number, "code_point": "%04X" % cp, "condition": fields[4]})
                continue
            self.lower[cp], self.title[cp], self.upper[cp] = cps(fields[1]), cps(fields[2]), cps(fields[3])
        properties = ranges(directory / "DerivedCoreProperties.txt", ("Cased", "Case_Ignorable"))
        self.cased, self.ignorable = properties["Cased"], properties["Case_Ignorable"]

    def map_lower(self, cp):
        return self.lower.get(cp, chr(cp))

    def map_upper(self, cp):
        return self.upper.get(cp, chr(cp))

    def map_title(self, cp):
        # A lone scalar follows the sot word boundary; R3 titlecases it only if it is Cased.
        return self.title.get(cp, chr(cp)) if cp in self.cased else chr(cp)

    def final_sigma(self, text, index):
        """Table 3-17 Final_Sigma for text[index]."""
        before = index - 1
        while before >= 0 and ord(text[before]) in self.ignorable:
            before -= 1
        if before < 0 or ord(text[before]) not in self.cased:
            return False
        after = index + 1
        while after < len(text) and ord(text[after]) in self.ignorable:
            after += 1
        return after == len(text) or ord(text[after]) not in self.cased

    def lower_string(self, text):
        return "".join("ς" if ch == "Σ" and self.final_sigma(text, i) else self.map_lower(ord(ch))
                       for i, ch in enumerate(text))


# --------------------------------------------------------------------------
# Assertion plans. A job is one script shape; each tuple of positional
# arguments yields one expected (stdout, status) per command in the job.

def encode(text):
    return text.encode("utf-8")


def line_output(text):
    return encode(text) + b"\n"


class Job:
    def __init__(self, name, commands, arity, tuples, planned, inputs=None, max_tuples=BATCH_TUPLES):
        self.name, self.commands, self.arity, self.max_tuples = name, commands, arity, max_tuples
        self.tuples = tuples        # iterator of (args, [(record, assertion_id, stdout, status), ...])
        self.planned = planned      # {record: assertion count}
        self.inputs = inputs or {}  # {file name under WORKDIR/inputs: bytes} read on fd 0
        self.probe_all = max_tuples == 1
        for command in commands:   # static check: every slot is braced or a single digit, within arity
            if re.search(r"\$[0-9]{2}", command):
                raise ValueError("%s: unbraced multi-digit positional parameter in %r" % (name, command))
            slots = [int(n) for n in re.findall(r"\$\{?([0-9]+)\}?", command)]
            if not slots or max(slots) > arity:
                raise ValueError("%s: positional slots %r exceed arity %d" % (name, slots, arity))

    def probe(self):
        """The same loop with each command replaced by printf of its resolved words (and stdin path)."""
        commands = []
        for command in self.commands:
            words, _, redirect = command.partition(" < ")
            probe = "printf '%s\\0' " + words
            if redirect:
                probe += "; printf 'stdin=%s\\0' " + redirect
            commands.append(probe)
        return Job(self.name + "-probe", commands, self.arity, iter(()), {}).script()

    def probe_expected(self, batch):
        out = bytearray()
        for tuple_args, _, _ in batch:
            for command in self.commands:
                words, _, redirect = command.partition(" < ")
                out += b"\xff"
                for word in words.split(" ") + (["stdin=" + redirect] if redirect else []):
                    prefix = b""
                    if word.startswith("stdin="):
                        prefix, word = b"stdin=", word[len("stdin="):]
                    slot = re.fullmatch(r'"\$\{?([0-9]+)\}?"', word)
                    out += prefix + (tuple_args[int(slot.group(1)) - 1] if slot else word.encode()) + b"\0"
                out += b"\xfe0"
        return bytes(out)

    def script(self):
        body = "".join("printf '\\377'; %s; printf '\\376%%d' \"$?\"\n" % command for command in self.commands)
        return 'while (($#)); do\n%sshift %d\ndone\n' % (body, self.arity)


def grapheme_jobs(directory, records):
    tests = grapheme_tests(directory / "GraphemeBreakTest.txt")
    usable = [(n, c) for n, c in tests if "\0" not in "".join(c)]
    excluded = [n for n, c in tests if "\0" in "".join(c)]
    records["unicode17-grapheme-nul-unrepresentable"] = {
        "status": "SKIP", "corpus": "GraphemeBreakTest.txt",
        "detail": "GraphemeBreakTest lines containing U+0000 cannot be passed through Bash argv "
                  "(C strings end at NUL); they are excluded from every grapheme assertion, not passed.",
        "lines_total": len(tests), "lines_excluded": len(excluded), "excluded_lines": excluded}
    common = {"corpus": "GraphemeBreakTest.txt", "lines_total": len(tests),
              "lines_used": len(usable), "lines_excluded_nul": len(excluded)}
    records["unicode17-grapheme-length"] = dict(common, operation="utf8 length TEXT (grapheme)")
    records["unicode17-grapheme-codepoint-length"] = dict(common, operation="utf8 length TEXT -T codepoint")
    records["unicode17-grapheme-byte-length"] = dict(common, operation="utf8 length TEXT -T byte")
    records["unicode17-grapheme-slice"] = dict(common, operation="utf8 slice TEXT K K+1 (each cluster)")

    def counts():
        for number, clusters in usable:
            text = "".join(clusters)
            yield (encode(text),), [
                ("unicode17-grapheme-length", "line%d" % number, b"%d\n" % len(clusters), 0),
                ("unicode17-grapheme-codepoint-length", "line%d" % number, b"%d\n" % len(text), 0),
                ("unicode17-grapheme-byte-length", "line%d" % number, b"%d\n" % len(encode(text)), 0)]

    def slices():
        for number, clusters in usable:
            text = encode("".join(clusters))
            for index, cluster in enumerate(clusters):
                yield (text, b"%d" % index, b"%d" % (index + 1)), [
                    ("unicode17-grapheme-slice", "line%d:cluster%d" % (number, index), line_output(cluster), 0)]

    yield Job("grapheme-counts", ['utf8 length "$1"', 'utf8 length "$1" -T codepoint',
                                  'utf8 length "$1" -T byte'], 1, counts(),
              {"unicode17-grapheme-length": len(usable), "unicode17-grapheme-codepoint-length": len(usable),
               "unicode17-grapheme-byte-length": len(usable)})
    yield Job("grapheme-slices", ['utf8 slice "$1" "$2" "$3"'], 3, slices(),
              {"unicode17-grapheme-slice": sum(len(c) for _, c in usable)})


# NormalizationTest.txt header: the conformance conditions per column.
NORMALIZATION_RULES = {
    "NFC": [(0, 1), (1, 1), (2, 1), (3, 3), (4, 3)],
    "NFD": [(0, 2), (1, 2), (2, 2), (3, 4), (4, 4)],
    "NFKC": [(0, 3), (1, 3), (2, 3), (3, 3), (4, 3)],
    "NFKD": [(0, 4), (1, 4), (2, 4), (3, 4), (4, 4)],
}
FORMS = tuple(NORMALIZATION_RULES)


def normalization_jobs(directory, records, part1, parts):
    total = sum(len(lines) for lines in parts.values())
    for part, lines in parts.items():
        usable = [(n, c) for n, c in lines if "\0" not in "".join(c)]
        record = "unicode17-normalization-" + part.lower()
        records[record] = {"corpus": "NormalizationTest.txt", "part": part, "lines_total": len(lines),
                           "lines_used": len(usable), "lines_excluded_nul": len(lines) - len(usable),
                           "operation": "utf8 normalize NFC|NFD|NFKC|NFKD; all 20 column conditions per line"}

        def tuples(usable=usable, part=part, record=record):
            for number, columns in usable:
                for source in range(5):
                    expected = [(record, "line%d:%s(c%d)" % (number, form, source + 1),
                                 line_output(columns[target]), 0)
                                for form in FORMS for src, target in NORMALIZATION_RULES[form] if src == source]
                    yield (encode(columns[source]),), expected

        yield Job("normalization-" + part, ['utf8 normalize %s "$1"' % form for form in FORMS], 1, tuples(),
                  {record: 20 * len(usable)})

    records["unicode17-normalization-cmp"] = {
        "corpus": "NormalizationTest.txt", "lines_total": total,
        "operation": "utf8 cmp A B -N FORM: equal pairs from the column rules, unequal where columns differ"}

    def comparisons():
        for part, lines in parts.items():
            for number, c in lines:
                if "\0" in "".join(c):
                    continue
                checks = [(1, "NFC", 0), (2, "NFD", 0), (3, "NFKC", 0), (4, "NFKD", 0)]
                if c[1] != c[3]:
                    checks.append((3, "NFC", 1))   # NFC(c1)=c2, NFC(c4)=c4
                if c[2] != c[4]:
                    checks.append((3, "NFD", 1))   # NFD(c1)=c3, NFD(c4)=c5
                for other, form, status in checks:
                    yield (encode(c[0]), encode(c[other]), form.encode()), [
                        ("unicode17-normalization-cmp", "%s:line%d:cmp(c1,c%d,%s)" % (part, number, other + 1, form),
                         b"", status)]

    planned = sum(1 for _ in comparisons())
    yield Job("normalization-cmp", ['utf8 cmp "$1" "$2" -N "$3"'], 3, comparisons(),
              {"unicode17-normalization-cmp": planned})


def sweep_jobs(directory, records, part1, folding, casing):
    invariant = [cp for cp in scalar_values() if cp not in part1]
    members = sorted(part1)
    sweep = {"domain": "Unicode scalar values U+0001..U+10FFFF (surrogates are not scalar values; "
                       "U+0000 is unrepresentable in Bash argv and recorded separately)"}
    records["unicode17-normalization-invariance"] = dict(
        sweep, corpus="NormalizationTest.txt", code_points=len(invariant),
        operation="NFC/NFD/NFKC/NFKD of each scalar outside Part 1 column 1 is the scalar itself")
    records["unicode17-casefold-full"] = dict(
        sweep, corpus="CaseFolding.txt", operation="utf8 casefold X == C+F mapping of X, else X")
    records["unicode17-lower-full"] = dict(
        sweep, corpus="UnicodeData.txt+SpecialCasing.txt", operation="utf8 lower X == Lowercase_Mapping(X)")
    records["unicode17-upper-full"] = dict(
        sweep, corpus="UnicodeData.txt+SpecialCasing.txt", operation="utf8 upper X == Uppercase_Mapping(X)")
    records["unicode17-title-full"] = dict(
        sweep, corpus="UnicodeData.txt+SpecialCasing.txt+DerivedCoreProperties.txt",
        operation="utf8 title X == Titlecase_Mapping(X) if Cased(X), else X (R3 on a one-scalar string)")
    casing_commands = ['utf8 casefold "$1"', 'utf8 lower "$1"', 'utf8 upper "$1"', 'utf8 title "$1"']

    def casing_expected(cp):
        tag = "U+%04X" % cp
        return [("unicode17-casefold-full", tag, line_output(folding.get(cp, chr(cp))), 0),
                ("unicode17-lower-full", tag, line_output(casing.map_lower(cp)), 0),
                ("unicode17-upper-full", tag, line_output(casing.map_upper(cp)), 0),
                ("unicode17-title-full", tag, line_output(casing.map_title(cp)), 0)]

    def outside():
        for cp in invariant:
            same = line_output(chr(cp))
            yield (encode(chr(cp)),), [("unicode17-normalization-invariance", "U+%04X:%s" % (cp, form), same, 0)
                                       for form in FORMS] + casing_expected(cp)

    def inside():
        for cp in members:
            yield (encode(chr(cp)),), casing_expected(cp)

    yield Job("sweep-outside-part1", ['utf8 normalize %s "$1"' % form for form in FORMS] + casing_commands,
              1, outside(), {"unicode17-normalization-invariance": 4 * len(invariant),
                             **{r: len(invariant) for r in ("unicode17-casefold-full", "unicode17-lower-full",
                                                            "unicode17-upper-full", "unicode17-title-full")}})
    yield Job("sweep-part1-casing", casing_commands, 1, inside(),
              {r: len(members) for r in ("unicode17-casefold-full", "unicode17-lower-full",
                                         "unicode17-upper-full", "unicode17-title-full")})
    for record in ("unicode17-casefold-full", "unicode17-lower-full", "unicode17-upper-full", "unicode17-title-full"):
        records[record]["code_points"] = len(invariant) + len(members)

    mapped = sorted(cp for cp in folding if "\0" not in folding[cp])
    records["unicode17-casefold-cmp"] = {"corpus": "CaseFolding.txt",
                                         "operation": "utf8 cmp X fold(X) -i is equal for every C+F mapping"}

    def compare():
        for cp in mapped:
            yield (encode(chr(cp)), encode(folding[cp])), [
                ("unicode17-casefold-cmp", "U+%04X" % cp, b"", 0)]

    yield Job("casefold-cmp", ['utf8 cmp "$1" "$2" -i'], 2, compare(), {"unicode17-casefold-cmp": len(mapped)})


def context_jobs(directory, records, casing):
    vectors = json.loads(CONTEXT.read_text())["final_sigma"]
    records["unicode17-final-sigma"] = {
        "corpus": "SpecialCasing.txt+DerivedCoreProperties.txt",
        "operation": "utf8 lower with Table 3-17 Final_Sigma context",
        "detail": "expected strings are stored as data and recomputed from Cased/Case_Ignorable before use"}
    problems = []
    for vector in vectors:
        derived = casing.lower_string(vector["input"])
        if derived != vector["lower"]:
            problems.append("%s: stored %r, derived %r" % (vector["id"], vector["lower"], derived))
    if problems:
        raise ValueError("Final_Sigma vectors disagree with the pinned properties: " + "; ".join(problems))

    def tuples():
        for vector in vectors:
            yield (encode(vector["input"]),), [("unicode17-final-sigma", vector["id"], line_output(vector["lower"]), 0)]

    yield Job("final-sigma", ['utf8 lower "$1"'], 1, tuples(), {"unicode17-final-sigma": len(vectors)})


def malformed_jobs(records, folding):
    data = json.loads(MALFORMED.read_text())
    vectors = data["vectors"]
    records["utf8-malformed-codepoint-length"] = {
        "corpus": MALFORMED.name, "vectors": len(vectors),
        "operation": "utf8 length BYTES -T codepoint counts U+FFFD per maximal subpart",
        "source": data["source"]}
    records["utf8-malformed-casefold"] = {
        "corpus": MALFORMED.name + "+CaseFolding.txt", "vectors": len(vectors),
        "operation": "utf8 casefold BYTES == C+F fold of the maximal-subpart decoding",
        "source": data["source"]}

    def tuples():
        for vector in vectors:
            raw = bytes.fromhex(vector["bytes"])
            decoded = "".join(chr(int(item, 16)) for item in vector["decoded"])
            folded = "".join(folding.get(ord(ch), ch) for ch in decoded)
            yield (raw,), [("utf8-malformed-codepoint-length", vector["id"], b"%d\n" % len(decoded), 0),
                           ("utf8-malformed-casefold", vector["id"], line_output(folded), 0)]

    yield Job("utf8-malformed", ['utf8 length "$1" -T codepoint', 'utf8 casefold "$1"'], 1, tuples(),
              {"utf8-malformed-codepoint-length": len(vectors), "utf8-malformed-casefold": len(vectors)})


def rfc_jobs(records):
    data = json.loads(RFC_VECTORS.read_text())
    if data["lock_sha256"] != sha256(RFC_LOCK):
        raise ValueError("rfc-vectors.json was generated from a different rfc.lock.json; regenerate it")
    inputs = {name: bytes.fromhex(item["hex"]) * item["repeat"] for name, item in data["inputs"].items()}
    groups = {}
    for vector in data["vectors"]:
        record = "rfc%d-%s" % (vector["rfc"], vector["loadable"])
        if record not in records:
            records[record] = {"loadable": vector["loadable"], "corpus": "RFC %d" % vector["rfc"],
                               "operation": "published RFC test vectors; see references/rfc-vectors.json",
                               "cross_checks": data["cross_checks"]}
        groups.setdefault(len(vector["argv"]), []).append((record, vector))
    records["rfc-not-executable"] = {"loadable": "crypto", "status": "SKIP", "corpus": RFC_VECTORS.name,
                                     "detail": "published vectors that cannot run through this interface",
                                     "vectors": data["not_executable"]}
    for width, members in sorted(groups.items()):
        # Braces are required: Bash reads "$10" as "${1}0".
        command = " ".join('"${%d}"' % (index + 2) for index in range(width)) + ' < "$1"'

        def tuples(members=members):
            for record, vector in members:
                source = str(WORKDIR / "inputs" / vector["stdin"]) if vector["stdin"] else "/dev/null"
                yield tuple(arg.encode() for arg in [source] + vector["argv"]), [
                    (record, vector["id"], bytes.fromhex(vector["expected_stdout_hex"]), vector["expected_status"])]

        planned = {}
        for record, _ in members:
            planned[record] = planned.get(record, 0) + 1
        # One process per vector: raw binary outputs may contain the 0xFE/0xFF frame bytes.
        yield Job("rfc-argv%d" % width, [command], width + 1, tuples(), planned, inputs, max_tuples=1)


def plan(directory, records):
    """Yield every job; fills records with corpus metadata as a side effect."""
    folding, statuses = casefolding(directory / "CaseFolding.txt")
    casing = Casing(directory)
    parts, part1 = normalization_tests(directory / "NormalizationTest.txt")
    records["unicode17-casing-not-exposed"] = {
        "status": "SKIP", "corpus": "CaseFolding.txt+SpecialCasing.txt",
        "detail": "utf8 exposes only full default case folding and default case mappings. Simple (S) and "
                  "Turkic (T) folds, and language-conditional SpecialCasing entries, have no candidate "
                  "interface; Final_Sigma is covered by unicode17-final-sigma.",
        "casefold_status_counts": statuses,
        "conditional_special_casing": casing.conditional}
    records["unicode17-nul-unrepresentable"] = {
        "status": "SKIP",
        "detail": "U+0000 is a scalar value but cannot appear in a Bash argument (C strings end at NUL). "
                  "Its 8 sweep assertions (NFC, NFD, NFKC, NFKD invariance, casefold, lower, upper, title) "
                  "are not executed; GraphemeBreakTest exclusions are in unicode17-grapheme-nul-unrepresentable. "
                  "NormalizationTest, CaseFolding and the malformed vectors contain no U+0000.",
        "assertions_not_executed": 8}
    yield from grapheme_jobs(directory, records)
    yield from normalization_jobs(directory, records, part1, parts)
    yield from sweep_jobs(directory, records, part1, folding, casing)
    yield from context_jobs(directory, records, casing)
    yield from malformed_jobs(records, folding)
    yield from rfc_jobs(records)


# --------------------------------------------------------------------------
# Guest execution

def require_vm():
    marker = Path("/etc/bashos-parity-vm")
    uuid = Path("/sys/class/dmi/id/product_uuid")
    if not marker.is_file() or not uuid.is_file():
        raise RuntimeError("refusing reference evaluation outside the disposable parity VM")
    if marker.read_text().strip().lower() != uuid.read_text().strip().lower():
        raise RuntimeError("parity VM marker does not match the VM identity")
    if os.geteuid() != 0:
        raise RuntimeError("guest controller must run as root to drop the candidate to the parity user")


def child_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (BATCH_TIMEOUT + 30, BATCH_TIMEOUT + 30))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.setgroups([])
    os.setgid(PARITY_UID)
    os.setuid(PARITY_UID)


class Runner:
    def __init__(self, candidate, workdir, deadline):
        self.candidate, self.workdir, self.deadline = candidate, workdir, deadline
        self.processes = 0
        self.env = {"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "PATH": "/nonexistent", "HOME": str(workdir),
                    "BASH_ENV": "", "ENV": "", "TZ": "UTC"}

    def run(self, script, args):
        """Run one candidate process; returns (stdout, stderr, status, error)."""
        argv = [str(self.candidate), "--noprofile", "--norc", "-c", script, "reference"] + list(args)
        proc = subprocess.Popen(argv, cwd=self.workdir, env=self.env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, preexec_fn=child_limits)
        self.processes += 1
        buffers = {proc.stdout.fileno(): bytearray(), proc.stderr.fileno(): bytearray()}
        out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
        error = None
        limit = min(time.monotonic() + BATCH_TIMEOUT, self.deadline + 30)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            selector.register(proc.stderr, selectors.EVENT_READ)
            while selector.get_map() and error is None:
                remaining = limit - time.monotonic()
                if remaining <= 0:
                    error = "wall-clock limit"
                    break
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 1 << 20)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.fd] += chunk
                    if len(buffers[out_fd]) + len(buffers[err_fd]) > BATCH_OUTPUT:
                        error = "output limit"
                        break
        status = None
        if error is None:
            try:
                status = proc.wait(timeout=max(0.1, limit - time.monotonic()))
            except subprocess.TimeoutExpired:
                error = "wall-clock limit after output closed"
        try:   # the session leader is reaped above; this removes any stray descendants
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if status is None:
            status = proc.wait()
        proc.stdout.close()
        proc.stderr.close()
        return bytes(buffers[out_fd]), bytes(buffers[err_fd]), status, error


def frames(stdout, expected):
    """Split framed stdout into per-command (stdout, status) pairs, or None if framing is lost."""
    if expected == 1:   # exact parse: the body may hold any bytes
        if not stdout.startswith(b"\xff"):
            return None
        body, mark, status = stdout[1:].rpartition(b"\xfe")
        return [(body, int(status))] if mark and status.isdigit() else None
    pieces = stdout.split(b"\xff")
    if pieces[0] != b"" or len(pieces) - 1 != expected:
        return None
    result = []
    for piece in pieces[1:]:
        body, mark, status = piece.rpartition(b"\xfe")
        if not mark or not status.isdigit():
            return None
        result.append((body, int(status)))
    return result


class Evaluation:
    def __init__(self, runner, evidence, trusted=None):
        self.runner, self.evidence, self.trusted = runner, evidence, trusted
        self.probes = []
        self.stats = {}
        self.logs = {}
        self.batches = (evidence / "batches.jsonl").open("w")
        self.archive = gzip.open(evidence / "batch-output.gz", "wb", compresslevel=6)
        self.archived = 0
        self.reruns = 0

    def record_batch(self, job, batch, args, stdout, stderr, status, error, outcome):
        """One line per candidate process: deterministic tuple range, assertion-id digest, raw output hashes."""
        ids = hashlib.sha256()
        for _, assertions, _ in batch:
            for record, assertion_id, *_ in assertions:
                ids.update(("%s\t%s\n" % (record, assertion_id)).encode())
        argv = hashlib.sha256(b"\0".join(args)).hexdigest()
        entry = {"job": job.name, "tuples": [batch[0][2], batch[-1][2] + 1], "assertions": sum(len(a) for _, a, _ in batch),
                 "assertion_ids_sha256": ids.hexdigest(), "args_sha256": argv,
                 "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stdout_bytes": len(stdout),
                 "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "stderr_bytes": len(stderr),
                 "status": status, "error": error, "outcome": outcome, "archived": False}
        if self.archived + len(stdout) + len(stderr) <= ARCHIVE_LIMIT:
            header = json.dumps({k: entry[k] for k in ("job", "tuples", "stdout_bytes", "stderr_bytes")}).encode()
            self.archive.write(header + b"\n" + stdout + stderr)
            self.archived += len(stdout) + len(stderr)
            entry["archived"] = True
        self.batches.write(json.dumps(entry) + "\n")

    def stat(self, record):
        if record not in self.stats:
            self.stats[record] = {"planned": 0, "executed": 0, "passed": 0, "failed": 0, "unexecuted": 0,
                                  "failures_logged": 0, "first_failures": []}
        return self.stats[record]

    def fail(self, record, assertion_id, args, expected, status, actual, actual_status, reason):
        stat = self.stat(record)
        stat["failed"] += 1
        item = {"id": assertion_id, "reason": reason, "args_hex": [a.hex() for a in args],
                "expected_hex": expected.hex(), "expected_status": status,
                "actual_hex": None if actual is None else actual.hex(), "actual_status": actual_status}
        if len(stat["first_failures"]) < FIRST_FAILURES:
            stat["first_failures"].append(item)
        if stat["failures_logged"] < FAILURE_LOG_LIMIT:
            if record not in self.logs:
                self.logs[record] = (self.evidence / (record + ".failures.jsonl")).open("w")
            self.logs[record].write(json.dumps(item) + "\n")
            stat["failures_logged"] += 1

    def check(self, args, assertions, observed, stderr):
        for (record, assertion_id, expected, status), (actual, actual_status) in zip(assertions, observed):
            stat = self.stat(record)
            stat["executed"] += 1
            if actual == expected and actual_status == status and not stderr:
                stat["passed"] += 1
                continue
            reason = "unexpected stderr" if actual == expected and actual_status == status \
                else "stdout or status mismatch"
            if stderr:
                reason += "; stderr: " + stderr[:200].decode("utf-8", "replace")
            self.fail(record, assertion_id, args, expected, status, actual, actual_status, reason)

    def unexecuted(self, batch, reason):
        for _, assertions, _ in batch:
            for record, *_ in assertions:
                self.stat(record)["unexecuted"] += 1
                self.stat(record).setdefault("unexecuted_reasons", {})
                reasons = self.stat(record)["unexecuted_reasons"]
                reasons[reason] = reasons.get(reason, 0) + 1

    def batch(self, job, batch, budget):
        """Run a batch; bisect when framing is lost so each failure is attributed."""
        if time.monotonic() > self.runner.deadline:
            self.unexecuted(batch, "reference time budget exhausted")
            return
        args = [a for tuple_args, _, _ in batch for a in tuple_args]
        expected_frames = len(batch) * len(job.commands)
        stdout, stderr, status, error = self.runner.run(job.script(), args)
        observed = frames(stdout, expected_frames) if error is None and status == 0 else None
        if observed is not None and not stderr:
            self.record_batch(job, batch, args, stdout, stderr, status, error, "checked")
            for index, (tuple_args, assertions, _) in enumerate(batch):
                width = len(job.commands)
                self.check(tuple_args, assertions, observed[index * width:(index + 1) * width], b"")
            return
        if len(batch) == 1:
            tuple_args, assertions, _ = batch[0]
            self.record_batch(job, batch, args, stdout, stderr, status, error, "checked-single")
            if observed is not None:
                self.check(tuple_args, assertions, observed, stderr)
                return
            reason = error or "shell status %d or lost framing" % status
            for record, assertion_id, expected, expected_status in assertions:
                self.stat(record)["executed"] += 1
                self.fail(record, assertion_id, tuple_args, expected, expected_status, stdout, status,
                          reason + "; stderr: " + stderr[:200].decode("utf-8", "replace"))
            return
        if budget[0] <= 0:
            self.record_batch(job, batch, args, stdout, stderr, status, error, "unattributed")
            self.unexecuted(batch, "batch lost framing and the rerun budget is exhausted")
            return
        # Not counted as assertions: the halves re-execute these same tuples for attribution.
        self.record_batch(job, batch, args, stdout, stderr, status, error, "split-for-attribution")
        self.reruns += 1
        budget[0] -= 1
        middle = len(batch) // 2
        self.batch(job, batch[:middle], budget)
        self.batch(job, batch[middle:], budget)

    def argv_probe(self, job, batch):
        """Run the job's loop under trusted Bash with printf in place of the candidate command."""
        if self.trusted is None:
            self.probes.append({"job": job.name, "result": "no trusted shell"})
            return False
        args = [a for tuple_args, _, _ in batch for a in tuple_args]
        stdout, stderr, status, error = self.trusted.run(job.probe(), args)
        expected = job.probe_expected(batch)
        ok = stdout == expected and not stderr and status == 0 and error is None
        self.probes.append({"job": job.name, "shell": str(self.trusted.candidate), "tuples": len(batch),
                            "result": "ok" if ok else "mismatch", "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                            "expected_sha256": hashlib.sha256(expected).hexdigest(), "status": status, "error": error,
                            "stderr": stderr[:300].decode("utf-8", "replace")})
        return ok

    def job(self, job):
        if job.inputs:
            folder = WORKDIR / "inputs"
            folder.mkdir(mode=0o755, exist_ok=True)
            for name, data in job.inputs.items():
                path = folder / name
                if path.is_file() and path.read_bytes() == data:
                    continue   # shared by several jobs
                path.write_bytes(data)
                path.chmod(0o444)
        for record, count in job.planned.items():
            self.stat(record)["planned"] += count
        budget = [RERUN_BUDGET]
        tuples = job.tuples
        if job.probe_all:   # small jobs: validate every tuple's argv before any candidate run
            items = [(a, s, n) for n, (a, s) in enumerate(job.tuples)]
            if not self.argv_probe(job, items):
                self.unexecuted(items, "harness argv probe failed under trusted Bash")
                return
            tuples = iter([(a, s) for a, s, _ in items])
        probed = job.probe_all
        batch, size = [], 0
        for number, (tuple_args, assertions) in enumerate(tuples):
            if len(tuple_args) != job.arity or len(assertions) != len(job.commands):
                raise ValueError("malformed assertion tuple in " + job.name)
            if any(b"\0" in arg for arg in tuple_args):
                raise ValueError("NUL reached an argument in " + job.name)
            weight = sum(len(arg) + 9 for arg in tuple_args)
            if batch and (len(batch) >= job.max_tuples or size + weight > BATCH_ARG_BYTES):
                if not probed:   # large jobs: validate the first full batch
                    probed = True
                    if not self.argv_probe(job, batch):
                        self.unexecuted(batch, "harness argv probe failed under trusted Bash")
                        for rest_args, rest in tuples:
                            self.unexecuted([(rest_args, rest, None)], "harness argv probe failed under trusted Bash")
                        return
                self.batch(job, batch, budget)
                batch, size = [], 0
            batch.append((tuple_args, assertions, number))
            size += weight
        if batch:
            if not probed and not self.argv_probe(job, batch):
                self.unexecuted(batch, "harness argv probe failed under trusted Bash")
                return
            self.batch(job, batch, budget)

    def close(self):
        for stream in self.logs.values():
            stream.close()
        self.batches.close()
        self.archive.close()


def finish(records, stats, provenance):
    results = []
    for record, meta in records.items():
        entry = {"id": "reference-" + record, "loadable": meta.pop("loadable", "utf8"), "group": "reference"}
        entry.update(meta)
        if record in stats:
            stat = stats[record]
            entry.update(stat)
            mismatch = stat["executed"] + stat["unexecuted"] != stat["planned"]
            complete = not (stat["unexecuted"] or mismatch or not stat["planned"])
            entry["validation_complete"] = complete
            if mismatch:
                entry["reason"] = "assertion accounting mismatch"
            entry["status"] = "FAIL" if stat["failed"] else "PASS" if complete else "ERROR"
            if stat["failed"] and not complete:
                # Keep the FAIL and also count the missing validation as its own ERROR.
                results.append({"id": entry["id"] + "-incomplete", "loadable": entry["loadable"],
                                "group": "reference", "status": "ERROR",
                                "reason": entry.get("reason", "assertions not executed"),
                                "unexecuted": stat["unexecuted"], "planned": stat["planned"],
                                "unexecuted_reasons": stat.get("unexecuted_reasons", {})})
            if stat["failed"] > stat["failures_logged"]:
                entry["failures_truncated"] = stat["failed"] - stat["failures_logged"]
            if stat["failures_logged"]:
                entry["failures_file"] = "reference-data/" + record + ".failures.jsonl"
        elif "status" not in entry:
            entry["status"] = "ERROR"
            entry["reason"] = "planned record produced no assertions"
        entry["provenance"] = provenance
        results.append(entry)
    return results


def error_record(name, reason):
    return {"id": "reference-" + name, "group": "reference", "status": "ERROR", "reason": reason}


def evaluate(root, output):
    """VM-only: evaluate root/candidate against the pinned corpora; returns result records."""
    require_vm()
    root = Path(root)
    candidate = root / "candidate"
    directory = root / "reference-data"
    if not candidate.is_file():
        return [error_record("candidate", "candidate binary missing")]
    if not directory.is_dir():
        return [error_record("unicode17-data", "no reference data in the payload; run vm.py with --references")]
    lock = load_lock()
    problems, verified = verify_files(directory, lock)
    if problems:
        return [error_record("unicode17-data", "pinned corpus verification failed: " + "; ".join(problems))]
    evidence = Path(output) / "reference-data"
    evidence.mkdir(parents=True, exist_ok=False)
    workdir = WORKDIR
    workdir.mkdir(mode=0o700, exist_ok=True)
    os.chown(workdir, PARITY_UID, PARITY_UID)
    started = time.monotonic()
    runner = Runner(candidate, workdir, started + TIME_BUDGET)
    shell = next((Path(p) for p in TRUSTED_SHELLS if Path(p).is_file()), None)
    evaluation = Evaluation(runner, evidence, Runner(shell, workdir, started + TIME_BUDGET) if shell else None)
    records = {}
    provenance = {"unicode_version": lock["version"], "lock_sha256": sha256(UNICODE_LOCK),
                  "verified_sha256": verified, "malformed_sha256": sha256(MALFORMED),
                  "context_sha256": sha256(CONTEXT), "rfc_lock_sha256": sha256(RFC_LOCK),
                  "rfc_vectors_sha256": sha256(RFC_VECTORS)}
    jobs_run = []
    try:
        for job in plan(directory, records):
            began = time.monotonic()
            evaluation.job(job)
            jobs_run.append({"job": job.name, "seconds": round(time.monotonic() - began, 3)})
            print(json.dumps({"reference_job": job.name, "seconds": jobs_run[-1]["seconds"]}), flush=True)
    except Exception as exc:  # keep every completed record and report the planning/runtime defect
        evaluation.close()
        results = finish(records, evaluation.stats, provenance)
        results.append(error_record("unicode17-evaluator", "%s: %s" % (type(exc).__name__, exc)))
        return results
    evaluation.close()
    results = finish(records, evaluation.stats, provenance)
    (evidence / "manifest.json").write_text(json.dumps({
        "provenance": provenance, "jobs": jobs_run, "processes": runner.processes,
        "attribution_splits": evaluation.reruns, "archived_output_bytes": evaluation.archived,
        "argv_probes": evaluation.probes,
        "seconds": round(time.monotonic() - started, 3), "python": sys.version,
        "summary": {r["id"]: r["status"] for r in results}}, indent=2) + "\n")
    return results


# --------------------------------------------------------------------------
# Host data tools

def outside_repo(path):
    path = path.resolve()
    if path == REPO or REPO in path.parents:
        raise SystemExit("reference corpora and generated vectors belong outside the checkout: %s" % path)
    return path


def fetch(args):
    destination = outside_repo(args.dest)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = load_lock()
    for entry in lock["files"]:
        path = destination / entry["name"]
        if path.is_file() and sha256(path) == entry["sha256"]:
            print("verified", entry["name"])
            continue
        if not entry["url"].startswith("https://"):
            raise SystemExit("refusing non-HTTPS reference URL " + entry["url"])
        partial = path.with_name(path.name + ".part")
        with urllib.request.urlopen(entry["url"], timeout=60) as source, partial.open("wb") as sink:
            sink.write(source.read(entry["bytes"] + 1))
        if partial.stat().st_size != entry["bytes"] or sha256(partial) != entry["sha256"]:
            partial.unlink()
            raise SystemExit("downloaded %s does not match the lock" % entry["name"])
        partial.chmod(0o600)
        partial.replace(path)
        print("fetched", entry["name"])
    return verify(args)


def verify(args):
    problems, verified = verify_files(args.dest.resolve(), load_lock())
    for name, digest in verified.items():
        print("ok      %s  %s" % (digest, name))
    for problem in problems:
        print("FAILED  " + problem)
    return 1 if problems else 0


def generate(args):
    """Write every planned assertion as data (no candidate involved) plus complete counts."""
    directory = args.dest.resolve()
    problems, verified = verify_files(directory, load_lock())
    if problems:
        raise SystemExit("; ".join(problems))
    output = outside_repo(args.output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    records, counts = {}, {}
    with (output / "assertions.jsonl").open("w") as stream:
        for job in plan(directory, records):
            written, per_job = 0, {}
            for tuple_args, assertions in job.tuples:
                for index, (record, assertion_id, expected, status) in enumerate(assertions):
                    counts[record] = counts.get(record, 0) + 1
                    per_job[record] = per_job.get(record, 0) + 1
                    written += 1
                    if args.sample is None or written <= args.sample:
                        stream.write(json.dumps({"job": job.name, "record": record, "id": assertion_id,
                                                 "command": job.commands[index],
                                                 "args_hex": [a.hex() for a in tuple_args],
                                                 "expected_stdout_hex": expected.hex(),
                                                 "expected_status": status}) + "\n")
            if per_job != job.planned:
                raise SystemExit("job %s planned %r but generated %r" % (job.name, job.planned, per_job))
    summary = {"verified_sha256": verified, "assertions": counts, "total": sum(counts.values()),
               "records": records}
    (output / "counts.json").write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n")
    print(json.dumps({"total": summary["total"], "assertions": counts}, indent=2))
    return 0


def generate_malformed(args):
    """Regenerate utf8-malformed.json from Python's maximal-subpart decoder, checked
    against the worked examples in Unicode 17 chapter 3 (section 3.9)."""
    examples = [
        ("61F18080E180C262806380BF64", "0061 FFFD FFFD FFFD 0062 FFFD 0063 FFFD FFFD 0064"),
        ("C0AFE080BFF0818241", "FFFD FFFD FFFD FFFD FFFD FFFD FFFD FFFD 0041"),
        ("EDA080EDBFBFEDAF41", "FFFD FFFD FFFD FFFD FFFD FFFD FFFD FFFD 0041"),
        ("F4919293FF4180BF42", "FFFD FFFD FFFD FFFD FFFD 0041 FFFD FFFD 0042"),
        ("E180E2F09192F1BF41", "FFFD FFFD FFFD FFFD 0041"),
    ]
    vectors = []

    def add(name, raw):
        decoded = raw.decode("utf-8", "replace")
        vectors.append({"id": name, "bytes": raw.hex(), "decoded": ["%04X" % ord(ch) for ch in decoded]})

    for index, (hexbytes, expected) in enumerate(examples):
        raw = bytes.fromhex(hexbytes.replace(" ", ""))
        if ["%04X" % ord(ch) for ch in raw.decode("utf-8", "replace")] != expected.split():
            raise SystemExit("Python decoder disagrees with Unicode chapter 3 example %d" % index)
        add("unicode-ch3-example-%d" % (index + 1), raw)
    for byte in range(0x80, 0x100):
        add("lone-%02X" % byte, bytes([byte]) + b"A")
    for lead in range(0xC0, 0x100):
        for trail in range(0x80, 0xC0):
            add("pair-%02X%02X" % (lead, trail), bytes([lead, trail]) + b"z")
    for lead, seconds in [(0xE0, range(0x80, 0xC0)), (0xED, range(0x80, 0xC0)),
                          (0xF0, range(0x80, 0xC0)), (0xF4, range(0x80, 0xC0))]:
        for second in seconds:
            add("triple-%02X%02X80" % (lead, second), bytes([lead, second, 0x80]) + b"Q")
            add("quad-%02X%02X8080" % (lead, second), bytes([lead, second, 0x80, 0x80]) + b"Q")
    for lead in list(range(0xE1, 0xED)) + [0xEE, 0xEF] + list(range(0xF1, 0xF4)):
        add("truncated-%02X" % lead, bytes([lead, 0x80]) + b"Q")
    data = {"schema": 1,
            "source": "Unicode 17.0 core specification chapter 3, section 3.9, 'U+FFFD Substitution of Maximal "
                      "Subparts' (best practice); its worked examples were "
                      "transcribed and cross-checked against CPython %s bytes.decode('utf-8', 'replace'), "
                      "which generated the systematic vectors. NUL bytes are never used." % sys.version.split()[0],
            "vectors": vectors}
    MALFORMED.write_text(json.dumps(data, indent=1) + "\n")
    print("wrote %d vectors to %s" % (len(vectors), MALFORMED))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in ("fetch", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--dest", type=Path, required=True, help="private corpus directory outside the checkout")
    command = sub.add_parser("generate", help="write planned assertions and counts as data")
    command.add_argument("--dest", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--sample", type=int, help="write only the first N assertions per job (counts stay complete)")
    sub.add_parser("generate-malformed", help="rebuild references/utf8-malformed.json")
    args = parser.parse_args()
    return {"fetch": fetch, "verify": verify, "generate": generate,
            "generate-malformed": generate_malformed}[args.operation](args)


if __name__ == "__main__":
    raise SystemExit(main())
