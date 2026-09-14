#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check bulk hash/count/equality paths and private service-log tails.

Usage: python3 tests/core-fastpaths.py [BINARY] [--only sha,diff,wc,crypto,sv]
The sha group builds a temporary standalone helper with CC (default cc), and
can run without a bash-os binary. All other groups require the named builtins.
GNU wc, explicit corrected word counts, and Python hashlib provide
independent count/digest references.
"""

import argparse
import ctypes
import hashlib
import hmac
import locale
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
GROUPS = ("sha", "diff", "wc", "crypto", "sv")
SHA_WRAPPER = r"""
#include "sha256.h"
#include <stddef.h>

static int released(mbedtls_sha256_context *ctx)
{
    mbedtls_sha256_free(ctx);
    const unsigned char *p = (const unsigned char *)ctx;
    for (size_t i = 0; i < sizeof(*ctx); i++)
        if (p[i] != 0) return -100;
    return 0;
}

int check_chunks(const unsigned char *data, size_t len, int is224,
                 const size_t *chunks, size_t nchunks, unsigned char *out)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int rc = mbedtls_sha256_starts(&ctx, is224);
    if (!rc) rc = mbedtls_sha256_update(&ctx, NULL, 0);
    size_t offset = 0, i = 0;
    while (!rc && offset < len) {
        size_t n = chunks[i++ % nchunks];
        if (n > len - offset) n = len - offset;
        rc = mbedtls_sha256_update(&ctx, data + offset, n);
        offset += n;
    }
    if (!rc) rc = mbedtls_sha256_update(&ctx, NULL, 0);
    if (!rc) rc = mbedtls_sha256_finish(&ctx, out);
    int erased = released(&ctx);
    return rc ? rc : erased;
}

int check_clone(const unsigned char *prefix, size_t plen,
                const unsigned char *a, size_t alen,
                const unsigned char *b, size_t blen, int is224,
                unsigned char *out_a, unsigned char *out_b)
{
    mbedtls_sha256_context first, second;
    mbedtls_sha256_init(&first);
    mbedtls_sha256_init(&second);
    int rc = mbedtls_sha256_starts(&first, is224);
    if (!rc) rc = mbedtls_sha256_update(&first, prefix, plen);
    if (!rc) mbedtls_sha256_clone(&second, &first);
    if (!rc) rc = mbedtls_sha256_update(&first, a, alen);
    if (!rc) rc = mbedtls_sha256_update(&second, b, blen);
    if (!rc) rc = mbedtls_sha256_finish(&first, out_a);
    if (!rc) rc = mbedtls_sha256_finish(&second, out_b);
    int erased_a = released(&first), erased_b = released(&second);
    return rc ? rc : (erased_a ? erased_a : erased_b);
}
"""


class Checks:
    def __init__(self, binary):
        self.binary = str(binary)
        self.count = 0
        self.env = {**os.environ, "PATH": "", "LC_ALL": "C", "TZ": "UTC"}
        # Test GNU default whitespace semantics independently of the caller.
        self.env.pop("POSIXLY_CORRECT", None)

    def equal(self, actual, expected, label):
        assert actual == expected, (label, repr(actual)[:400], repr(expected)[:400])
        self.count += 1

    def shell(self, script, *args, data=b"", env=None, rc=0):
        result = subprocess.run(
            [self.binary, "--noprofile", "--norc", "-c", script, "fastpaths",
             *map(str, args)], input=data, capture_output=True, timeout=20,
            env={**self.env, **(env or {})})
        assert b"AddressSanitizer" not in result.stderr, result.stderr
        assert b"runtime error:" not in result.stderr, result.stderr
        assert result.returncode == rc, (script, args, result.returncode,
                                         result.stderr[:2000])
        return result.stdout

    def run(self, *args, **kwargs):
        return self.shell('"$@"', *args, **kwargs)


def check_sha(checks, directory):
    source = directory / "sha-check.c"
    module = directory / "sha-check.so"
    source.write_text(SHA_WRAPPER)
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-O2", "-fPIC", "-shared", "-I", str(ROOT / "loadables/_mbedtls"),
        str(source), str(ROOT / "loadables/_mbedtls/sha256.c"), "-o", str(module)]
    subprocess.run(command, check=True, capture_output=True, timeout=60)
    lib = ctypes.CDLL(str(module))
    ptr, size, integer = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int
    lib.mbedtls_sha256.argtypes = [ptr, size, ptr, integer]
    lib.mbedtls_sha256.restype = integer
    lib.check_chunks.argtypes = [ptr, size, integer, ctypes.POINTER(size), size, ptr]
    lib.check_chunks.restype = integer
    lib.check_clone.argtypes = [ptr, size, ptr, size, ptr, size, integer, ptr, ptr]
    lib.check_clone.restype = integer
    lengths = (0, 1, 55, 56, 57, 63, 64, 65, 127, 128, 129, 255, 256, 257,
               4095, 4096, 4097, 65535, 65536, 65537, 131137)
    plans = ((1,), (63,), (64,), (65,), (4096,), (17, 0, 129, 65536))

    def output():
        return (ctypes.c_ubyte * 32)(*([0xA5] * 32))

    def expected_bytes(payload, is224):
        digest = (hashlib.sha224 if is224 else hashlib.sha256)(payload).digest()
        return digest + b"\xa5" * (32 - len(digest))

    for is224 in (0, 1):
        for length in lengths:
            payload = (bytes(range(256)) * ((length + 255) // 256))[:length]
            data = ctypes.create_string_buffer(payload)
            expected = expected_bytes(payload, is224)
            out = output()
            rc = lib.mbedtls_sha256(data, length, out, is224)
            checks.equal((rc, bytes(out)), (0, expected), ("SHA one-shot", is224, length))
            for plan in plans:
                chunks = (size * len(plan))(*plan)
                out = output()
                rc = lib.check_chunks(data, length, is224, chunks, len(plan), out)
                checks.equal((rc, bytes(out)), (0, expected),
                             ("SHA chunks/context erasure", is224, length, plan))
        # The compressor must accept arbitrary byte addresses, including
        # input that is unaligned for native 32/64-bit or 16-byte loads.
        payload = (bytes(range(256)) * 2)[:257]
        for misalignment in (1, 3, 7, 15):
            storage = ctypes.create_string_buffer(len(payload) + 31)
            start = (-ctypes.addressof(storage)) % 16 + misalignment
            data = ctypes.byref(storage, start)
            ctypes.memmove(data, payload, len(payload))
            out = output()
            rc = lib.mbedtls_sha256(data, len(payload), out, is224)
            checks.equal((rc, bytes(out)), (0, expected_bytes(payload, is224)),
                         ("SHA unaligned input", is224, misalignment))
        for length in (0, 1, 55, 56, 63, 64, 65, 127):
            prefix = bytes(range(length))
            a, b = b"first suffix\x00" * 17, b"other suffix\xff" * 11
            buffers = [ctypes.create_string_buffer(x) for x in (prefix, a, b)]
            out_a, out_b = output(), output()
            rc = lib.check_clone(buffers[0], len(prefix), buffers[1], len(a),
                                 buffers[2], len(b), is224, out_a, out_b)
            checks.equal((rc, bytes(out_a), bytes(out_b)),
                         (0, expected_bytes(prefix + a, is224),
                          expected_bytes(prefix + b, is224)),
                         ("SHA clone/independent suffixes/context erasure", is224, length))


def check_diff(checks, directory):
    first, second = directory / "first", directory / "second"
    payloads = (b"", b"one\nlast", b"one\ntwo\n", b"a\x00b\nlast\x00",
                b"prefix" * 1000 + b"\x00last", b"same line\n" * 12000)
    modes = ((), ("-u",), ("-q",), ("-i",), ("-ui",), ("-uq",), ("-uqi",))
    for index, payload in enumerate(payloads):
        first.write_bytes(payload)
        second.write_bytes(payload)
        for mode in modes:
            checks.equal(checks.run("diff", *mode, first, second), b"",
                         ("diff identical", index, mode))
        checks.equal(checks.run("diff", "-", "-", data=payload), b"",
                     ("diff shared stdin", index))
        checks.equal(checks.run("diff", "-u", "-", second, data=payload), b"",
                     ("diff stdin/file", index))
    first.write_bytes(b"Alpha\n")
    second.write_bytes(b"alpha\n")
    checks.equal(checks.run("diff", "-i", first, second), b"", "diff case-fold fallback")
    checks.equal(bool(checks.run("diff", "-q", first, second, rc=1)), True,
                 "diff changed input still differs")
    second.write_bytes(b"Alpha")
    checks.run("diff", first, second, rc=1)
    checks.count += 1
    checks.run("diff", first, directory / "missing", rc=2)
    checks.count += 1


def check_wc(checks, directory):
    gnu = shutil.which("wc", path="/usr/bin:/bin")
    assert gnu, "GNU wc is required for count comparisons"
    locales = ["C"]
    saved = locale.setlocale(locale.LC_CTYPE)
    try:
        locale.setlocale(locale.LC_CTYPE, "C.UTF-8")
        locales.append("C.UTF-8")
    except locale.Error:
        print("SKIP wc UTF-8 locale: C.UTF-8 is unavailable")
    finally:
        locale.setlocale(locale.LC_CTYPE, saved)

    def reference(args, data, loc):
        result = subprocess.run([gnu, *map(str, args)], input=data, capture_output=True,
                                check=True, timeout=20, env={**checks.env, "LC_ALL": loc})
        return result.stdout.split()

    opts = ("-c", "-l", "-m", "-lc", "-cm", "-lcm", "-w", "-L", "-lwm")
    payloads = (b"", b"one two\nlast", bytes(range(256)) * 257,
                b"\xffA\xe2\x82\xac\xc3\n\xf0\x9f",
                b"a" * 65535 + "\u20ac\n\u754c\tlast".encode(),
                b"\n" * 65536 + b"end")
    # Coreutils before 9.5 ignored encoding errors and some nonprinting
    # bytes while counting words; see tests/wc-tail-parity.sh. Such hosts
    # are not valid word-count references for these non-ASCII payloads.
    # The all-byte cycle has ASCII separators 9..13 and 32; C additionally
    # treats byte 0xA0 as nonbreaking whitespace under GNU's default rules.
    # Adjacent cycles join their last/first words: 1 + 3*257 in C, and
    # 1 + 2*257 in UTF-8. Only bytes 0..127 count as UTF-8 characters here.
    # The short malformed payload has one word on each side of its newline;
    # only A, EURO SIGN, and newline are valid UTF-8 characters.
    corrected_word_counts = {
        (2, "C"): {"l": 257, "w": 1 + 3 * 257, "m": 256 * 257},
        (2, "C.UTF-8"): {"l": 257, "w": 1 + 2 * 257, "m": 128 * 257},
        (3, "C"): {"l": 1, "w": 2, "m": 9},
        (3, "C.UTF-8"): {"l": 1, "w": 2, "m": 3},
        # EURO is attached to the initial a's, then CJK and 'last' are
        # separate words. CJK remains a word even in the C byte locale.
        (4, "C"): {"l": 1, "w": 3, "m": len(payloads[4])},
        (4, "C.UTF-8"): {"l": 1, "w": 3,
                            "m": len(payloads[4].decode("utf-8"))},
    }
    first, second = directory / "first", directory / "second"
    for loc in locales:
        env = {"LC_ALL": loc}
        for index, payload in enumerate(payloads):
            first.write_bytes(payload)
            for opt in opts:
                corrected = corrected_word_counts.get((index, loc))
                if corrected is not None and "w" in opt:
                    expected = [str(corrected[flag]).encode()
                                for flag in "lwm" if flag in opt]
                    expected_file = expected + [os.fsencode(first)]
                    label = "wc corrected words"
                else:
                    expected = reference([opt], payload, loc)
                    expected_file = reference([opt, first], b"", loc)
                    label = "wc GNU parity"
                checks.equal(checks.run("wc", opt, data=payload, env=env).split(), expected,
                             (label, "pipe", loc, index, opt))
                checks.equal(checks.run("wc", opt, first, env=env).split(), expected_file,
                             (label, "regular file", loc, index, opt))
        first.write_bytes(b"first\n" * 12000)
        second.write_bytes("second \u20ac\nlast".encode())
        for opt in ("-c", "-l", "-m", "-lcm"):
            actual = checks.shell('wc "$1" < "$2"; wc "$1" < "$3"',
                                  opt, first, second, env=env)
            expected = reference([opt], first.read_bytes(), loc)
            expected += reference([opt], second.read_bytes(), loc)
            checks.equal(actual.split(), expected, ("wc repeated distinct stdin", loc, opt))
            checks.equal(checks.run("wc", opt, first, second, env=env).split(),
                         reference([opt, first, second], b"", loc),
                         ("wc selected totals", loc, opt))
            remainder = second.read_bytes()
            first.write_bytes(b"PREFIX\n" + remainder)
            actual = checks.shell('exec 0<"$1"; IFS= read -r prefix; '
                                  'wc "$2"; if IFS= read -r extra; then exit 90; fi; :',
                                  first, opt, env=env)
            checks.equal(actual.split(), reference([opt], remainder, loc),
                         ("wc begins at current stdin position", loc, opt))


def check_crypto(checks, directory):
    path = directory / "hash-input"
    for length in (0, 55, 56, 63, 64, 65, 8191, 8192, 8193, 65536, 131137):
        payload = (bytes(range(256)) * ((length + 255) // 256))[:length]
        digest = hashlib.sha256(payload).digest()
        path.write_bytes(payload)
        checks.equal(checks.run("crypto", "sha256", data=payload), digest,
                     ("crypto SHA256 raw pipe", length))
        checks.equal(checks.run("crypto", "sha256", "-x", path).strip(),
                     digest.hex().encode(), ("crypto SHA256 hex file", length))
        for key in (b"\x0b" * 20, bytes(range(100))):
            expected = hmac.new(key, payload, hashlib.sha256).hexdigest().encode()
            checks.equal(checks.run("crypto", "hmac-sha256", "-k", key.hex(),
                                    "-x", data=payload).strip(), expected,
                         ("crypto HMAC-SHA256", length, len(key)))
    path.write_bytes(b"repeated digest\x00\n" * 5000)
    actual = checks.shell('for ((i=0;i<3;i++)); do crypto sha256 -x < "$1" || exit; done', path)
    expected = (hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n") * 3
    checks.equal(actual, expected, "crypto repeated redirected stdin")
    checks.shell('crypto sha256 -x "$1" >/dev/full', path, rc=1)
    checks.count += 1


def check_sv(checks, directory):
    paths = {name: directory / name for name in ("services", "run", "logs")}
    for path in paths.values():
        path.mkdir()
    env = {"BASHSV_DIR": str(paths["services"]), "BASHSV_RUNDIR": str(paths["run"]),
           "BASHSV_LOGDIR": str(paths["logs"])}
    log = paths["logs"] / "fixture"

    def tail(payload, n):
        if not payload:
            return b""
        records = payload.split(b"\n")
        terminated = payload.endswith(b"\n")
        if terminated:
            records.pop()
        return b"\n".join(records[-n:]) + (b"\n" if terminated else b"")

    payloads = [b"", b"one", b"one\n", b"one\ntwo\nlast", b"one\ntwo\n\n",
                b"one\x00tail\nmiddle\x00bytes\nlast\x00",
                b"first\n" + b"long" * 20000 + b"\nend\n",
                b"first\n" + b"partial" * 10000]
    for width in (32767, 32768, 32769):
        payloads.append(b"prefix\n" + (b"x" * (width - 1) + b"\n") * 3 + b"last\n")
    for index, payload in enumerate(payloads):
        log.write_bytes(payload)
        for n in (1, 2, 3, 20, 200):
            checks.equal(checks.run("sv", "log", "fixture", "-n", n, env=env),
                         tail(payload, n), ("sv log complete records", index, n))
        checks.equal(checks.run("sv", "log", "fixture", env=env), tail(payload, 20),
                     ("sv log default count", index))
    # Refreshes observe stable changes between calls. Concurrent rewriting
    # has no atomic-snapshot promise and is deliberately not assumed here.
    for payload in (b"old\n" * 10000, b"old\n" * 10000 + b"appended\n", b"short\n", b""):
        log.write_bytes(payload)
        checks.equal(checks.run("sv", "log", "fixture", "-n", 2, env=env),
                     tail(payload, 2), "sv log refresh after append/truncate")
    log.write_bytes(b"first\nsecond\nlast\n")
    checks.equal(checks.shell('sv log fixture -n 2; sv log fixture -n 1', env=env),
                 b"second\nlast\nlast\n", "sv repeated log calls")
    checks.run("sv", "log", "missing", env=env, rc=1)
    checks.shell('sv log fixture -n 1 >/dev/full', env=env, rc=1)
    checks.count += 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=ROOT / "out/bash")
    parser.add_argument("--only", default=",".join(GROUPS), help="Comma-separated test groups")
    args = parser.parse_args()
    selected = set(args.only.split(","))
    if selected - set(GROUPS):
        parser.error("unknown test groups: " + ", ".join(sorted(selected - set(GROUPS))))
    binary = args.binary.resolve()
    if selected != {"sha"} and not binary.is_file():
        parser.error(f"missing bash-os binary: {binary}")
    checks = Checks(binary)
    functions = {"sha": check_sha, "diff": check_diff, "wc": check_wc,
                 "crypto": check_crypto, "sv": check_sv}
    with tempfile.TemporaryDirectory(prefix="bash-os-core-fastpaths-") as temporary:
        root = Path(temporary)
        for group in GROUPS:
            if group not in selected:
                continue
            before = checks.count
            directory = root / group
            directory.mkdir()
            if group != "sha":
                checks.equal(checks.run("type", "-t", group), b"builtin\n", (group, "builtin"))
            functions[group](checks, directory)
            print(f"core-fastpaths {group}: {checks.count - before} checks passed", flush=True)
    print(f"core-fastpaths: {checks.count} checks passed")


if __name__ == "__main__":
    main()
