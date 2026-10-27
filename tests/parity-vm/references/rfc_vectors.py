#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host-only generator: extract published RFC test vectors as data.

Reads the RFC texts pinned in rfc.lock.json, extracts each vector from the
normative text by anchor and byte count, recomputes it with an independent
implementation (Python hashlib/hmac/base64 and, when installed, the
'cryptography' package), and writes rfc-vectors.json. A vector is written only
when the RFC text and the recomputation agree. Nothing here runs the candidate.

    python3 references/rfc_vectors.py --rfc-dir DIR [--fetch]
"""
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
import sys
import urllib.request

HERE = Path(__file__).resolve().parent
LOCK = HERE / "rfc.lock.json"
OUTPUT = HERE / "rfc-vectors.json"
INPUTS = "/tmp/parity-reference/inputs/"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean(text):
    """Drop page headers/footers so values that cross a page break stay contiguous."""
    lines = []
    for line in text.replace("\f", "\n").splitlines():
        if "[Page " in line or re.match(r"^RFC \d{4} ", line):
            continue
        lines.append(line)
    return "\n".join(lines)


class Text:
    def __init__(self, number, text):
        self.number, self.text = number, clean(text)

    def section(self, start, end=None):
        """Text from the last line-initial START (body, not the table of contents) to END."""
        starts = [m.start() for m in re.finditer("^" + re.escape(start), self.text, re.M)]
        if not starts:
            raise ValueError("RFC %d: no section %r" % (self.number, start))
        begin = starts[-1]
        stop = self.text.index(end, begin + len(start)) if end else len(self.text)
        return Section(self, self.text[begin:stop])


class Section:
    def __init__(self, rfc, text):
        self.rfc, self.text, self.cursor = rfc, text, 0

    def hex(self, anchor, count, style="tokens"):
        """Collect COUNT bytes of hex after ANCHOR (searched from the cursor)."""
        where = self.text.index(anchor, self.cursor) + len(anchor)
        out = bytearray()
        position = where
        for line in self.text[where:].splitlines(keepends=True):
            position += len(line)
            if style == "dump":   # '000  4c 61 ...  ascii' rows (RFC 8439)
                match = re.match(r"^\s*\d{3}\s+((?:[0-9a-fA-F]{2} )*[0-9a-fA-F]{2})(?:\s|$)", line)
                tokens = match.group(1).split() if match else []
            else:
                tokens = line.replace(":", " ").split()
            for token in tokens:
                token = token[2:] if token.startswith("0x") else token
                if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", token):
                    out += bytes.fromhex(token)
                elif out:
                    break
                if len(out) >= count:
                    break
            if len(out) >= count:
                break
        if len(out) != count:
            raise ValueError("RFC %d: %r yielded %d of %d bytes" % (self.rfc.number, anchor, len(out), count))
        self.cursor = position
        return bytes(out)


class Vectors:
    def __init__(self):
        self.items, self.inputs = [], {}
        self.unexecutable = []

    def add(self, ident, loadable, rfc, section, argv, expected, *, stdin=b"", repeat=1, status=0, note=None):
        """STDIN (repeated REPEAT times) becomes a regular file the command reads on fd 0."""
        name = None
        if stdin:
            name = hashlib.sha256(stdin * repeat).hexdigest()[:16]
            self.inputs[name] = {"hex": stdin.hex(), "repeat": repeat}
        if any("\0" in word for word in argv):
            raise ValueError(ident + ": NUL in argv")
        self.items.append({"id": ident, "loadable": loadable, "rfc": rfc, "section": section, "argv": argv,
                           "stdin": name, "expected_stdout_hex": expected.hex() if isinstance(expected, bytes)
                           else expected, "expected_status": status, **({"note": note} if note else {})})

    def skip(self, ident, rfc, section, reason):
        self.unexecutable.append({"id": ident, "rfc": rfc, "section": section, "reason": reason})


def hmac_vectors(rfcs, v):
    t = rfcs[4231]
    cases = [("4.2", "Test Case 1", 20, 8), ("4.3", "Test Case 2", 4, 28), ("4.4", "Test Case 3", 20, 50),
             ("4.5", "Test Case 4", 25, 50), ("4.7", "Test Case 6", 131, 54), ("4.8", "Test Case 7", 131, 152)]
    for number, title, klen, dlen in cases:
        s = t.section(number + ".  " + title)
        key, data = s.hex("Key", klen), s.hex("Data =", dlen)
        s.hex("HMAC-SHA-224 =", 28)
        h256 = s.hex("HMAC-SHA-256 =", 32)
        s.hex("HMAC-SHA-384 =", 48)
        h512 = s.hex("HMAC-SHA-512 =", 64)
        for name, digest, func in (("sha256", h256, hashlib.sha256), ("sha512", h512, hashlib.sha512)):
            if hmac.new(key, data, func).digest() != digest:
                raise ValueError("RFC 4231 %s %s disagrees with hmac" % (title, name))
            v.add("rfc4231-%s-hmac-%s" % (title.lower().replace(" ", ""), name), "crypto", 4231, title,
                  ["crypto", "hmac-" + name, "-k", key.hex(), "-x"], (digest.hex() + "\n").encode(), stdin=data)
    v.skip("rfc4231-testcase5", 4231, "4.6", "truncated 128-bit outputs; the full HMAC is not published")
    t = rfcs[2202]
    lines = t.text.splitlines()
    block, current, algo = [], {}, None
    for line in lines:
        if line.startswith("4. "):
            break
        m = re.match(r"^(test_case|key|key_len|data|data_len|digest) =?\s+(.*)$", line.strip())
        if line.startswith("3. Test Cases for HMAC-SHA-1"):
            algo = "sha1"
        if line.startswith("2. Test Cases for HMAC-MD5"):
            algo = "md5"
        last = current.get("_last")
        if not m:
            if last and current[last].startswith('"') and not current[last].endswith('"') and line.strip():
                current[last] += " " + line.strip()   # quoted value wrapped onto the next line
            continue
        key, value = m.group(1), m.group(2).strip()
        current["_last"] = key
        if key == "test_case":
            current = {"_algo": algo, "test_case": value}
            block.append(current)
        elif key not in current:   # RFC 2202 repeats a fragment after SHA-1 case 7; first value wins
            current[key] = value

    def literal(value):
        match = re.fullmatch(r"0x(\w\w) repeated (\d+) times", value)
        if match:
            return bytes.fromhex(match.group(1)) * int(match.group(2))
        if value.startswith("0x"):
            return bytes.fromhex(value[2:])
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1].encode()
        raise ValueError("RFC 2202 value %r" % value)

    seen = {}
    for case in block:
        algo = case["_algo"]
        fields = tuple(case.get(k) for k in ("key", "key_len", "data", "data_len", "digest"))
        if (algo, case["test_case"]) in seen:
            if seen[algo, case["test_case"]] != fields:
                raise ValueError("RFC 2202 repeats %s case %s with different values" % (algo, case["test_case"]))
            continue
        seen[algo, case["test_case"]] = fields
        key, data = literal(case["key"]), literal(case["data"])
        digest = bytes.fromhex(case["digest"][2:])
        if len(key) != int(case["key_len"]) or len(data) != int(case["data_len"]):
            raise ValueError("RFC 2202 length mismatch in %s case %s" % (algo, case["test_case"]))
        if hmac.new(key, data, getattr(hashlib, algo)).digest() != digest:
            raise ValueError("RFC 2202 %s case %s disagrees with hmac" % (algo, case["test_case"]))
        v.add("rfc2202-hmac-%s-tc%s" % (algo, case["test_case"]), "crypto", 2202, algo + " case " + case["test_case"],
              ["crypto", "hmac-" + algo, "-k", key.hex(), "-x"], (digest.hex() + "\n").encode(), stdin=data)


def hkdf_vectors(rfcs, v):
    t = rfcs[5869]
    for number, (ilen, slen, info_len, length) in enumerate([(22, 13, 10, 42), (80, 80, 80, 82), (22, 0, 0, 42)], 1):
        s = t.section("A.%d.  Test Case %d" % (number, number), "A.%d." % (number + 1))
        ikm = s.hex("IKM  =", ilen)
        salt = s.hex("salt =", slen) if slen else b""
        info = s.hex("info =", info_len) if info_len else b""
        s.hex("PRK  =", 32)
        okm = s.hex("OKM  =", length)
        prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
        derived, block = b"", b""
        for counter in range(1, -(-length // 32) + 1):
            block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
            derived += block
        if derived[:length] != okm:
            raise ValueError("RFC 5869 case %d disagrees with HKDF recomputation" % number)
        for verb in (["crypto", "hkdf-sha256"], ["crypto", "hkdf", "-a", "sha256"]):
            argv = verb + ["-s", salt.hex(), "-k", ikm.hex(), "-i", info.hex(), "-L", str(length), "-x"]
            v.add("rfc5869-a%d-%s" % (number, verb[1]), "crypto", 5869, "A.%d" % number, argv,
                  (okm.hex() + "\n").encode())


def pbkdf2_vectors(rfcs, v):
    t = rfcs[6070]
    s = t.section("2.  PBKDF2 HMAC-SHA1 Test Vectors", "3.  ")
    for index, match in enumerate(re.finditer(r'P = "([^"]*)" \((\d+) octets\)\s+S = "([^"]*)" \((\d+) octets\)\s+'
                                              r'c = (\d+)\s+dkLen = (\d+)', s.text), 1):
        password = match.group(1).replace("\\0", "\0").encode()
        salt = match.group(3).replace("\\0", "\0").encode()
        count, length = int(match.group(5)), int(match.group(6))
        if len(password) != int(match.group(2)) or len(salt) != int(match.group(4)):
            raise ValueError("RFC 6070 length mismatch")
        s.cursor = match.end()
        dk = s.hex("DK =", length)
        ident = "rfc6070-pbkdf2-sha1-%d" % index
        if b"\0" in password:
            v.skip(ident, 6070, "2", "password contains NUL; -p PASSWORD is a C string from Bash argv")
            continue
        if count > 100000:
            v.skip(ident, 6070, "2", "c=%d is a 16M-iteration stress vector; omitted from the bounded VM run" % count)
            continue
        if hashlib.pbkdf2_hmac("sha1", password, salt, count, length) != dk:
            raise ValueError(ident + " disagrees with hashlib")
        v.add(ident, "crypto", 6070, "2", ["crypto", "pbkdf2", "-a", "sha1", "-s", salt.hex(), "-p",
                                           password.decode(), "-i", str(count), "-L", str(length), "-x"],
              (dk.hex() + "\n").encode())
    t = rfcs[7914]
    s = t.section("11.  Test Vectors for PBKDF2 with HMAC-SHA-256", "12.  ")
    for index, match in enumerate(re.finditer(r'P="(\w+)", S="(\w+)",\s+c=(\d+), dkLen=(\d+)\) =', s.text), 1):
        password, salt = match.group(1).encode(), match.group(2).encode()
        count, length = int(match.group(3)), int(match.group(4))
        s.cursor = match.end()
        dk = s.hex("", length)
        if hashlib.pbkdf2_hmac("sha256", password, salt, count, length) != dk:
            raise ValueError("RFC 7914 vector %d disagrees with hashlib" % index)
        v.add("rfc7914-pbkdf2-sha256-%d" % index, "crypto", 7914, "11",
              ["crypto", "pbkdf2", "-a", "sha256", "-s", salt.hex(), "-p", password.decode(), "-i", str(count),
               "-L", str(length), "-x"], (dk.hex() + "\n").encode())


def digest_vectors(rfcs, v):
    t = rfcs[1321]
    for match in re.finditer(r'MD5 \("([^"]*)"\) =\s*([0-9a-f]{32})', t.text.replace('\n78901234567890"', '78901234567890"')):
        message, digest = match.group(1).encode(), bytes.fromhex(match.group(2))
        if hashlib.md5(message).digest() != digest:
            raise ValueError("RFC 1321 vector disagrees with hashlib")
        v.add("rfc1321-md5-%d" % len(message), "crypto", 1321, "A.5", ["crypto", "md5", "-x"],
              (digest.hex() + "\n").encode(), stdin=message)
    t = rfcs[6234]
    defines = {"TEST1": b"abc", "TEST2_1": b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
               "TEST2_2": b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                          b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
               "TEST3": b"a", "TEST4": b"01234567012345670123456701234567" * 2}
    for literal in ('#define TEST1    "abc"', '"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"',
                    '"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"',
                    '"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"', '#define TEST3    "a"',
                    '#define TEST4a   "01234567012345670123456701234567"',
                    '#define TEST4   TEST4a TEST4b', '#define TEST2_2  TEST2_2a TEST2_2b'):
        if literal not in t.text:   # the patterns above must be the RFC's own
            raise ValueError("RFC 6234 pattern %s not found" % literal)
    table = t.text[t.text.index("} hashes[HASHCOUNT] = {"):]
    for algo, func in (("SHA1", "sha1"), ("SHA256", "sha256"), ("SHA384", "sha384"), ("SHA512", "sha512")):
        block = table[table.index('{ "%s", ' % algo):]
        block = block[:block.index("_SEED")]
        for match in re.finditer(r"/\* (\d+) \*/ \{ (TEST\w+), length\(\2\), (\d+), 0, 0,\s*((?:\"[0-9A-F]+\"\s*)+)\}",
                                 block):
            pattern = match.group(2)
            if pattern not in defines:
                continue
            unit, repeat = defines[pattern], int(match.group(3))
            digest = bytes.fromhex("".join(re.findall(r'"([0-9A-F]+)"', match.group(4))))
            if hashlib.new(func, unit * repeat).digest() != digest:
                raise ValueError("RFC 6234 %s %s disagrees with hashlib" % (algo, pattern))
            v.add("rfc6234-%s-%s" % (func, pattern.lower()), "crypto", 6234, "8.4 " + algo,
                  ["crypto", func, "-x"], (digest.hex() + "\n").encode(), stdin=unit, repeat=repeat)
    t = rfcs[7693]
    s = t.section("Appendix A.  Example of BLAKE2b Computation", "Appendix B.")
    digest = s.hex('BLAKE2b-512("abc") =', 64)
    if hashlib.blake2b(b"abc").digest() != digest:
        raise ValueError("RFC 7693 Appendix A disagrees with hashlib")
    v.add("rfc7693-blake2b-512-abc", "crypto", 7693, "Appendix A", ["crypto", "blake2b", "-x"],
          (digest.hex() + "\n").encode(), stdin=b"abc")


def base_vectors(rfcs, v):
    t = rfcs[4648]
    s = t.section("10.  Test Vectors", "11.  ")
    for match in re.finditer(r'BASE64\("(\w*)"\) = "([\w=]*)"', s.text):
        raw, encoded = match.group(1).encode(), match.group(2)
        if base64.b64encode(raw).decode() != encoded:
            raise ValueError("RFC 4648 base64 vector disagrees with base64")
        # These vectors contain no '+' or '/', so the base64url alphabet (section 5) is identical.
        unpadded = encoded.rstrip("=")
        v.add("rfc4648-base64url-pad-%d" % len(raw), "crypto", 4648, "10", ["crypto", "base64url", "-e", "--pad"],
              encoded.encode(), stdin=raw, note="raw encoder output: no trailing newline")
        v.add("rfc4648-base64url-nopad-%d" % len(raw), "crypto", 4648, "10", ["crypto", "base64url", "-e", "--no-pad"],
              unpadded.encode(), stdin=raw, note="RFC 4648 section 3.2 permits omitting padding when specified")
        if raw:
            v.add("rfc4648-base64url-decode-%d" % len(raw), "crypto", 4648, "10", ["crypto", "base64url", "-d"],
                  raw, stdin=encoded.encode())


def totp_vectors(rfcs, v):
    t = rfcs[6238]
    code = t.text[t.text.index("Appendix A.  TOTP Algorithm: Reference Implementation"):]
    seeds = {}
    for name, length in (("seed", 20), ("seed32", 32), ("seed64", 64)):
        match = re.search(r'String %s = ((?:"[0-9]+"\s*\+?\s*)+);' % name, code)
        seeds[name] = bytes.fromhex("".join(re.findall(r'"([0-9]+)"', match.group(1))))
        if len(seeds[name]) != length:
            raise ValueError("RFC 6238 %s length" % name)
    table = t.text[t.text.index("Appendix B.  Test Vectors"):]
    rows = re.findall(r"\|\s+(\d+)\s+\|\s+[\d-]+\s+\|\s+([0-9A-F]{16})\s+\|\s+(\d{8})\s+\|\s+(SHA\d+)\s+\|", table)
    if len(rows) != 18:
        raise ValueError("RFC 6238 table has %d rows" % len(rows))
    for when, counter, otp, mode in rows:
        seed = {"SHA1": seeds["seed"], "SHA256": seeds["seed32"], "SHA512": seeds["seed64"]}[mode]
        digest = hmac.new(seed, struct.pack(">Q", int(when) // 30), mode.lower()).digest()
        offset = digest[-1] & 15
        value = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 10**8
        if int(counter, 16) != int(when) // 30 or "%08d" % value != otp:
            raise ValueError("RFC 6238 row %s %s disagrees with HOTP recomputation" % (when, mode))
        secret = base64.b32encode(seed).decode()
        v.add("rfc6238-totp-%s-%s" % (mode.lower(), when), "totp", 6238, "Appendix B",
              ["totp", "generate", "-k", secret, "-t", when, "-d", "8", "-s", "30", "-a", mode.lower()],
              (otp + "\n").encode(),
              note="Appendix B's prose names a 20-byte seed; the table uses the Appendix A 32/64-byte seeds (RFC 6238 erratum 2866)")
        v.add("rfc6238-totp-verify-%s-%s" % (mode.lower(), when), "totp", 6238, "Appendix B",
              ["totp", "verify", "-k", secret, "-c", otp, "-w", "0", "-t", when, "-d", "8", "-s", "30",
               "-a", mode.lower()], b"", status=0)


def curve_vectors(rfcs, v, crypto):
    t = rfcs[8032]
    s = t.section("7.1.  Test Vectors for Ed25519", "7.2.  ")
    for name, length in (("TEST 1", 0), ("TEST 2", 1), ("TEST 3", 2), ("TEST 1024", 1023), ("TEST SHA(abc)", 64)):
        s.cursor = s.text.index("-----" + name)
        secret = s.hex("SECRET KEY:", 32)
        public = s.hex("PUBLIC KEY:", 32)
        message = s.hex("bytes):" if length != 1 else "byte):", length) if length else b""
        signature = s.hex("SIGNATURE:", 64)
        if crypto:
            key = crypto.ed25519.Ed25519PrivateKey.from_private_bytes(secret)
            if key.sign(message) != signature or key.public_key().public_bytes_raw() != public:
                raise ValueError("RFC 8032 %s disagrees with cryptography" % name)
        tag = name.split()[-1].lower().replace("(", "").replace(")", "")
        v.add("rfc8032-ed25519-pub-%s" % tag, "crypto", 8032, "7.1 " + name, ["crypto", "ed25519-pub", "-k",
                                                                             secret.hex(), "-x"],
              (public.hex() + "\n").encode())
        v.add("rfc8032-ed25519-sign-%s" % tag, "crypto", 8032, "7.1 " + name, ["crypto", "ed25519-sign", "-k",
                                                                              secret.hex(), "-x"],
              (signature.hex() + "\n").encode(), stdin=message)
        v.add("rfc8032-ed25519-verify-%s" % tag, "crypto", 8032, "7.1 " + name,
              ["crypto", "ed25519-verify", "-k", public.hex(), "-s", signature.hex()], b"", stdin=message)
        forged = bytes([signature[0] ^ 1]) + signature[1:]
        v.add("rfc8032-ed25519-verify-altered-%s" % tag, "crypto", 8032, "7.1 " + name,
              ["crypto", "ed25519-verify", "-k", public.hex(), "-s", forged.hex()], b"", stdin=message, status=1,
              note="first signature byte flipped; RFC 8032 5.1.7 verification must reject")
    s = t.section("7.4.  Test Vectors for Ed448", "7.5.  ")
    for name, length in (("-----Blank", 0), ("-----1 octet\n", 1), ("-----11 octets", 11), ("-----12 octets", 12),
                         ("-----13 octets", 13), ("-----64 octets", 64), ("-----256 octets", 256),
                         ("-----1023 octets", 1023)):
        s.cursor = s.text.index(name)
        s.hex("SECRET KEY:", 57)
        public = s.hex("PUBLIC KEY:", 57)
        message = s.hex("):", length) if length else b""
        signature = s.hex("SIGNATURE:", 114)
        if crypto:
            crypto.ed448.Ed448PublicKey.from_public_bytes(public).verify(signature, message)  # raises if invalid
        tag = name.strip("-\n ").split()[0].lower()
        v.add("rfc8032-ed448-verify-%s" % tag, "crypto", 8032, "7.4 " + name.strip("-\n "),
              ["crypto", "ed448-verify", "-k", public.hex(), "-s", signature.hex()], b"", stdin=message)
    t = rfcs[7748]
    s = t.section("5.2.  Test Vectors", "   X448:")
    for index in (1, 2):
        scalar = s.hex("Input scalar:", 32)
        u = s.hex("Input u-coordinate:", 32)
        out = s.hex("Output u-coordinate:", 32)
        if crypto:
            got = crypto.x25519.X25519PrivateKey.from_private_bytes(scalar).exchange(
                crypto.x25519.X25519PublicKey.from_public_bytes(u))
            if got != out:
                raise ValueError("RFC 7748 5.2 vector %d disagrees with cryptography" % index)
        v.add("rfc7748-x25519-%d" % index, "crypto", 7748, "5.2", ["crypto", "x25519-shared", "-p", u.hex(), "-k",
                                                                   scalar.hex(), "-x"], (out.hex() + "\n").encode())
    s = t.section("6.1.  Curve25519", "6.2.  ")
    a, ka = s.hex("Alice's private key, a:", 32), s.hex("Alice's public key, X25519(a, 9):", 32)
    b, kb = s.hex("Bob's private key, b:", 32), s.hex("Bob's public key, X25519(b, 9):", 32)
    k = s.hex("Their shared secret, K:", 32)
    v.add("rfc7748-x25519-alice-public", "crypto", 7748, "6.1", ["crypto", "x25519-pub", "-k", a.hex(), "-x"],
          (ka.hex() + "\n").encode())
    v.add("rfc7748-x25519-bob-public", "crypto", 7748, "6.1", ["crypto", "x25519-pub", "-k", b.hex(), "-x"],
          (kb.hex() + "\n").encode())
    v.add("rfc7748-x25519-alice-shared", "crypto", 7748, "6.1",
          ["crypto", "x25519-shared", "-p", kb.hex(), "-k", a.hex(), "-x"], (k.hex() + "\n").encode())
    v.add("rfc7748-x25519-bob-shared", "crypto", 7748, "6.1",
          ["crypto", "x25519-shared", "-p", ka.hex(), "-k", b.hex(), "-x"], (k.hex() + "\n").encode())


def aead_vectors(rfcs, v, crypto):
    t = rfcs[8439]
    s = t.section("2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305", "3.  Implementation Advice")
    plaintext = s.hex("Plaintext:", 114, "dump")
    aad = s.hex("AAD:", 12, "dump")
    key = s.hex("Key:", 32, "dump")
    iv = s.hex("IV:", 8, "dump")
    fixed = s.hex("32-bit fixed-common part:", 4, "dump")
    ciphertext = s.hex("Ciphertext:", 114, "dump")
    tag = s.hex("Tag:", 16)
    nonce = fixed + iv
    if plaintext[:16] != b"Ladies and Gentl":
        raise ValueError("RFC 8439 plaintext extraction")
    if crypto and crypto.ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad) != ciphertext + tag:
        raise ValueError("RFC 8439 2.8.2 disagrees with cryptography")
    v.add("rfc8439-chacha20-poly1305-encrypt", "crypto", 8439, "2.8.2",
          ["crypto", "chacha20-poly1305", "-e", "-k", key.hex(), "-n", nonce.hex(), "-A", aad.hex()],
          ciphertext + tag, stdin=plaintext)
    v.add("rfc8439-chacha20-poly1305-decrypt", "crypto", 8439, "2.8.2",
          ["crypto", "chacha20-poly1305", "-d", "-k", key.hex(), "-n", nonce.hex(), "-A", aad.hex()],
          plaintext, stdin=ciphertext + tag)
    t = rfcs[5297]
    s = t.section("A.1.  Deterministic Authenticated Encryption Example", "A.2.  ")
    key, ad, plaintext = s.hex("Key:", 32), s.hex("AD:", 24), s.hex("Plaintext:", 14)
    output = s.hex("IV || C:", 30)
    cases = [("a1", key, [ad], plaintext, output)]
    s = t.section("A.2.  Nonce-Based Authenticated Encryption Example")
    key, ad1, ad2 = s.hex("Key:", 32), s.hex("AD1:", 40), s.hex("AD2:", 10)
    nonce, plaintext = s.hex("Nonce:", 16), s.hex("Plaintext:", 47)
    output = s.hex("IV || C:", 63)
    cases.append(("a2", key, [ad1, ad2, nonce], plaintext, output))
    for name, key, ads, plaintext, output in cases:
        if crypto and crypto.AESSIV(key).encrypt(plaintext, ads) != output:
            raise ValueError("RFC 5297 %s disagrees with cryptography" % name)
        extra = [word for ad in ads for word in ("-A", ad.hex())]
        # Raw mode: with -x the command also expects hex on stdin (loadables/crypto.c).
        v.add("rfc5297-%s-encrypt" % name, "crypto", 5297, name.upper(),
              ["crypto", "aes-siv-cmac", "-e", "-k", key.hex()] + extra, output,
              stdin=plaintext, note="A.2 passes the nonce as the final associated-data component (RFC 5297 section 3)"
              if name == "a2" else None)
        v.add("rfc5297-%s-decrypt" % name, "crypto", 5297, name.upper(),
              ["crypto", "aes-siv-cmac", "-d", "-k", key.hex()] + extra, plaintext, stdin=output)


def fetch(directory, lock):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for entry in lock["files"]:
        path = directory / entry["name"]
        if path.is_file() and sha256(path) == entry["sha256"]:
            continue
        with urllib.request.urlopen(entry["url"], timeout=60) as source:
            data = source.read(entry["bytes"] + 1)
        if hashlib.sha256(data).hexdigest() != entry["sha256"] or len(data) != entry["bytes"]:
            raise SystemExit("downloaded %s does not match the lock" % entry["name"])
        path.write_bytes(data)
        path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rfc-dir", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    lock = json.loads(LOCK.read_text())
    if args.fetch:
        fetch(args.rfc_dir, lock)
    rfcs = {}
    for entry in lock["files"]:
        path = args.rfc_dir / entry["name"]
        if sha256(path) != entry["sha256"]:
            raise SystemExit("%s does not match rfc.lock.json" % path)
        rfcs[entry["rfc"]] = Text(entry["rfc"], path.read_text(encoding="utf-8", errors="strict"))
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESSIV, ChaCha20Poly1305
        import cryptography

        class Crypto:
            pass
        crypto = Crypto()
        crypto.ed25519, crypto.ed448, crypto.x25519 = ed25519, ed448, x25519
        crypto.AESSIV, crypto.ChaCha20Poly1305 = AESSIV, ChaCha20Poly1305
        second = "cryptography " + cryptography.__version__
    except ImportError:
        crypto, second = None, None
    v = Vectors()
    hmac_vectors(rfcs, v)
    hkdf_vectors(rfcs, v)
    pbkdf2_vectors(rfcs, v)
    digest_vectors(rfcs, v)
    base_vectors(rfcs, v)
    totp_vectors(rfcs, v)
    curve_vectors(rfcs, v, crypto)
    aead_vectors(rfcs, v, crypto)
    ids = [item["id"] for item in v.items]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate vector ids")
    data = {"schema": 1, "lock_sha256": sha256(LOCK), "inputs_directory": INPUTS,
            "cross_checks": ["Python %s hashlib/hmac/base64" % sys.version.split()[0]] + ([second] if second else []),
            "unchecked_without_cryptography": [] if crypto else ["Ed25519", "Ed448", "X25519", "ChaCha20-Poly1305",
                                                                 "AES-SIV"],
            "vectors": v.items, "not_executable": v.unexecutable, "inputs": v.inputs}
    OUTPUT.write_text(json.dumps(data, indent=1) + "\n")
    print("wrote %d vectors (%d not executable) to %s" % (len(v.items), len(v.unexecutable), OUTPUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
