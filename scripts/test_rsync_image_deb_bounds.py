"""Focused in-memory Debian/tar regressions; no native extraction or guest."""
import bz2
import gzip
import io
import lzma
import tarfile
import unittest
from unittest.mock import patch

import rsync_image_deb as deb


FIELDS = {"Package": "rsync", "Version": "3.4.1-1", "Architecture": "amd64",
          "Depends": "libc6 (>= 2.38)", "Pre-Depends": "init-system-helpers (>= 1.54~)"}
CONTROL = (b"Package: rsync\nVersion: 3.4.1-1\nArchitecture: amd64\n"
           b"Depends: libc6 (>= 2.38)\nPre-Depends: init-system-helpers (>= 1.54~)\n")
BINARY = b"\x7fELFsynthetic"


def tar_member(name, content=b"", kind=tarfile.REGTYPE, link=""):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = 0o755 if name.endswith("rsync") or kind == tarfile.DIRTYPE else 0o644
    info.linkname = link
    info.size = len(content)
    header = info.tobuf(format=tarfile.USTAR_FORMAT, encoding="utf-8", errors="strict")
    if len(header) != 512:
        raise AssertionError("test header is not a single physical block")
    return header + content + b"\0" * ((-len(content)) % 512)


def archive(*entries):
    return b"".join(entries) + b"\0" * 1024


def ar_member(name, content, *, slash=False):
    token = name + ("/" if slash else "")
    if len(token) > 16:
        raise ValueError("test ar name too long")
    header = (f"{token:<16}{0:<12}{0:<6}{0:<6}{0o100644:<8o}{len(content):<10}`\n").encode("ascii")
    return header + content + (b"\n" if len(content) % 2 else b"")


def package(control=CONTROL, payload=None, *, slash=False):
    if payload is None:
        payload = archive(tar_member("./usr/bin/rsync", BINARY))
    return (b"!<arch>\n" + ar_member("debian-binary", b"2.0\n", slash=slash)
            + ar_member("control.tar", archive(tar_member("./control", control)), slash=slash)
            + ar_member("data.tar", payload, slash=slash))


class DebParserBounds(unittest.TestCase):
    def test_valid_package_and_canonical_ar_name_conventions(self):
        for slash in (False, True):
            with self.subTest(slash=slash):
                parsed = deb.inspect_deb(package(slash=slash), FIELDS)
                self.assertEqual(parsed["binary"], BINARY)
        with self.assertRaises(ValueError):
            deb.inspect_deb(package(), {})

    def test_non_directory_ancestors_are_rejected_in_both_orders(self):
        target = tar_member("usr/bin/rsync", BINARY)
        for path in ("usr", "usr/bin"):
            for kind in (tarfile.REGTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
                item = tar_member(path, b"x" if kind == tarfile.REGTYPE else b"", kind, "elsewhere")
                for parts in ((item, target), (target, item)):
                    with self.subTest(path=path, kind=kind, reverse=parts[0] is target):
                        with self.assertRaisesRegex(ValueError, "ancestor"):
                            deb.index_tar(archive(*parts))

    def test_leaf_links_are_never_resolved_and_target_link_is_rejected(self):
        link = tar_member("usr/share/doc/other", b"", tarfile.SYMTYPE, "readme")
        parsed = deb.index_tar(archive(link, tar_member("usr/bin/rsync", BINARY)))
        self.assertIsNone(parsed["usr/share/doc/other"][1])
        target_link = archive(tar_member("usr/bin/rsync", b"", tarfile.SYMTYPE, "elsewhere"))
        with self.assertRaises(ValueError):
            deb.inspect_deb(package(payload=target_link), FIELDS)

    def test_duplicate_and_unsafe_normalized_paths(self):
        cases = ((tar_member("usr/bin/rsync", BINARY), tar_member("./usr/bin/rsync", BINARY)),
                 (tar_member("../escape", b"x"),), (tar_member("/absolute", b"x"),),
                 (tar_member(".", b"x"),))
        for entries in cases:
            with self.subTest(entries=len(entries)), self.assertRaises(ValueError):
                deb.index_tar(archive(*entries))

    def test_terminal_blocks_and_trailing_bytes_are_strict(self):
        raw = archive(tar_member("usr/bin/rsync", BINARY))
        self.assertIn("usr/bin/rsync", deb.index_tar(raw + b"\0" * 512))
        cases = (raw[:-1024], raw[:-512], raw[:-1], raw + b"garbage",
                 raw + b"X" * 512, raw + archive(tar_member("usr/bin/rsync", b"other")))
        for data in cases:
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                deb.index_tar(data)

    def test_physical_headers_and_small_resource_caps(self):
        raw = archive(tar_member("first", b"abc"), tar_member("second", b"def"))
        with patch.object(deb, "MAX_EXPANDED_BYTES", 5), \
             patch.object(tarfile.TarInfo, "frombuf", side_effect=AssertionError("metadata parser ran")) as parse:
            with self.assertRaisesRegex(ValueError, "aggregate"):
                deb.index_tar(raw)
            parse.assert_not_called()
        with patch.object(deb, "MAX_MEMBER_BYTES", 2), \
             patch.object(tarfile.TarInfo, "frombuf", side_effect=AssertionError("metadata parser ran")) as parse:
            with self.assertRaisesRegex(ValueError, "member size"):
                deb.index_tar(raw)
            parse.assert_not_called()
        with patch.object(deb, "MAX_MEMBERS", 1), \
             patch.object(tarfile.TarInfo, "frombuf", side_effect=AssertionError("metadata parser ran")) as parse:
            with self.assertRaisesRegex(ValueError, "too many"):
                deb.index_tar(raw)
            parse.assert_not_called()
        corrupted = bytearray(raw)
        corrupted[0] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum"):
            deb.index_tar(bytes(corrupted))

    def test_real_pax_sparse_rejected_before_tarfile_expansion(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:", format=tarfile.PAX_FORMAT) as tar:
            item = tarfile.TarInfo("usr/bin/rsync")
            item.size = 1
            item.pax_headers = {"GNU.sparse.map": ",".join(["0", "1"] * 500),
                                "GNU.sparse.size": "1000000"}
            tar.addfile(item, io.BytesIO(b"x"))
        raw = output.getvalue()
        self.assertEqual(raw[156:157], tarfile.XHDTYPE)
        with patch.object(tarfile.TarInfo, "_proc_gnusparse_01",
                          side_effect=AssertionError("sparse map expanded")) as sparse, \
             patch.object(tarfile.TarInfo, "frombuf", side_effect=AssertionError("metadata parser ran")) as parse:
            with self.assertRaises(deb.UnsupportedPackage):
                deb.index_tar(raw)
            sparse.assert_not_called()
            parse.assert_not_called()

    def test_extension_headers_cannot_recurse(self):
        extension = tar_member("extension", b"x", tarfile.XHDTYPE)
        raw = archive(*([extension] * 600), tar_member("usr/bin/rsync", BINARY))
        with patch.object(tarfile.TarInfo, "frombuf", side_effect=AssertionError("metadata parser ran")) as parse:
            with self.assertRaises(deb.UnsupportedPackage):
                deb.index_tar(raw)
            parse.assert_not_called()
        for kind in (tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
                     tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind), self.assertRaises(deb.UnsupportedPackage):
                deb.index_tar(archive(tar_member("metadata", b"", kind)))

    def test_control_is_one_complete_well_formed_paragraph(self):
        self.assertEqual(deb.inspect_deb(package(), FIELDS)["binary"], BINARY)
        cases = (CONTROL + b"not a field\nVersion: 2\n",
                 CONTROL + b"\nVersion: 2\n", CONTROL + b"vErSiOn: 2\n",
                 b" continuation before field\n" + CONTROL,
                 CONTROL + b"\n continued after paragraph\n", CONTROL[:-1],
                 CONTROL.replace(b"Version:", b"Version :", 1),
                 CONTROL.replace(b"Version:", b"Version\r:", 1))
        for control in cases:
            with self.subTest(control=control), self.assertRaises(ValueError):
                deb.inspect_deb(package(control=control), FIELDS)
        folded = CONTROL.replace(b"Depends: libc6 (>= 2.38)\n",
                                 b"Depends: libc6\n (>= 2.38)\n")
        self.assertEqual(deb.inspect_deb(package(control=folded), FIELDS)["binary"], BINARY)

    def test_ar_member_names_order_and_unsupported_compression(self):
        control = ar_member("control.tar", archive(tar_member("control", CONTROL)))
        data = ar_member("data.tar", archive(tar_member("usr/bin/rsync", BINARY)))
        prefix = b"!<arch>\n" + ar_member("debian-binary", b"2.0\n")
        cases = (prefix + data + control,
                 prefix + ar_member("control.tar.tar", b"") + data,
                 prefix + ar_member("control.tar", archive(tar_member("control", CONTROL)), slash=True) + data,
                 prefix + control + data + ar_member("extra", b""),
                 package()[:-1])
        for raw in cases:
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                deb.parse_ar(raw)
        with self.assertRaises(deb.UnsupportedPackage):
            deb.parse_ar(prefix + ar_member("control.tar.zst", b"") + data)
        with self.assertRaises(deb.UnsupportedPackage):
            deb.unpack_tar("data.tar.tar", b"")

    def test_decompression_rejects_truncation_concatenation_and_oversize(self):
        data = b"bounded-data"
        for name, encode in (("data.tar.gz", gzip.compress), ("data.tar.xz", lzma.compress),
                             ("data.tar.bz2", bz2.compress)):
            encoded = encode(data)
            self.assertEqual(deb.unpack_tar(name, encoded), data)
            for bad in (encoded[:-1], encoded + encoded, encoded + b"extra"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    deb.unpack_tar(name, bad)
            with patch.object(deb, "MAX_TAR", 5), self.assertRaises(ValueError):
                deb.unpack_tar(name, encoded)


if __name__ == "__main__":
    unittest.main()
