"""Pure small-data checks for Debian package inspection; no subprocesses."""
import gzip
import hashlib
import io
import tarfile
import unittest
from unittest.mock import patch

import rsync_image_deb as package


FIELDS = {"Package": "rsync", "Version": "3.4.1-1", "Architecture": "amd64"}
CONTROL = b"Package: rsync\nVersion: 3.4.1-1\nArchitecture: amd64\n"
EXECUTABLE = b"\x7fELFsynthetic-package-data"


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, content, mode, pax in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.size = len(content)
            info.pax_headers = pax
            tar.addfile(info, io.BytesIO(content))
    return stream.getvalue()


def member(name, data):
    header = (name + "/").ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6)
    header += "100644".ljust(8) + str(len(data)).ljust(10) + "`\n"
    assert len(header) == 60
    return header.encode("ascii") + data + (b"\n" if len(data) % 2 else b"")


def deb(control=CONTROL, payload=None, extra_control=()):
    if payload is None:
        payload = [("./usr/bin/rsync", EXECUTABLE, 0o755, {})]
    controls = [("./control", control, 0o644, {})] + list(extra_control)
    return b"!<arch>\n" + member("debian-binary", b"2.0\n") + member(
        "control.tar", archive(controls)) + member("data.tar", archive(payload))


class PackageInspectionTests(unittest.TestCase):
    def test_exact_package_bytes_and_script_hashes_are_returned(self):
        script = b"#!/bin/sh\nexit 0\n"
        data = deb(extra_control=[("postinst", script, 0o755, {})])
        result = package.inspect_deb(data, FIELDS)
        self.assertEqual(result["binary"], EXECUTABLE)
        self.assertEqual(result["binary_sha256"], hashlib.sha256(EXECUTABLE).hexdigest())
        self.assertEqual(result["scripts"], {"postinst": script})
        self.assertEqual(result["script_sha256"]["postinst"], hashlib.sha256(script).hexdigest())
        self.assertEqual(result["deb_sha256"], hashlib.sha256(data).hexdigest())

    def test_signed_fields_and_duplicate_control_fields_fail(self):
        mutations = [CONTROL.replace(b"3.4.1-1", b"3.4.1-2"),
                     CONTROL + b"Package: alternate\n",
                     CONTROL.replace(b"amd64", b"arm64")]
        for control in mutations:
            with self.subTest(control=control), self.assertRaises(ValueError):
                package.inspect_deb(deb(control=control), FIELDS)

    def test_executable_mode_and_location_are_required(self):
        for name, mode in [("usr/bin/rsync", 0o644), ("usr/local/bin/rsync", 0o755)]:
            with self.subTest(name=name, mode=mode), self.assertRaises(ValueError):
                package.inspect_deb(deb(payload=[(name, EXECUTABLE, mode, {})]), FIELDS)

    def test_traversal_and_duplicate_normalized_paths_fail(self):
        for entries in [[("../escape", b"x", 0o644, {})],
                        [("usr/bin/rsync", EXECUTABLE, 0o755, {}),
                         ("./usr/bin/rsync", EXECUTABLE, 0o755, {})]]:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                package.inspect_deb(deb(payload=entries), FIELDS)

    def test_symlink_does_not_substitute_for_executable(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            info = tarfile.TarInfo("usr/bin/rsync")
            info.type = tarfile.SYMTYPE
            info.linkname = "alternate"
            info.mode = 0o755
            tar.addfile(info)
        control_tar = archive([("control", CONTROL, 0o644, {})])
        data = b"!<arch>\n" + member("debian-binary", b"2.0\n") + member(
            "control.tar", control_tar) + member("data.tar", stream.getvalue())
        with self.assertRaises(ValueError):
            package.inspect_deb(data, FIELDS)

    def test_sparse_pax_is_rejected_before_content_read(self):
        # Small ordinary content with a sparse declaration: no sparse expansion.
        raw = archive([("usr/bin/rsync", b"x", 0o755, {"SCHILY.realsize": "1"})])
        with patch.object(tarfile.TarFile, "extractfile", side_effect=AssertionError("must reject before read")):
            with self.assertRaises(package.UnsupportedPackage):
                package.index_tar(raw)

    def test_global_expanded_budget_precedes_second_content_read(self):
        raw = archive([("first", b"1234", 0o644, {}), ("second", b"5678", 0o644, {})])
        with patch.object(package, "MAX_EXPANDED_BYTES", 6):
            with self.assertRaisesRegex(ValueError, "aggregate"):
                package.index_tar(raw)

    def test_member_count_limit_and_member_size_limit(self):
        raw = archive([("one", b"1", 0o644, {}), ("two", b"2", 0o644, {})])
        with patch.object(package, "MAX_MEMBERS", 1), self.assertRaisesRegex(ValueError, "too many"):
            package.index_tar(raw)
        with patch.object(package, "MAX_MEMBER_BYTES", 0), self.assertRaisesRegex(ValueError, "size"):
            package.index_tar(raw)

    def test_non_octal_numeric_headers_fail_before_tar_metadata_interpretation(self):
        original = archive([("usr/bin/rsync", EXECUTABLE, 0o755, {})])
        for label, offset, width in [("mode", 100, 8), ("uid", 108, 8),
                                     ("gid", 116, 8), ("mtime", 136, 12),
                                     ("devmajor", 329, 8), ("devminor", 337, 8)]:
            raw = bytearray(original)
            raw[offset:offset + width] = tarfile.itn(-1, width, tarfile.GNU_FORMAT)
            raw[148:156] = b" " * 8
            raw[148:156] = (f"{sum(raw[:512]):06o}\0 ").encode("ascii")
            with self.subTest(field=label), patch.object(
                    tarfile.TarInfo, "frombuf", side_effect=AssertionError("metadata parser ran")), \
                    self.assertRaises(ValueError):
                package.index_tar(bytes(raw))

    def test_archive_truncation_duplicate_and_extra_member_fail(self):
        complete = deb()
        mutations = [complete[:-1], complete + member("debian-binary", b"2.0\n"),
                     complete + member("unexpected", b"x")]
        for data in mutations:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                package.parse_ar(data)

    def test_gzip_truncated_concatenated_and_oversized_streams_fail(self):
        encoded = gzip.compress(b"bounded-content")
        self.assertEqual(package.unpack_tar("data.tar.gz", encoded), b"bounded-content")
        for data in [encoded[:-1], encoded + encoded, encoded + b"garbage"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                package.unpack_tar("data.tar.gz", data)
        with patch.object(package, "MAX_TAR", 5), self.assertRaises(ValueError):
            package.unpack_tar("data.tar.gz", encoded)

    def test_unsupported_compression_and_debian_version_fail(self):
        with self.assertRaises(package.UnsupportedPackage):
            package.unpack_tar("data.tar.zst", b"unparsed")
        with self.assertRaises(ValueError):
            package.parse_ar(deb().replace(b"2.0\n", b"1.0\n", 1))


if __name__ == "__main__":
    unittest.main()
