"""Bounded in-memory inspection of a Debian package, with no extraction to disk.

The caller must first authenticate the complete deb against signed metadata.
Unsupported compression, PAX/GNU extensions, sparse files, ambiguous paths,
invalid control syntax and oversize archives fail closed. Symlink and hardlink
leaves are recorded but never resolved; no explicit ancestor may be a link or
other non-directory, and selected package members must be regular files.
"""
import bz2
import hashlib
import lzma
import posixpath
import re
import tarfile
import zlib


class UnsupportedPackage(ValueError):
    pass


MAX_AR = 4 * 1024 * 1024
MAX_TAR = 64 * 1024 * 1024
MAX_MEMBERS = 10000
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_CONTROL_FILE = 1024 * 1024
MAX_BINARY = 16 * 1024 * 1024
CONTROL_FIELDS = frozenset(("Package", "Version", "Architecture", "Depends", "Pre-Depends"))
BASE_CONTROL_FIELDS = frozenset(("Package", "Version", "Architecture"))
TAR_SUFFIXES = ("", ".gz", ".xz", ".bz2", ".zst", ".lzma")
SUPPORTED_SUFFIXES = ("", ".gz", ".xz", ".bz2")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_ar(data):
    if not isinstance(data, bytes) or len(data) > MAX_AR or not data.startswith(b"!<arch>\n"):
        raise ValueError("invalid or oversized Debian ar archive")
    offset, files, names, convention = 8, {}, [], None
    while offset < len(data):
        h = data[offset:offset + 60]
        if len(h) != 60 or h[58:] != b"`\n":
            raise ValueError("truncated or invalid ar header")
        field = h[:16].decode("ascii", "strict")
        token = field.rstrip(" ")
        slash = token.endswith("/")
        name = token[:-1] if slash else token
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name) or name in files:
            raise ValueError("duplicate or unsafe ar member")
        if field != (name + ("/" if slash else "")).ljust(16):
            raise ValueError("noncanonical ar member name")
        if convention is None:
            convention = slash
        elif convention != slash:
            raise ValueError("mixed ar member naming conventions")
        size_text = h[48:58].decode("ascii", "strict")
        if not re.fullmatch(r"(?:0|[1-9][0-9]*) *", size_text):
            raise ValueError("invalid ar member size")
        size = int(size_text.rstrip(" "))
        start = offset + 60
        end = start + size
        if end > len(data):
            raise ValueError("truncated ar member")
        files[name] = data[start:end]
        names.append(name)
        if size % 2:
            if data[end:end + 1] != b"\n":
                raise ValueError("invalid ar alignment")
            end += 1
        offset = end
    if offset != len(data) or files.get("debian-binary") != b"2.0\n":
        raise ValueError("invalid Debian package version")
    controls = {"control.tar" + suffix for suffix in TAR_SUFFIXES}
    payloads = {"data.tar" + suffix for suffix in TAR_SUFFIXES}
    if len(names) != 3 or names[0] != "debian-binary" or names[1] not in controls or names[2] not in payloads:
        raise ValueError("unexpected or ambiguous Debian archive members")
    for name, prefix in ((names[1], "control.tar"), (names[2], "data.tar")):
        if name[len(prefix):] not in SUPPORTED_SUFFIXES:
            raise UnsupportedPackage("unsupported package tar compression: " + name)
    return files, names[1], names[2]


def unpack_tar(name, data):
    if not isinstance(data, bytes) or len(data) > MAX_AR:
        raise ValueError("invalid or oversized compressed tar member")
    if name not in {"control.tar" + suffix for suffix in TAR_SUFFIXES} | {
            "data.tar" + suffix for suffix in TAR_SUFFIXES}:
        raise UnsupportedPackage("unsupported package tar member: " + str(name))
    try:
        return _unpack_tar(name, data)
    except (lzma.LZMAError, zlib.error, EOFError, OSError) as error:
        raise ValueError("invalid compressed tar stream") from error


def _unpack_tar(name, data):
    if name.endswith(".tar"):
        raw = data
    elif name.endswith(".tar.xz"):
        d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_TAR)
        raw = d.decompress(data, max_length=MAX_TAR + 1)
        if not d.eof or d.unused_data:
            raise ValueError("truncated, concatenated or oversized xz stream")
    elif name.endswith(".tar.gz"):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = d.decompress(data, MAX_TAR + 1)
        if not d.eof or d.unused_data or d.unconsumed_tail:
            raise ValueError("truncated, concatenated or oversized gzip stream")
    elif name.endswith(".tar.bz2"):
        d = bz2.BZ2Decompressor()
        raw = d.decompress(data, max_length=MAX_TAR + 1)
        if not d.eof or d.unused_data:
            raise ValueError("truncated, concatenated or oversized bzip2 stream")
    else:
        raise UnsupportedPackage("unsupported package tar compression: " + name)
    if len(raw) > MAX_TAR:
        raise ValueError("package tar exceeds size limit")
    return raw


def _tar_octal(field, label, *, empty_zero=False):
    value = field.strip(b" \0")
    if not value and empty_zero:
        return 0
    if not value or not re.fullmatch(rb"[0-7]+", value):
        raise ValueError("invalid or unsupported tar " + label)
    return int(value, 8)


def _physical_tar(raw):
    """Scan physical blocks before invoking any tarfile header processing.

    PAX, GNU long-name/long-link and sparse headers, other extensions and
    special files are unsupported. This intentionally conservative subset has
    no recursive metadata interpretation or sparse expansion.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_TAR or len(raw) % 512:
        raise ValueError("invalid bounded tar framing")
    entries, offset, expanded = [], 0, 0
    zero = b"\0" * 512
    while offset + 512 <= len(raw):
        header = raw[offset:offset + 512]
        if header == zero:
            if offset + 1024 > len(raw) or raw[offset + 512:offset + 1024] != zero:
                raise ValueError("tar requires two terminal zero blocks")
            if sum(memoryview(raw)[offset + 1024:]) != 0:
                raise ValueError("nonzero data follows tar terminator")
            return entries
        kind = header[156:157]
        if kind not in (b"0", b"\0", b"5", b"1", b"2"):
            raise UnsupportedPackage("unsupported tar extension or member type")
        if len(entries) >= MAX_MEMBERS:
            raise ValueError("too many physical tar members")
        for field in (header[:100], header[157:257], header[345:500]):
            before, marker, after = field.partition(b"\0")
            if marker and any(after):
                raise ValueError("nonzero bytes after tar string terminator")
        checksum = _tar_octal(header[148:156], "checksum")
        if checksum != sum(header[:148]) + 8 * 32 + sum(header[156:]):
            raise ValueError("tar header checksum mismatch")
        mode = _tar_octal(header[100:108], "mode")
        if mode > 0o7777:
            raise ValueError("tar permission mode out of bounds")
        for label, start, end in (("uid", 108, 116), ("gid", 116, 124),
                                  ("mtime", 136, 148)):
            _tar_octal(header[start:end], label)
        for label, start, end in (("devmajor", 329, 337), ("devminor", 337, 345)):
            _tar_octal(header[start:end], label, empty_zero=True)
        size = _tar_octal(header[124:136], "size")
        if size > MAX_MEMBER_BYTES:
            raise ValueError("tar member size out of bounds")
        if kind not in (b"0", b"\0") and size:
            raise ValueError("non-regular tar member carries data")
        if kind in (b"0", b"\0"):
            expanded += size
            if expanded > MAX_EXPANDED_BYTES:
                raise ValueError("aggregate expanded tar data exceeds size limit")
        start = offset + 512
        end = start + ((size + 511) // 512) * 512
        if end > len(raw):
            raise ValueError("truncated tar member")
        entries.append((header, start, size, kind))
        offset = end
    raise ValueError("tar requires two terminal zero blocks")


def index_tar(raw):
    """Validate physical framing and the whole path graph before reading data.

    Link entries may occur only as leaves; they are never resolved or read.
    Selected files and every explicit ancestor must be regular files or
    directories as appropriate, regardless of archive order.
    """
    entries = _physical_tar(raw)
    indexed, contents = {}, {}
    for header, start, size, kind in entries:
        try:
            member = tarfile.TarInfo.frombuf(header, encoding="utf-8", errors="strict")
        except (tarfile.TarError, UnicodeError, ValueError, OverflowError) as error:
            raise ValueError("invalid tar header") from error
        if member.type != kind or member.size != size or member.sparse is not None or member.pax_headers:
            raise ValueError("tar header interpretation mismatch or sparse metadata")
        name = member.name
        if not name or name.startswith("/") or "\x00" in name or "\\" in name:
            raise ValueError("unsafe tar path")
        if any(part == ".." for part in name.split("/")):
            raise ValueError("tar parent traversal")
        name = posixpath.normpath(name)
        if name in indexed:
            raise ValueError("duplicate or aliased tar path: " + name)
        if name == "." and not member.isdir():
            raise ValueError("tar root is not a directory")
        indexed[name] = (member, None)
        if member.isfile():
            contents[name] = (start, size)
    for name in indexed:
        if name == ".":
            continue
        parent = posixpath.dirname(name)
        while parent:
            if parent in indexed and not indexed[parent][0].isdir():
                raise ValueError("non-directory tar ancestor: " + parent)
            parent = posixpath.dirname(parent)
        if "." in indexed and not indexed["."][0].isdir():
            raise ValueError("tar root is not a directory")
    for name, (start, size) in contents.items():
        indexed[name] = (indexed[name][0], raw[start:start + size])
    return indexed


def parse_control(raw, expected_fields):
    """Parse exactly one complete Debian control paragraph, without recovery."""
    if (not isinstance(raw, bytes) or len(raw) > MAX_CONTROL_FILE or not raw.endswith(b"\n")
            or b"\r" in raw or b"\0" in raw):
        raise ValueError("invalid control file framing")
    if (not isinstance(expected_fields, dict) or not BASE_CONTROL_FIELDS.issubset(expected_fields)
            or not set(expected_fields).issubset(CONTROL_FIELDS)):
        raise ValueError("authenticated package identity fields are required")
    if any(not isinstance(value, str) or not value for value in expected_fields.values()):
        raise ValueError("invalid authenticated control field value")
    text = raw.decode("utf-8", "strict")
    fields, current, ended = {}, None, False
    for line in text.split("\n")[:-1]:
        if not line:
            ended = True
            continue
        if ended:
            raise ValueError("additional control paragraph or body")
        if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in line):
            raise ValueError("invalid control character")
        if line[0] in " \t":
            if current is None:
                raise ValueError("orphaned control continuation")
            fields[current] += " " + line.lstrip(" \t")
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*(.*)", line)
        if match is None:
            raise ValueError("malformed control field")
        current = match.group(1).lower()
        if current in fields:
            raise ValueError("duplicate control field")
        fields[current] = match.group(2)
    for key, value in expected_fields.items():
        if fields.get(key.lower()) != value:
            raise ValueError("package control field differs from signed index: " + key)
    return fields


def inspect_deb(deb, expected_fields):
    """Return actual executable and maintainer-script bytes from this deb."""
    files, control_name, data_name = parse_ar(deb)
    controls = index_tar(unpack_tar(control_name, files[control_name]))
    payload = index_tar(unpack_tar(data_name, files[data_name]))
    control = controls.get("control")
    if control is None or not control[0].isfile() or len(control[1]) > MAX_CONTROL_FILE:
        raise ValueError("missing or invalid control file")
    parse_control(control[1], expected_fields)
    entry = payload.get("usr/bin/rsync")
    if entry is None or not entry[0].isfile() or not (entry[0].mode & 0o111):
        raise ValueError("package lacks a regular executable usr/bin/rsync")
    binary = entry[1]
    if not binary or len(binary) > MAX_BINARY:
        raise ValueError("extracted binary size out of bounds")
    scripts = {}
    for name in ("preinst", "postinst", "prerm", "postrm", "config", "triggers"):
        item = controls.get(name)
        if item is not None:
            if not item[0].isfile() or len(item[1]) > MAX_CONTROL_FILE:
                raise ValueError("invalid maintainer script or trigger: " + name)
            scripts[name] = item[1]
    return {"binary": binary, "binary_sha256": sha(binary), "binary_size": len(binary),
            "control_sha256": sha(control[1]), "scripts": scripts,
            "script_sha256": {name: sha(content) for name, content in scripts.items()},
            "deb_sha256": sha(deb), "control_member": control_name, "data_member": data_name}
