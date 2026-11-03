#!/bin/bash
# SPDX-License-Identifier: MIT
# Run as a nonroot user in the candidate image inside the parity VM.
set -euo pipefail
[[ $(id -u) != 0 ]]
[[ $(type -t ls) == builtin ]]
[[ -w /work ]]
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
printf 'test\n' > data
[[ $(printf abc | base64 -w0) == YWJj ]]
[[ $(printf abc | sha256sum | cut -d ' ' -f 1) == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ]]
gzip -c data > data.gz
gzip -dc data.gz | cmp -s - data
zstd -qc data > data.zst
zstd -qdc data.zst | cmp -s - data
tar -cf data.tar data
mkdir unpack
tar -xf data.tar -C unpack
cmp data unpack/data
[[ $(printf '{"z":[2,3],"a":1}' | jq -c .z) == '[2,3]' ]]
[[ $(printf '2^10\n' | bc) == 1024 ]]
[[ $(awk 'BEGIN { print 6*7 }') == 42 ]]
[[ $(git hash-object data) == 9daeafb9864cf43055ae93beb0afd6c7d144bfa4 ]]
bashperl -MIO::Compress::Gzip=gzip -MIO::Compress::Bzip2=bzip2 -e '
    my $data="test\n";
    gzip \$data => "perl.gz" or die $IO::Compress::Gzip::GzipError;
    bzip2 \$data => "perl.bz2" or die $IO::Compress::Bzip2::Bzip2Error;
'
bashpython - <<'PY'
import bz2,ctypes,gzip,lzma,sqlite3,ssl,zoneinfo,zlib
from pathlib import Path
value=b'test\n'
assert gzip.decompress(Path('perl.gz').read_bytes())==value
assert bz2.decompress(Path('perl.bz2').read_bytes())==value
assert gzip.decompress(Path('data.gz').read_bytes())==value
for codec in (bz2,gzip,lzma,zlib):
    assert codec.decompress(codec.compress(value))==value
Path('python.gz').write_bytes(gzip.compress(value))
assert sqlite3.connect(':memory:').execute('select 42').fetchone()==(42,)
assert ssl.create_default_context().cert_store_stats()['x509_ca']>0
assert zoneinfo.ZoneInfo('America/New_York').key=='America/New_York'
for library in ('libEGL.so.1','libGLESv2.so.2','libgbm.so.1'):
    ctypes.CDLL(library)
PY
bashperl -MIO::Uncompress::Gunzip=gunzip -e '
    my $data;
    gunzip "python.gz" => \$data or die $IO::Uncompress::Gunzip::GunzipError;
    die "cross-runtime gzip mismatch" unless $data eq "test\n";
'
gzip -dc python.gz | cmp -s - data
printf '{"nonroot_userland_smoke":"PASS","uid":%s}\n' "$(id -u)"
