#!/bin/bash
# Only in a disposable VM, without CAP_MKNOD. TAR is the candidate wrapper.
set -euo pipefail
export LC_ALL=C
: "${TAR:?set TAR to candidate wrapper}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir out outside
printf 'keep-existing\n' > out/char
printf 'keep-outside\n' > outside/sentinel
ln -s ../outside out/link
if mknod probe c 1 3 2>/dev/null; then
    echo 'fixture error: CAP_MKNOD unexpectedly available' >&2; exit 1
fi
python3 - <<'PY'
import io, tarfile
with tarfile.open('test.tar', 'w', format=tarfile.USTAR_FORMAT) as t:
    for name in ('char', 'link/evil'):
        e = tarfile.TarInfo(name); e.type = tarfile.CHRTYPE
        e.mode = 0o600; e.devmajor = 1; e.devminor = 3; t.addfile(e)
    e = tarfile.TarInfo('after'); e.size = 2; t.addfile(e, io.BytesIO(b'ok'))
PY
if "$TAR" -xf test.tar -C out 2>error; then
    echo 'device extraction unexpectedly succeeded' >&2; exit 1
fi
test -s error
test "$(cat out/char)" = keep-existing
test "$(cat outside/sentinel)" = keep-outside
test ! -e outside/evil
test "$(cat out/after)" = ok
if compgen -G 'out/.pax-node-*' >/dev/null; then echo 'temporary node left behind' >&2; exit 1; fi

# Independently corrupt the major field while retaining a valid tar checksum.
python3 - <<'PY2'
data = bytearray(open('test.tar', 'rb').read())
data[329:337] = b'0000080\0'
data[148:156] = b'        '
checksum = sum(data[:512])
data[148:156] = ('%06o\0 ' % checksum).encode('ascii')
open('malformed.tar', 'wb').write(data)
PY2
if "$TAR" -xf malformed.tar -C out 2>malformed-error; then
    echo 'malformed device number unexpectedly accepted' >&2; exit 1
fi
LC_ALL=C grep -q 'Invalid argument' malformed-error
test "$(cat out/char)" = keep-existing
