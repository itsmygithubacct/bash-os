#!/bin/bash
# Run inside a disposable Linux VM. TAR must name the candidate or GNU tar.
# Run once with CAP_MKNOD and once without it in a writable private directory.
set -euo pipefail
: "${TAR:?set TAR to candidate wrapper or GNU tar}"
: "${EXPECT_MKNOD:?set EXPECT_MKNOD to yes or no}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir source out
# Independent archive with device entries and a following regular member.
python3 - <<'PY'
import io, tarfile
with tarfile.open('independent.tar', 'w', format=tarfile.USTAR_FORMAT) as t:
    for name, kind, major, minor in [('char', tarfile.CHRTYPE, 1, 3), ('block', tarfile.BLKTYPE, 7, 19)]:
        e = tarfile.TarInfo(name); e.type = kind; e.mode = 0o640
        e.devmajor = major; e.devminor = minor; t.addfile(e)
    e = tarfile.TarInfo('after'); e.size = 2; t.addfile(e, io.BytesIO(b'ok'))
PY
"$TAR" -tvf independent.tar > listing
python3 - <<'PY'
s = open('listing').read().splitlines()
for name, major, minor in [('char', 1, 3), ('block', 7, 19)]:
    lines = [line for line in s if line.split()[-1] == name]
    assert len(lines) == 1 and f'{major},{minor}' in lines[0].replace(' ', ''), lines
assert any(line.split()[-1] == 'after' for line in s)
PY
# Existing /dev/null is readable as metadata without CAP_MKNOD.
"$TAR" -cf created.tar -C /dev null
python3 - <<'PY'
import os, tarfile
with tarfile.open('created.tar') as t:
    e = t.getmember('null'); st = os.stat('/dev/null')
    assert e.ischr() and (e.devmajor, e.devminor) == (os.major(st.st_rdev), os.minor(st.st_rdev))
PY
if [[ $EXPECT_MKNOD == yes ]]; then
    # Fail the fixture if the profile lacks its prerequisite.
    mknod source/probe c 1 3
    rm source/probe
    "$TAR" -xf independent.tar -C out
    python3 - <<'PY'
import os, stat
for name, kind, major, minor in [('char', stat.S_ISCHR, 1, 3), ('block', stat.S_ISBLK, 7, 19)]:
    st = os.lstat('out/' + name)
    assert kind(st.st_mode) and (os.major(st.st_rdev), os.minor(st.st_rdev)) == (major, minor)
assert open('out/after', 'rb').read() == b'ok'
PY
    "$TAR" -cf roundtrip.tar -C out block char
    python3 - <<'PY'
import tarfile
with tarfile.open('roundtrip.tar') as t:
    b = t.getmember('block'); c = t.getmember('char')
    assert b.isblk() and (b.devmajor, b.devminor) == (7, 19)
    assert c.ischr() and (c.devmajor, c.devminor) == (1, 3)
PY
else
    if mknod source/probe c 1 3 2>/dev/null; then
        echo 'fixture error: CAP_MKNOD unexpectedly available' >&2; exit 1
    fi
    if "$TAR" -xf independent.tar -C out 2>error; then
        echo 'device extraction unexpectedly succeeded' >&2; exit 1
    fi
    test -s error
    test ! -e out/char && test ! -e out/block
    test "$(cat out/after)" = ok
fi
