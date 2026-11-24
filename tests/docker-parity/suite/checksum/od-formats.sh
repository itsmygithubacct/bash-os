# checksum/od-formats: od -A -t -c -x -w -j -N -v
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'Hello, od!\0\001\377\n' > f
od f; od -c f; od -An -tx1 f; od -Ax -tx2 f; od -Ad -to1 -w4 f; od -tx1z f; od -j 3 -N 4 -c f; od -td4 f; od -tu1 -An -w16 f
printf '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0x' > z; od -c z; od -v -c z | wc -l; od -tf4 -An -N4 f
# --- od signed/unsigned/float types and -t combos
mkdir part-od-endian-types && (cd part-od-endian-types || exit
printf '\001\002\003\004\377\376\375\374' > f; od -An -tu2 f; od -An -td2 f; od -An -tx4 f; od -An -to2 f; od -An -td1 -tc f; od -An -tx8 f; od -i -An f; od -l -An f
)
