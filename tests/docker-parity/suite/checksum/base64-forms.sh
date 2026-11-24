# checksum/base64-forms: base64 encode/decode, -w, -d errors, -i
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'hello world, this is a longer line to force wrapping in base64 output!!' > f
base64 f; base64 -w 20 f; base64 -w 0 f; echo; base64 f | base64 -d | cmp - f && echo roundtrip
printf 'a\0b\377' | base64; printf 'YQBi/w==' | base64 -d | od -An -tx1; printf 'Y Q\nB i\n/w==' | base64 -d -i 2>&1 | od -An -tx1
printf '!!!' | base64 -d; echo "rc=$?"; printf 'YWJj' | base64 -d; echo
