# sed/sed-null-ext: -z, -E, -s and special replacement cases
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\0b\0' | sed -z 's/^/x/' | od -An -c; printf 'abc\n' | sed 's/b/\
/'; printf 'path/to/f\n' | sed 's|/|:|g'; printf 'abc\n' | sed 's/b/[&&]/'; printf 'aaa\n' | sed 's/a/b/3'
printf 'hello\n' | sed 's/\(.\)/\U\1/'; printf 'Hello World\n' | sed -E 's/(\w+)/\L\1/g'; printf 'ab\n' | sed 's/a/\u&x/'
