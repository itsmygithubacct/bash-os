# sed/sed-hold-tricks: classic one-liners: reverse, join, dedupe adjacent
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '1\n2\n3\n' | sed -n '1!G;h;$p'; printf 'a\na\nb\nb\nc\n' | sed '$!N; /^\(.*\)\n\1$/!P; D'
printf 'a\nb\nc\n' | sed ':a;N;$!ba;s/\n/,/g'; printf 'line\n' | sed 'G'; printf ' x \n' | sed 's/^[ \t]*//;s/[ \t]*$//' | od -An -c
