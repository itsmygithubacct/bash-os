# text/tr-classes: tr with [=c=], [:space:], octal escapes and repeats
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a b\tc\n' | tr '[:space:]' '_'
printf 'xyz\n' | tr 'x-z' '[a*2]Q'
printf 'banana\n' | tr '[=a=]' A
printf 'A\001B\n' | tr '\001' '\101' | od -An -c
printf 'abc\n' | tr -d 'a-b' ; printf 'zzz\n' | tr -s z
