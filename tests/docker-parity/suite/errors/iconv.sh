# errors/iconv: iconv: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ iconv %s\n' "$*"; iconv "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -f
e -f NOSUCH -t UTF-8
e -f UTF-8 -t NOSUCH
e nosuch
