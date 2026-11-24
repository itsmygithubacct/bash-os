# errors/date: date: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ date %s\n' "$*"; date "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e -d
e -d nonsense
e -r nosuch
e +%Y +%m
e -I bad
