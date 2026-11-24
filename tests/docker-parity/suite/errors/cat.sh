# errors/cat: cat: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ cat %s\n' "$*"; cat "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e nosuch
