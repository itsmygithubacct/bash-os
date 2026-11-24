# errors/truncate: truncate: unrecognized/invalid options, missing arguments and operands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch a b x
e() { printf '$ truncate %s\n' "$*"; truncate "$@" </dev/null; printf 'rc=%s\n' "$?"; }
e --bogus
e -@
e
e x
e -s
e -s bad x
