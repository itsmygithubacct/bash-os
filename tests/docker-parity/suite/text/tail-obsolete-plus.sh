# text/tail-obsolete-plus: obsolete tail +N FILE and -N forms
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '1\n2\n3\n4\n5\n' > f; tail +4 f; echo "rc=$?"; tail -3 f
