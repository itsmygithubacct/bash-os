# find/xargs-exit-x: xargs -x exits when a command line would exceed -s
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '1 2 3 4\n' | xargs -n 3 -x echo; echo "rc=$?"; printf 'aaaa bbbb\n' | xargs -x -s 8 echo; echo "rc=$?"
