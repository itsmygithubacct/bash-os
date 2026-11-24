# files/mkfifo-stat: mkfifo and stat file types
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkfifo -m 640 p; stat -c '%F %a' p; mkfifo p; echo "rc=$?"; rm p
