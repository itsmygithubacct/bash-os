# awk/awk-system: system() runs a command and returns its status (G24 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{r=system("exit 3"); print "r=" r; r=system("echo hi"); print "r=" r}'
