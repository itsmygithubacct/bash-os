# shell/traps: EXIT, ERR, RETURN traps and trap -p
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
f() { trap 'echo return-trap' RETURN; echo in-f; }; f; trap - RETURN
( trap 'echo exit-trap' EXIT; echo body ); ( set -E; trap 'echo "err at $LINENO"' ERR; false; echo after ) ; trap 'echo int' INT; trap -p INT; trap - INT; trap -p INT
( trap 'echo got-term; exit 3' TERM; kill -TERM $BASHPID; echo not-reached ); echo "rc=$?"
