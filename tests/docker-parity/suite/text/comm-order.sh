# text/comm-order: comm order checking
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%s\n' b a > u; printf '%s\n' a b > s
comm u s; echo "rc=$?"
comm --nocheck-order u s; echo "rc=$?"
comm --check-order u s; echo "rc=$?"
