# numbers/arith-shell: shell arithmetic (same bash): bases, overflow, division
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
echo $((2**63-1)) $((2**63)) $((16#ff)) $((8#17)) $((2#1010)) $((-7/2)) $((-7%3)) $((7<<2)) $((~0)) $((1?2:3))
(( x = 5, x *= 3 )); echo $x; ( echo $(( 1/0 )) ); echo "rc=$?"
