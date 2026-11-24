# text/csplit-basic: csplit by line numbers and regex
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 15 > f
csplit f 5 /10/; for x in xx*; do printf '%s: ' "$x"; tr '\n' ' ' < "$x"; echo; done; rm -f xx*
csplit -s -f part -n 3 f '/[05]$/' '{*}'; ls part*; cat part002; rm -f part*
