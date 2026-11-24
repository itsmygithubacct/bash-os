# sed/sed-addresses: line, regex, range, step, $ and ! addresses
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 12 > f
sed -n '3p' f; sed -n '$p' f; sed -n '2,4p' f | tr '\n' ' '; echo; sed -n '/5/,/8/p' f | tr '\n' ' '; echo
sed -n '0~4p' f | tr '\n' ' '; echo; sed -n '2~3p' f | tr '\n' ' '; echo; sed '3,$d' f; sed -n '10,+1p' f; sed -n '/1/!p' f | tr '\n' ' '; echo
sed -n '8,~4p' f | tr '\n' ' '; echo; sed -n '0,/1/p' f; sed -n '/^1/{/2$/p}' f
