# files/truncate-forms: truncate sizes and relative adjustments
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abcdefghij' > f; truncate -s 4 f; cat f; echo; truncate -s +3 f; od -An -c f
truncate -s -2 f; wc -c < f; truncate -s '%4' f; wc -c < f; truncate -s '/3' f; wc -c < f
truncate -s 1K g; wc -c < g; truncate -c -s 5 nosuch; ls nosuch 2>/dev/null; echo "rc=$?"; truncate -r g h; wc -c < h
truncate -s '>2000' g; wc -c < g; truncate -s '<10' g; wc -c < g
