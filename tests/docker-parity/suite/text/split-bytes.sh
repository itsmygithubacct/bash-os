# text/split-bytes: split -b, -C, -n l/N, -n r/N
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 30 > f
split -b 20 f b-; ls b-*; cat b-ab; echo; rm b-*
split -C 20 f c-; for x in c-*; do printf '%s %s\n' "$x" "$(wc -c < "$x")"; done; rm c-*
split -n l/3 f l-; wc -l l-* ; rm l-*
split -n r/3 f r-; head -n 2 r-*; rm r-*
split -n 2/4 f; echo
