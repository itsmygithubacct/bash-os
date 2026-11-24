# text/split-filter: split --filter and -e
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 7 > f
split -l 3 --filter='sed "s/^/[$FILE] /"' f
split -n 10 -e f e-; ls e-* | wc -l; rm -f e-*
split -l 2 --numeric-suffixes=5 f s; ls s*
