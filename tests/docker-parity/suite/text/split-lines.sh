# text/split-lines: split -l, -d, -a, --additional-suffix
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
seq 1 10 > f
split -l 4 f; for x in x*; do printf '%s: ' "$x"; tr '\n' ' ' < "$x"; echo; done; rm -f x*
split -l 3 -d -a 3 --additional-suffix=.txt f part-; ls part-*; cat part-003.txt; rm -f part-*
split -n 3 f n-; wc -c n-* | sort; rm -f n-*
