# text/sort-month-random: sort -M and a seeded -R grouping
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%s\n' Mar jan DEC feb xyz ' Apr' | sort -M
printf '%s\n' b a b a c > f; seq 1 5000 > rnd
sort -R --random-source=rnd f | uniq -c | sort
