# find/find-print0-xargs: -print0 | xargs -0 and names with spaces
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir s; touch 's/a b' 's/c
d' s/e; find s -type f -print0 | sort -z | xargs -0 -n1 printf '<%s>\n'
find s -type f -print0 | xargs -0 ls -1 | sort | od -c | head -n 3
# --- find over many files piped through sort
mkdir part-find-sort-names && (cd part-find-sort-names || exit
mkdir m; for i in $(seq 1 60); do touch "m/f$i"; done; find m -type f | sort -V | head -n 3; find m -type f | wc -l
find m -type f -name 'f1*' | sort | tr '\n' ' '; echo
)
