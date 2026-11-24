# text/sort-merge-check: -m on presorted inputs and -c/-C checks
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '1\n4\n7\n' > a; printf '2\n5\n8\n' > b; printf '3\n6\n9\n' > c
sort -m a b c
echo --; sort -n -m c b a
echo --; t sort -c a
printf '1\n3\n2\n' > u
sort -c u; echo "rc=$?"
sort -C u; echo "rc=$?"
printf '1\n1\n' | sort -cu; echo "rc=$?"
# --- sort -c reports the first disorder
mkdir part-sort-check-msg && (cd part-sort-check-msg || exit
printf 'a\nc\nb\nd\n' > f
sort -c f; echo "rc=$?"
sort -c -r f; echo "rc=$?"
)
