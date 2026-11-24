# diff/diff-unified: -u with fixed timestamps and -U N, labels
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\n' > old
printf 'one\nTWO\nthree\nfour\nfive\nsix\nseven\neight\n' > new
touch -d @1700000000 old; touch -d @1700000100 new
diff -u old new; echo "rc=$?"; diff -U0 old new; diff -U 1 --label A --label B old new; echo "rc=$?"
