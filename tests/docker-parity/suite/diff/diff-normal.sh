# diff/diff-normal: default output and exit statuses
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\n' > old
printf 'one\nTWO\nthree\nfour\nfive\nsix\nseven\neight\n' > new
touch -d @1700000000 old; touch -d @1700000100 new
diff old new; echo "rc=$?"; diff old old; echo "rc=$?"; diff old nosuch; echo "rc=$?"
# --- diff file against directory and -u of identical files
mkdir part-diff-labels-dirs && (cd part-diff-labels-dirs || exit
mkdir d; printf 'a\n' > d/f; printf 'b\n' > f; diff f d; echo "rc=$?"; diff -u d/f d/f; echo "rc=$?"
)
