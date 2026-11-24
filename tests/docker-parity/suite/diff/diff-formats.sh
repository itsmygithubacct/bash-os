# diff/diff-formats: -y side by side, --brief, -e ed script, -n RCS, --normal
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\n' > old
printf 'one\nTWO\nthree\nfour\nfive\nsix\nseven\neight\n' > new
touch -d @1700000000 old; touch -d @1700000100 new
diff -y -W 40 old new; echo --; diff --brief old new; echo --; diff -e old new; echo --; diff -n old new; echo --; diff --suppress-common-lines -y -W 30 old new; echo "rc=$?"
