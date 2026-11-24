# diff/patch-unified: apply a unified diff, then reverse it
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\n' > old
printf 'one\nTWO\nthree\nfour\nfive\nsix\nseven\neight\n' > new
touch -d @1700000000 old; touch -d @1700000100 new
cp old work; diff -u old new > fix.patch; patch work < fix.patch; echo "rc=$?"; cmp work new && echo applied
patch -R work < fix.patch; cmp work old && echo reversed; patch --dry-run work < fix.patch; cmp work old && echo untouched
