# diff/patch-normal-offset: normal diff format and offset application
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\n' > old
printf 'one\nTWO\nthree\nfour\nfive\nsix\nseven\neight\n' > new
touch -d @1700000000 old; touch -d @1700000100 new
diff old new > n.patch; { printf 'pre1\npre2\n'; cat old; } > shifted; patch shifted n.patch; echo "rc=$?"; cat shifted
