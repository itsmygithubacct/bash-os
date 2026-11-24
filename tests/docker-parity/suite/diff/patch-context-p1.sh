# diff/patch-context-p1: context diff with -p1, -d and new/deleted files
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p a b; printf 'x\ny\nz\n' > a/f; printf 'x\nY\nz\n' > b/f; printf 'new\n' > b/added; printf 'gone\n' > a/removed
touch -d @1700000000 a/* b/*
diff -ruN a b > u.patch; mkdir t; cp a/f a/removed t/; patch -d t -p1 < u.patch; echo "rc=$?"; ls t; cat t/f t/added
diff -c a/f b/f > c.patch; cp a/f g; patch g c.patch; echo "rc=$?"; cat g
