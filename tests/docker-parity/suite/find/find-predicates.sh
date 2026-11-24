# find/find-predicates: -name -iname -type -path -prune
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p t/a/b t/c t/.hid; printf 'x' > t/one; printf '%0600d' 0 > t/a/six; printf '%02000d' 0 > t/a/b/two
: > t/c/empty; printf 'hi\n' > t/.hid/h.txt; ln -s one t/lnk; ln -s missing t/dang; chmod 755 t/a; chmod 700 t/c
touch -h -d @1600000000 t/one t/lnk t/dang; touch -d @1700000000 t/a/six t/c/empty; touch -d @1650000000 t/a/b/two t/.hid/h.txt
find t -name '*.txt' | sort; echo --; find t -iname 'ONE'; echo --; find t -type d | sort; echo --; find t -type l | sort
echo --; find t -path '*a/b*' | sort; echo --; find t -name a -prune -o -type f -print | sort; echo --; find t -type f,l | sort
