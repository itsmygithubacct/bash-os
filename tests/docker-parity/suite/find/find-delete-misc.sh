# find/find-delete-misc: -delete, -quit, -L, -xtype
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p t/a/b t/c t/.hid; printf 'x' > t/one; printf '%0600d' 0 > t/a/six; printf '%02000d' 0 > t/a/b/two
: > t/c/empty; printf 'hi\n' > t/.hid/h.txt; ln -s one t/lnk; ln -s missing t/dang; chmod 755 t/a; chmod 700 t/c
touch -h -d @1600000000 t/one t/lnk t/dang; touch -d @1700000000 t/a/six t/c/empty; touch -d @1650000000 t/a/b/two t/.hid/h.txt
find t -name empty -delete; ls t/c; find t -type f -print -quit | wc -l; find -L t -type l | sort; echo --; find t -xtype l | sort; echo --; find -L t -name lnk -type f
