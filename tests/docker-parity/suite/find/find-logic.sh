# find/find-logic: -a -o ! and grouping, -true -false, -empty, -perm
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p t/a/b t/c t/.hid; printf 'x' > t/one; printf '%0600d' 0 > t/a/six; printf '%02000d' 0 > t/a/b/two
: > t/c/empty; printf 'hi\n' > t/.hid/h.txt; ln -s one t/lnk; ln -s missing t/dang; chmod 755 t/a; chmod 700 t/c
touch -h -d @1600000000 t/one t/lnk t/dang; touch -d @1700000000 t/a/six t/c/empty; touch -d @1650000000 t/a/b/two t/.hid/h.txt
find t \( -name one -o -name six \) -print | sort; echo --; find t ! -type d ! -type l | sort; echo --; find t -empty | sort
echo --; find t -perm 700 | sort; echo --; find t -perm -u+x -type d | sort; echo --; find t -false; find t -maxdepth 0 -true
echo --; find t -type f -perm /o+r | sort; echo --; find t -links 1 -type f -name six
# --- -perm with symbolic forms and -readable -writable -executable
mkdir part-find-perm-symbolic && (cd part-find-perm-symbolic || exit
touch a b c; chmod 644 a; chmod 755 b; chmod 600 c
find . -type f -perm -g=r | sort; echo --; find . -type f -perm /u=x,g=x | sort; echo --; find . -type f -executable | sort; echo --; find . -type f -perm 0600
)
