# find/find-depth: -maxdepth -mindepth -depth ordering
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p t/a/b t/c t/.hid; printf 'x' > t/one; printf '%0600d' 0 > t/a/six; printf '%02000d' 0 > t/a/b/two
: > t/c/empty; printf 'hi\n' > t/.hid/h.txt; ln -s one t/lnk; ln -s missing t/dang; chmod 755 t/a; chmod 700 t/c
touch -h -d @1600000000 t/one t/lnk t/dang; touch -d @1700000000 t/a/six t/c/empty; touch -d @1650000000 t/a/b/two t/.hid/h.txt
find t -maxdepth 1 | sort; echo --; find t -mindepth 2 -maxdepth 2 | sort; echo --; find t/a/b -depth; echo --; find t/a/b; echo --; find t/a -depth | sort
# --- -prune with -depth and -print ordering
mkdir part-find-depth-prune-order && (cd part-find-depth-prune-order || exit
mkdir -p p/q/r p/s; touch p/q/r/f p/s/g
find p -name q -prune -o -print | sort; echo --; find p -depth -name 'r' ; echo --; find p -mindepth 1 -maxdepth 1 -printf '%f\n' | sort
)
