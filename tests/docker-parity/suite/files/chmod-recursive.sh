# files/chmod-recursive: chmod -R, -c, -v reporting
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p t/u; touch t/a t/u/b; chmod -R 755 t; chmod -c -R go-x t | sort; chmod -v 700 t/a
stat -c '%n %a' t t/a t/u t/u/b
