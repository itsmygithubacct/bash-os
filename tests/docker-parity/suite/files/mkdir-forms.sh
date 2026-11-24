# files/mkdir-forms: mkdir -p -m -v and existing paths
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p a/b/c; mkdir -m 700 m; mkdir -pm 711 x/y; stat -c '%n %a' a a/b/c m x x/y
mkdir -v n | sed 's/^/v: /'; mkdir a; echo "rc=$?"; mkdir -p a; echo "rc=$?"; mkdir -m u=rwx,g=rx,o= sym; stat -c %a sym
