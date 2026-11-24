# awk/awk-convfmt-int: CONVFMT=%d applied to a non-integer value
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{CONVFMT="%d"; y=2.7; z=y ""; print z; a[y]=1; for (k in a) print k}'
