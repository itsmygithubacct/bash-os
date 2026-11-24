# files/du-sizes: du -b, -s, --apparent-size on fixed contents
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p d/e; printf '%01000d' 0 > d/f; printf '%03000d' 0 > d/e/g
du -b d | sort -k2; du -sb d; du -ab d | sort -k2; du --apparent-size -s --block-size=1 d; du -sb --max-depth=0 d
