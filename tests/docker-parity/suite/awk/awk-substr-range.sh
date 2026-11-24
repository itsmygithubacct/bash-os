# awk/awk-substr-range: substr with a start below 1 (gawk and BWK awk clamp to 1)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{s="Hello"; print substr(s,0,3), substr(s,-1,3), substr(s,0), substr(s,1.5,2)}'
