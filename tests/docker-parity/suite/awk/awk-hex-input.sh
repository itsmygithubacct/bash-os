# awk/awk-hex-input: hexadecimal-looking input fields are not numbers
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
echo '0x10 0x1A' | awk '{print ($1==16), $1+0, $2+1}'
