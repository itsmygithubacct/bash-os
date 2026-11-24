# numbers/factor-forms: factor small, large and stdin tokens
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
command -v factor >/dev/null || factor() { coreutils factor "$@"; }
factor 1 2 12 97 360 1001 65536 4294967297 600851475143; echo '84 85' | factor; factor 18446744073709551615
factor --exponents 360 2>/dev/null || factor -h 360
