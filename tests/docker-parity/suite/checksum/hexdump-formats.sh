# checksum/hexdump-formats: hexdump -C, -b, -c, -x, -e, -v and -n -s (G123 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'Hello, hexdump!\0\001\377\n' > f
hexdump -C f; hexdump -c f; hexdump -b f; hexdump -x f; hexdump -n 4 -s 2 -C f; hexdump -e '16/1 "%02x" "\n"' f
hexdump -v -e '1/1 "%02x"' f; echo; hexdump -ve '1/1 "%02x "' -n 3 f; echo; hexdump -Cv f | head -n 1
printf '%032d' 0 > z; hexdump -C z
