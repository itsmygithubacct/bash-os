# checksum/iconv-latin1: iconv Latin-1 conversions and unconvertible input
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'caf\351 \374ber\n' > l1; iconv -f ISO-8859-1 -t UTF-8 l1 | od -An -c; iconv -f LATIN1 -t UTF-8 l1 | iconv -f UTF-8 -t ISO-8859-1 | cmp - l1 && echo rt
printf '\342\202\254\n' | iconv -f UTF-8 -t ISO-8859-1; echo "rc=$?"; printf 'a\342\202\254b\n' | iconv -c -f UTF-8 -t ISO-8859-1; echo "rc=$?"
printf 'a\377b\n' | iconv -f UTF-8 -t UTF-16LE; echo "rc=$?"; printf 'x\200' | iconv -f ASCII -t UTF-8; echo "rc=$?"
