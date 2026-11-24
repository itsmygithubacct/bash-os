# checksum/iconv-utf: iconv between UTF-8, UTF-16 and UTF-32 variants
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'A\303\251\342\202\254\360\237\230\200\n' > u8
for t in UTF-16LE UTF-16BE UTF-32LE UTF-32BE; do printf '%s: ' "$t"; iconv -f UTF-8 -t "$t" u8 | od -An -tx1 | tr -s ' \n' ' '; echo; done
iconv -f UTF-8 -t UTF-16LE u8 | iconv -f UTF-16LE -t UTF-8 | cmp - u8 && echo rt16; iconv -f UTF-8 -t UTF-32BE u8 | iconv -f UTF-32BE -t UTF-8 | cmp - u8 && echo rt32
iconv -f UTF-8 -t UTF-16 u8 | od -An -tx1 -N 4; printf '\377\376A\0' | iconv -f UTF-16 -t UTF-8 | od -An -c
# --- iconv accepts common encoding aliases
mkdir part-iconv-list-names && (cd part-iconv-list-names || exit
for e in UTF-8 utf8 UTF8 ISO-8859-1 ISO_8859-1 LATIN1 L1 US-ASCII ASCII UTF-16 UCS-2 UCS-4 UTF-32; do printf 'A' | iconv -f "$e" -t UTF-8 >/dev/null 2>&1; printf '%s=%s\n' "$e" "$?"; done
)
