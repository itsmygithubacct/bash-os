# text/uniq-fields: uniq -f -s -w and --group
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%s\n' '1 apple x' '2 apple y' '3 pear z' '4 pear z' > f
uniq -f1 f; echo --; uniq -f1 -c f; echo --; uniq -s2 -w3 f
echo --; uniq --group -f1 f; echo --; uniq --all-repeated=separate -f1 f
printf 'a\0a\0b\0' | uniq -z | od -An -c
# --- uniq -f beyond the field count and -c widths
mkdir part-uniq-skip-edge && (cd part-uniq-skip-edge || exit
printf 'a x\nb x\nc\nc\n' | uniq -f 5 -c
for i in $(seq 1 120); do echo same; done | uniq -c
)
