# text/comm-basic: comm columns and suppression
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%s\n' apple banana cherry > a; printf '%s\n' banana cherry date > b
comm a b; echo --; comm -12 a b; echo --; comm -3 a b; echo --; comm -23 a b
echo --; comm --output-delimiter=, a b; echo --; comm --total a b
# --- comm -z and a file vs stdin
mkdir part-comm-zero && (cd part-comm-zero || exit
printf 'a\0b\0' > a; printf 'b\0c\0' | comm -z a - | od -An -c
)
