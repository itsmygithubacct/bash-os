# sed/sed-a-text-semicolon: a/i/c text runs to the end of the line (G101 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'x\ny\n' > f
sed '1a x; p' f; sed '1i x; y' f; sed '2c gone; really' f; sed -e '1a\' -e 'cont' f; sed '$a\' f | od -An -c | tail -n 1
