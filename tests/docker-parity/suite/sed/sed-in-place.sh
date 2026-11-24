# sed/sed-in-place: sed -i with and without suffix, -s and -n
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\nb\n' > f; printf 'c\nd\n' > g
sed -i 's/a/A/' f; cat f; sed -i.bak 's/c/C/' g; cat g g.bak; sed -s -n '$p' f g; sed -n '$p' f g
mkdir sub; printf 'z\n' > sub/h; chmod 711 sub; sed -i 's/z/Z/' sub/h; cat sub/h
