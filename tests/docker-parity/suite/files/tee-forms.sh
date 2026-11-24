# files/tee-forms: tee to files, -a append
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one\n' | tee a b; printf 'two\n' | tee -a a > /dev/null; cat a b; printf 'x\n' | tee; printf 'y\n' | tee - | cat
