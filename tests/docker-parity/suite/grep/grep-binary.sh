# grep/grep-binary: binary file detection and -a
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'text\0more\nline2\n' > b
grep line b; echo "rc=$?"; grep -a line b; grep -c more b; grep --binary-files=without-match line b; echo "rc=$?"
