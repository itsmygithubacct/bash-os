# files/cat-options: cat -n -b -s -A -E -T -v
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\tb\n\n\n\nc\001\n' > f
cat -n f; echo --; cat -b f; echo --; cat -s f; echo --; cat -A f; echo --; cat -E f; echo --; cat -T f; echo --; cat -v f
echo --; printf '\200\377\n' | cat -v; echo --; cat f - f < /dev/null | wc -l
