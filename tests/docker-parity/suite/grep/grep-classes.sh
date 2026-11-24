# grep/grep-classes: bracket expressions, POSIX classes, anchors, backrefs
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abc\nABC\n123\na1\n  \n_x\nabab\nx.y\n' > f
grep '[[:upper:]]' f; echo --; grep -c '[[:digit:]]' f; echo --; grep '^[[:space:]]*$' f; echo --; grep '\(ab\)\1' f
echo --; grep -E '^[a-z]+[0-9]$' f; echo --; grep '[^[:alnum:][:space:]]' f; echo --; grep 'x\.y' f; echo --; grep -E '\<a' f; echo --; grep -w '_x' f
