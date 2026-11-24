# text/column-table: column -t, -s, -o, -c filling
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'name age city\nalice 30 paris\nbob 5 rome\n' > f
column -t f; echo --; printf 'a:b:c\nddd:e:f\n' | column -t -s: ; echo --; printf 'a:b\ncc:d\n' | column -t -s: -o ' | '
echo --; seq 1 20 | column -c 40; echo --; seq 1 20 | column -c 40 -x
# --- column without -t on short input and with -L
mkdir part-column-fill && (cd part-column-fill || exit
printf 'a\nbb\nccc\n' | column -c 20
printf 'a b\n\nc d\n' | column -t
printf 'a b\n\nc d\n' | column -t -L
)
