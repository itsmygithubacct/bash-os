# text/rev-tac: rev and tac basics and separators
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abc\nhello world\n\nx\n' > f
rev f; echo --; tac f; echo --; printf 'a,b,c,' | tac -s,; echo; echo --; printf 'a,b,c' | tac -b -s,; echo; echo --
printf '1x2xx3' | tac -r -s 'x\+'; echo
# --- tac -s with a multi-byte separator
mkdir part-tac-regex-sep && (cd part-tac-regex-sep || exit
printf 'one--two--three--' | tac -s -- '--'; echo
printf 'A\nB\nC' | tac; echo
)
