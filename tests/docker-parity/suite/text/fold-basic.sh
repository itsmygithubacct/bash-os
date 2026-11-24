# text/fold-basic: fold -w -s -b
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
text='the quick brown fox jumps over the lazy dog'
echo "$text" | fold -w 10; echo --; echo "$text" | fold -s -w 10; echo --; echo "$text" | fold -w 15 -b
echo --; printf 'abc\tdefgh\n' | fold -w 6; echo --; printf 'abcdefghij' | fold -w 4; echo; echo --
printf 'a\bbcdef\n' | fold -w 3 | od -An -c
