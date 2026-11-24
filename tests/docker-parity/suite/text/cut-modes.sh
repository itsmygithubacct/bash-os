# text/cut-modes: cut -b -c -f -d -s --complement --output-delimiter
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one:two:three\nfour\nfive:six\n' > f
cut -d: -f2 f; echo --; cut -d: -f2 -s f; echo --; cut -d: -f1,3 f
echo --; cut -d: -f2- --output-delimiter=' | ' f; echo --; cut -c2-4 f
echo --; cut -b1,3-,2 f; echo --; cut -d: --complement -f2 f
printf 'a\tb\tc\n' | cut -f2
printf 'abcdef\n' | cut -c-2,5-
# --- cut with missing fields, ranges past the end, and -z
mkdir part-cut-fields-edge && (cd part-cut-fields-edge || exit
printf 'a,b\nc\n,d,\n' | cut -d, -f2
printf 'a,b\nc\n,d,\n' | cut -d, -f3-
printf 'abc\n' | cut -c5-
printf 'a,b\0c,d\0' | cut -z -d, -f2 | od -An -c
printf 'a b  c\n' | cut -d' ' -f3
)
