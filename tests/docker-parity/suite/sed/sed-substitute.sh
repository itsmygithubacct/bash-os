# sed/sed-substitute: s with flags g, N, p, I, w and & / \n references
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'hello world\nfoo bar foo\nABC abc\n' > f
sed 's/o/0/' f; sed 's/o/0/g' f; sed 's/o/0/2' f; sed -n 's/foo/X/p' f; sed 's/abc/x/I' f
sed 's/\(hel\)\(lo\)/\2\1/' f; sed -E 's/(foo) (bar)/\2 \1/' f; sed 's/[a-z]*/<&>/' f; sed 's/o/0/2g' f
sed -n 's/foo/F/w out' f; cat out
