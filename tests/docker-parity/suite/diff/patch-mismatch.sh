# diff/patch-mismatch: a hunk that does not match is rejected (G45 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one\ntwo\nthree\n' > f; printf 'one\nTWO\nthree\n' > g; diff -u --label f --label g f g > p; printf 'one\nDIFFERENT\nthree\n' > f
patch -s --no-backup-if-mismatch f < p; echo "rc=$?"; cat f; ls f.rej >/dev/null 2>&1 && echo has-rej; rm -f f.rej f.orig
printf 'z\n' > one; printf 'q\n' > two; diff -U0 --label one --label two one two > p0; printf 'a\n' > one; patch -s --no-backup-if-mismatch one < p0; echo "rc=$?"; cat one; rm -f one.rej
