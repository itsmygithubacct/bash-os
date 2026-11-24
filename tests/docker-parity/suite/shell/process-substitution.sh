# shell/process-substitution: <( ) and >( ) with diff and tee
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
diff <(printf 'a\nb\n') <(printf 'a\nc\n'); echo "rc=$?"; paste <(seq 3) <(seq 4 6); printf 'x\n' | tee >(tr x y > out) > /dev/null; wait; sleep 0.2; cat out
while read -r l; do echo "got $l"; done < <(printf '1\n2\n')
