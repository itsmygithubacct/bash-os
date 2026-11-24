# checksum/check-mixed: -c with tagged, untagged and escaped lines; --quiet --status --strict
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abc' > a; printf 'xyz' > b; printf 'q\n' > 'back\slash'
{ sha256sum a; sha256sum --tag b; sha256sum 'back\slash'; } > SUMS; cat SUMS
sha256sum -c SUMS; echo "rc=$?"; printf 'changed' > b; sha256sum -c SUMS; echo "rc=$?"; sha256sum -c --quiet SUMS; echo "rc=$?"
sha256sum -c --status SUMS; echo "rc=$?"; echo 'garbage line' >> SUMS; sha256sum -c SUMS; echo "rc=$?"; sha256sum -c --strict SUMS; echo "rc=$?"
