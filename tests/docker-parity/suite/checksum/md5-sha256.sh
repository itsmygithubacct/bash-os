# checksum/md5-sha256: md5sum and sha256sum of files and stdin
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abc' > a; printf '' > e; printf 'line\n' > 'sp ace'
md5sum a e 'sp ace'; sha256sum a e; printf 'abc' | md5sum; printf 'abc' | sha256sum -; md5sum --tag a; sha256sum -z a | od -An -c | tail -n 2
# --- md5sum -b and -t markers and --tag with spaces
mkdir part-md5-binary-modes && (cd part-md5-binary-modes || exit
printf 'a' > f; md5sum -b f; md5sum -t f; md5sum --tag 'f'; printf 'a' > 'two words'; md5sum --tag 'two words'
printf 'a' > 'nl
name'; md5sum 'nl
name'; sha256sum 'nl
name' > S; sha256sum -c S
)
