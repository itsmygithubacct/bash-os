# archive/tar-newer: -N / --newer-mtime selection
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir d; printf 'o\n' > d/old; printf 'n\n' > d/new; touch -d @1500000000 d/old; touch -d @1700000000 d/new
tar -cf /tmp/n.tar --newer-mtime=@1600000000 d/old d/new; tar -tf /tmp/n.tar
