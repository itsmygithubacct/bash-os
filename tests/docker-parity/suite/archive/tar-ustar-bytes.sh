# archive/tar-ustar-bytes: ustar archive bytes are identical with fixed metadata
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p src/sub; printf 'alpha\n' > src/a; printf 'beta\n' > src/sub/b; ln -s a src/link; chmod 640 src/a; chmod 750 src/sub
touch -h -d @1700000000 src/a src/sub/b src/link src/sub src
U=/tmp/u.tar; tar --format=ustar -cf $U --owner=0 --group=0 --numeric-owner --mtime=@1700000000 --sort=name src/a src/sub/b; wc -c < $U; head -c 2048 $U | md5sum; md5sum < $U; od -An -c -j 257 -N 8 $U
