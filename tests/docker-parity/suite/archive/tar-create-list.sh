# archive/tar-create-list: create with fixed metadata, list -t and -tv
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p src/sub; printf 'alpha\n' > src/a; printf 'beta\n' > src/sub/b; ln -s a src/link; chmod 640 src/a; chmod 750 src/sub
touch -h -d @1700000000 src/a src/sub/b src/link src/sub src
tar -cf /tmp/x.tar --owner=0 --group=0 --numeric-owner --mtime=@1700000000 --sort=name src; echo "rc=$?"; tar -tf /tmp/x.tar; echo --; tar -tvf /tmp/x.tar
