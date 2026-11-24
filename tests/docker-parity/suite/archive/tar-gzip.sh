# archive/tar-gzip: tar -z round trip and gzip-compressed listing
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p src/sub; printf 'alpha\n' > src/a; printf 'beta\n' > src/sub/b; ln -s a src/link; chmod 640 src/a; chmod 750 src/sub
touch -h -d @1700000000 src/a src/sub/b src/link src/sub src
tar -czf /tmp/x.tgz --owner=0 --group=0 --numeric-owner --mtime=@1700000000 --sort=name src; gzip -t /tmp/x.tgz && echo gz-ok; tar -tzf /tmp/x.tgz; mkdir o; tar -xzf /tmp/x.tgz -C o; cat o/src/a o/src/sub/b
