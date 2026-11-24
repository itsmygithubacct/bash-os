# archive/tar-extract: extract with modes, links and times preserved
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p src/sub; printf 'alpha\n' > src/a; printf 'beta\n' > src/sub/b; ln -s a src/link; chmod 640 src/a; chmod 750 src/sub
touch -h -d @1700000000 src/a src/sub/b src/link src/sub src
tar -cf /tmp/x.tar src; mkdir out; tar -xf /tmp/x.tar -C out; stat -c '%n %a %F %Y' out/src out/src/a out/src/sub out/src/sub/b out/src/link | sort; readlink out/src/link
