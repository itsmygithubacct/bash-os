# files/cp-archive: cp -a keeps links, modes and times
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p d/sub; printf 'hello\n' > d/a; printf '' > d/empty; printf '%0100d' 0 > d/big
ln -s a d/link; ln d/a d/hard; chmod 750 d/sub; chmod 600 d/big
touch -h -d @1700000000 d/a d/empty d/big d/link d/sub d
cp -a d da; stat -c '%n %a %F %Y' da/a da/link da/sub da/big | sort; readlink da/link
[ da/a -ef da/hard ] && echo hardlink-kept
