# files/ls-long: ls -l formats with fixed times, owner and group hidden
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p d/sub; printf 'hello\n' > d/a; printf '' > d/empty; printf '%0100d' 0 > d/big
ln -s a d/link; ln d/a d/hard; chmod 750 d/sub; chmod 600 d/big
touch -h -d @1700000000 d/a d/empty d/big d/link d/sub d
ls -lgo d; echo --; ls -lgo --time-style=long-iso d; echo --; ls -lgo --time-style=full-iso d/a
echo --; ls -lgo --time-style=+%Y%m%d d; echo --; ls -lgo -d d/sub; echo --; ls -n d | awk '{print $1, $2, $5}'
