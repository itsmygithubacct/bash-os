# files/cp-backup: cp --backup numbered and simple, -u
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'v1\n' > f; printf 'v2\n' > g; printf 'v3\n' > h
cp --backup=numbered g f; cp --backup=numbered h f; ls f*; cat f f.~1~ f.~2~
printf 'n\n' > n; cp -b --suffix=.bak g n; ls n*
touch -d @2000 new; touch -d @1000 old; printf 'O\n' > old; touch -d @1000 old; printf 'N\n' > new; touch -d @2000 new
cp -u old new; cat new
