# files/ls-sorting: ls sort orders: -t -S -r -X -v -U count
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch -d @1000 old; touch -d @3000 new; touch -d @2000 mid
printf 'aaaa' > s4; printf 'a' > s1; touch -d @500 s4 s1
ls -t; echo --; ls -tr; echo --; ls -S s1 s4 old; echo --; ls -r; echo --
touch b.txt a.c c.txt z f10 f9 f1; ls -X; echo --; ls -v f*; echo --; ls -U | wc -l
