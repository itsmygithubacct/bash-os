# files/dirs-ordering: ls -l on a directory with many entries sorts by name
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
for i in $(seq 1 40); do touch "f$i"; done; touch -d @1700000000 f*
ls | head -n 5; ls -1v | tail -n 3; ls -lgo | head -n 3
