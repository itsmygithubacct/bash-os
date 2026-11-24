# shell/mapfile-readarray: mapfile with -t -d -n -s and a callback
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mapfile -t lines < <(printf 'l1\nl2\nl3\n'); printf '<%s>' "${lines[@]}"; echo
mapfile -d , -t parts <<< 'a,b,c'; printf '<%s>' "${parts[@]}"; echo
mapfile -t -n 2 -s 1 sub < <(seq 5); echo "${sub[*]}"; readarray -t -C 'printf cb:%s:%s\\n' -c 2 r < <(seq 4)
