# shell/jobs-wait: background jobs, wait -n, $? of waited jobs
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
( exit 3 ) & p=$!; wait $p; echo "rc=$?"; sleep 0.1 & sleep 0.2 & wait -n; echo "first-done=$?"; wait; ( exit 5 ) & wait -n; echo "rc=$?"
coproc C { read -r x; echo "co:$x"; }; echo hi >&"${C[1]}"; read -r y <&"${C[0]}"; echo "$y"; wait
