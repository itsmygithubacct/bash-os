# shell/redirection: fd duplication, exec {fd}, noclobber, &> and |&
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
exec {fd}> out; echo via-fd >&$fd; exec {fd}>&-; cat out; set -C; echo x > out 2>/dev/null || echo clobber-refused; echo y >| out; cat out; set +C
{ echo o; echo e >&2; } &> both; sort both; { echo o2; echo e2 >&2; } |& sort; exec 3<<< 'fd3'; read -r l <&3; echo "$l"
