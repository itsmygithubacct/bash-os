# find/xargs-max-args-repl: xargs -I with -n interplay, -x, --process-slot-var
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\nb\nc\n' | xargs -I % sh -c 'echo "% %"'
printf '1\n2\n' | xargs -P1 --process-slot-var=SLOT -n1 sh -c 'echo "$SLOT $0"'
printf 'a\0b\0' | xargs -0 -I{} echo '[{}]'; printf '%s\n' a b c | xargs -E b echo
