# find/xargs-quotes-status: xargs quoting and exit status from commands
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%s\n' "'a b'" '"c d"' 'e\ f' | xargs -n1 printf '<%s>\n'
printf '1\n2\n' | xargs sh -c 'exit 1'; echo "rc=$?"; printf '1\n' | xargs sh -c 'exit 255'; echo "rc=$?"
printf '1\n' | xargs nosuchcmd; echo "rc=$?"; printf "a 'b\n" | xargs echo; echo "rc=$?"
