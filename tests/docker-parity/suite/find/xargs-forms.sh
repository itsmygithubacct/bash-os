# find/xargs-forms: xargs -n -L -I -d -s -r -t
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a b c\nd e\n\nf\n' > in
xargs echo < in; xargs -n 2 echo < in; xargs -L 1 echo < in; xargs -I{} echo 'x{}y' < in
printf 'a,b,c' | xargs -d, -n1 echo; : | xargs -r echo nothing; : | xargs echo empty
printf '1 2 3\n' | xargs -t -n1 echo 2>&1; printf 'a b c d e\n' | xargs -s 12 echo
