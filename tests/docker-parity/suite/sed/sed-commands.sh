# sed/sed-commands: a i c d D n N p P h H g G x y = l q Q
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'one\ntwo\nthree\nfour\n' > f
sed '2a\
after two' f; sed '2i before two' f; sed '3c changed' f; sed -n '$=' f; sed 'n;d' f; sed '$!N;s/\n/+/' f
sed -n 'h;n;G;p' f; sed '1!G;h;$!d' f; sed 'y/onetw/ONETW/' f; sed '2q' f; sed '2Q' f; printf 'a\tb\001\n' | sed -n l
sed -n 'N;P' f; sed 'N;N;D' f; sed '=' f | sed 'N;s/\n/ /'
