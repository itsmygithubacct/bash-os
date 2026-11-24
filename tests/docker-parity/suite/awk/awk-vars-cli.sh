# awk/awk-vars-cli: -v, var=value operands, ENVIRON, ARGV, FILENAME (G23 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'x\n' > f; printf 'y\n' > g
awk -v 'v=a\tb' 'BEGIN{print v}' | od -An -c; awk '{print n, $0, FILENAME}' n=1 f n=2 g
awk 'BEGIN{for (i=0;i<ARGC;i++) print i, ARGV[i]}' p q | sed '1s/.*/0 awk/'; awk 'END{print NR, FNR, FILENAME}' f g
