# text/uniq-basic: uniq -c -d -u -i
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%s\n' a a b c c c a A a > f
uniq f; echo --; uniq -c f; echo --; uniq -d f; echo --; uniq -u f
echo --; uniq -i f; echo --; uniq -ic f; echo --; uniq -D f
