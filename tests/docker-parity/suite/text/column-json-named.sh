# text/column-json-named: column -N/-R/-J table output
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'alice 30\nbob 5\n' > f
column -t -N NAME,AGE f; echo --; column -t -N NAME,AGE -R AGE f; echo --; column -J -N name,age f
echo --; column -t -N NAME,AGE -H AGE f
