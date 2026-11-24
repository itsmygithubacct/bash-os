# awk/awk-numeric-compare: numeric strings compare numerically (G21 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
echo 9 10 | awk '{print ($1<$2)}'; printf '5\n12\n3\n' | awk '$1>max{max=$1} END{print max}'
awk 'BEGIN{print ("2.0"==2), ("abc"<"abd"), (2<10), ("2"<"10")}'; echo '2.0' | awk '{print ($1==2)}'
awk -v x=10 'BEGIN{print (x>9)}'; echo ' 1e2 ' | awk '{print ($1==100)}'
