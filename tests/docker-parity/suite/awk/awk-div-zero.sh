# awk/awk-div-zero: division by zero is fatal (G104 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{x=0; print 1/x}'; echo "rc=$?"; awk 'BEGIN{x=0; print 1%x}'; echo "rc=$?"
echo 0 | awk '{print 5/$1} END{print "end ran"}'; echo "rc=$?"; awk 'BEGIN{y=0; z=4; z/=y; print z}'; echo "rc=$?"
