# awk/awk-math: int, sqrt, exp, log, sin, atan2, srand determinism, number output
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{print int(-3.7), int("4x"), sqrt(16), exp(1), log(10), sin(0), cos(0), atan2(0,-1)
print 1e6, 1e16, 123456789012, 0.1+0.2, 1/3, -0, 100000*100000, 2^10, 2**3; OFMT="%.2f"; x=3.14159; print x, x ""; CONVFMT="%.3g"; y=2.71828; z=y ""; print z
srand(1); a=rand(); srand(1); b=rand(); print (a==b), (a>=0 && a<1)}'
