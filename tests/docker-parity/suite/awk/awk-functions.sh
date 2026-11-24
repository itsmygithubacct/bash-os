# awk/awk-functions: user functions, recursion, array parameters by reference
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'function fact(n) {return n<=1 ? 1 : n*fact(n-1)} function fill(arr, n,  i) {for (i=1;i<=n;i++) arr[i]=i*i} function loc(  t) {t=5; return t}
BEGIN{print fact(10); fill(sq, 4); print sq[3], length(sq); print loc(), t; untyped(z); print z[1]} function untyped(a) {a[1]="set"}'
