# numbers/bc-forms: bc arithmetic, scale, -l, functions, ibase/obase
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
echo '2^64' | bc; echo '10/3' | bc; echo 'scale=5; 10/3' | bc; echo 's(1)' | bc -l; echo 'l(10)' | bc -l; echo 'sqrt(2)' | bc -l
echo 'obase=16; 255' | bc; echo 'ibase=2; 1010' | bc; echo 'define f(n) { if (n<2) return 1; return n*f(n-1); }; f(25)' | bc
echo '-7 % 3' | bc; echo 'scale=2; -7/2' | bc; echo '1/0' | bc; echo "rc=$?"; echo 'x=3; x++; x' | bc; echo '2^200' | bc
