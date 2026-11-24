# files/ls-sizes: ls -s, -h, --block-size, -k on fixed sizes
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%01024d' 0 > k1; printf '%01500d' 0 > k15; : > zero; touch -d @1700000000 k1 k15 zero
ls -lgo --block-size=1 k1 k15 zero | awk '{print $3, $NF}'; ls -lgoh k1 k15; ls -lgo --si k15
