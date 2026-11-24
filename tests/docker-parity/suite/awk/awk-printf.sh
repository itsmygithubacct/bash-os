# awk/awk-printf: printf formats: widths, precision, %c %e %g %x %o %%
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
awk 'BEGIN{printf "%5d|%-5d|%05d|%+d\n", 42, 42, 42, 42
printf "%.2f|%10.3f|%-8.1e|%g|%G\n", 3.14159, 2.5, 12345.678, 0.0001234, 1e20
printf "%x|%X|%o|%c|%c|%%|%s\n", 255, 255, 8, 65, "hello", "str"
printf "%*d|%-*s|%.3s\n", 6, 7, 4, "ab", "abcdef"
printf "%i|%5.2s|\n", 3.9, "xyz"; printf "%d %d\n", "12abc", -3.7}' 2>&1
