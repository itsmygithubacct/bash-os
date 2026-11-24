# numbers/printf-builtin: printf builtin (same bash): formats and escapes
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%5s|%-5s|%.2s|%c\n' ab ab abc xyz; printf '%d %i %o %x %X %u\n' 42 -7 8 255 255 3; printf '%5.2f %e %g %G\n' 3.14159 1234.5 0.00001 1e100
printf '%b\n' 'a\tb\x41\101'; printf '%q\n' "it's" 'a b' $'\n'; printf '%s\n' a b c; printf '%(%F)T\n' 1700000000; printf '%#x %#o %+d % d\n' 255 8 5 5
printf '%d\n' 0x1f 010 "'A"; printf '%s %s\n' 1; printf 'x%.0sy\n' z; printf '%d\n' abc; echo "rc=$?"
