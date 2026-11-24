# text/sort-numeric: -n -g -h -V orderings
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '%s\n' 10 9 -1 1.5 -0 0 +3 abc 1e3 ' 7' 007 | sort -n
echo --; printf '%s\n' 1e3 10 2.5e-1 -inf nan 0x10 9 | sort -g
echo --; printf '%s\n' 1K 512 2M 1.5G 900 3k 1T 0 | sort -h
echo --; printf '%s\n' file10 file2 file1.10 file1.9 a-1.2.10 a-1.2.9 1.0rc1 1.0 1.0a | sort -V
echo --; printf '%s\n' 3 1 2 | sort -rn
