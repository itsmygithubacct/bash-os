# files/ls-escapes: ls quoting of awkward names
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch 'sp ace' 'tab	x' "q'uote" 'new
line' 'star*'
ls; echo --; ls -b; echo --; ls -N; echo --; ls --quoting-style=shell-escape; echo --; ls --quoting-style=c; echo --; ls -q
