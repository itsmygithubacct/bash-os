# text/wc-utf8: wc -m and -L on multibyte text
export LC_ALL=C.UTF-8 TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'h\303\251llo\n\342\202\254\n' > f
wc -c f; wc -m f; wc -L f
