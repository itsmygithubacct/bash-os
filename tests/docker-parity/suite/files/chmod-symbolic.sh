# files/chmod-symbolic: chmod symbolic and octal modes
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
touch f; mkdir d
for m in 644 u+x g-r o=rw a-w u=rwx,g=rx,o= +t g+s u-s 0 a+X 755 go-x u+r,u-w =r +r-w; do chmod "$m" f; printf '%s %s\n' "$m" "$(stat -c %a f)"; done
chmod 600 d; chmod a+X d; stat -c %a d; chmod -R u+rwx,go-rwx d; stat -c %a d; chmod --reference=f d; stat -c %a d
