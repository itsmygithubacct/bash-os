# files/install-forms: install -m, -d, -D, -t
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
command -v install >/dev/null || install() { coreutils install "$@"; }
printf 'x\n' > src
install -m 640 src dst; stat -c '%n %a' dst; install -d -m 755 dd/ee; stat -c '%n %a' dd dd/ee
install -D src deep/er/file; stat -c '%n %a' deep/er/file; mkdir t; install -t t -m 600 src dst; stat -c '%n %a' t/src t/dst
install -m u=rw,go=r src sym; stat -c %a sym
