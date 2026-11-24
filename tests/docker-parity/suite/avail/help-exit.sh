# avail/help-exit: --help exits 0 and writes stdout for common tools
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
for c in sort uniq cut head tail wc ls cp mv rm mkdir touch stat chmod ln find xargs grep sed tr du; do $c --help </dev/null >o 2>e; printf '%s rc=%s stdout=%s stderr=%s\n' "$c" "$?" "$([ -s o ] && echo yes || echo no)" "$([ -s e ] && echo yes || echo no)"; done; rm -f o e
