# avail/coreutils-names: coreutils commands reachable by their own names
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
for c in install fmt factor numfmt tsort shuf nproc yes shred groups mknod sha1sum sha224sum sha384sum sha512sum b2sum sum base32 basenc dircolors ptx; do printf '%s ' "$c"; command -v "$c" >/dev/null && echo found || echo missing; done
