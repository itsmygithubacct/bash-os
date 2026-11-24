# text/tsort-basic: tsort ordering and cycle report
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
command -v tsort >/dev/null || tsort() { coreutils tsort "$@"; }
printf 'a b\nb c\na c\nd c\n' | tsort
echo --; printf 'x y\ny x\n' | tsort; echo "rc=$?"
