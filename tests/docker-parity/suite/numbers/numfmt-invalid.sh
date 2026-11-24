# numbers/numfmt-invalid: numfmt diagnostics for invalid input
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
command -v numfmt >/dev/null || numfmt() { coreutils numfmt "$@"; }
numfmt abc; echo "rc=$?"; numfmt --invalid=warn abc 10; echo "rc=$?"
