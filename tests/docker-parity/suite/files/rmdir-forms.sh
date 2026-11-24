# files/rmdir-forms: rmdir -p and non-empty refusal
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p a/b/c; rmdir -p a/b/c; ls -d a 2>/dev/null; echo "rc=$?"
mkdir -p x/y; touch x/f; rmdir x; echo "rc=$?"; rmdir --ignore-fail-on-non-empty x; echo "rc=$?"; rmdir -v x/y
# --- link and unlink
mkdir part-link-unlink && (cd part-link-unlink || exit
printf 'x\n' > a; link a b; stat -c %h a; unlink b; stat -c %h a; unlink a; ls
)
