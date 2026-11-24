# files/rm-forms: rm -r -f -d -v and refusal cases
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p a/b/c; touch a/b/c/f a/x; mkdir empty
rm -rv a | sort; rm -d empty; ls; rm -f nosuch; echo "rc=$?"
mkdir keep; rm keep; echo "rc=$?"; rm -r . ; echo "rc=$?"; ls -d keep
# --- rm -i reading answers from stdin
mkdir part-rm-interactive-no && (cd part-rm-interactive-no || exit
touch a b
printf 'n\ny\n' | rm -i a b; ls
)
