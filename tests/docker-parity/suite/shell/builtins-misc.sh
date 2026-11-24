# shell/builtins-misc: type, command -v, hash, getopts, let, shift, printf %s of $-
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
type -t cd; type -t type; command -v cd; f() { :; }; type -t f; set -- -a -b val -c rest; while getopts 'ab:c' o; do echo "$o ${OPTARG-}"; done; shift $((OPTIND-1)); echo "$@"
let 'z=3*4'; echo $z; echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"; umask -S; ulimit -n >/dev/null && echo ulimit-ok
# --- case patterns and ;& ;;& fallthrough
mkdir part-case-select && (cd part-case-select || exit
for w in apple Banana 42 x.y ''; do case $w in a*) echo "a: $w";; [A-Z]*) echo "cap: $w" ;& *[0-9]*) echo "fall: $w";; *.*) echo dot;; '') echo empty;; esac; done
case abc in a*) echo one ;;& *c) echo two ;; esac
)
