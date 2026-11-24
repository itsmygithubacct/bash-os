# shell/functions-scope: local, declare -n namerefs, recursion
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
x=global; f() { local x=local; g; }; g() { echo "$x"; }; f; echo "$x"
setv() { local -n ref=$1; ref=changed; }; v=orig; setv v; echo "$v"; fib() { (( $1 < 2 )) && echo $1 && return; echo $(( $(fib $(( $1-1 ))) + $(fib $(( $1-2 ))) )); }; fib 10
declare -f g | head -n 1; declare -i i=5; i+=2; echo $i; declare -u up=low; echo $up
