# shell/expansions: parameter expansion operators
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
p=/a/b/c.tar.gz; echo "${p##*/} ${p%%.*} ${p#*.} ${p%.*} ${p/b/B} ${p//\//:} ${#p} ${p:3:4} ${p^^} ${p,}"
v=; echo "[${v:-d}] [${v-d}] [${v:+s}] [${u:=set}] $u"; n=abc; echo "${n@Q} ${n@U} ${!n@} $((${#n}*2))"; set -- x y z; echo "$# ${*:2} ${@: -1}"
echo {a,b}{1,2} {1..5..2} {c..a}; x=5; echo $(( x++ + ++x )); echo $'tab\there' "$(printf '%s' sub)" `echo back`
# --- here-documents and here-strings
mkdir part-here-docs && (cd part-here-docs || exit
cat <<EOF
var=$HOME-x $((1+2))
EOF
cat <<'EOF'
literal $HOME
EOF
cat <<-EOF
	tab-stripped
	EOF
read -r a b <<< 'one two'; echo "$b $a"
)
