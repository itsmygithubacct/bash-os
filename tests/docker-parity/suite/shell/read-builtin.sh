# shell/read-builtin: read with -r -a -d -n -N, IFS splitting
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
IFS=: read -r a b c <<< 'x:y:z:w'; echo "$a|$b|$c"; read -r -a arr <<< '1 2  3'; echo "${#arr[@]}"; read -d , first <<< 'p,q'; echo "$first"
read -n 3 three <<< 'abcdef'; echo "$three"; read -N 4 four <<< $'ab\ncd'; printf '%q\n' "$four"; read -r line <<< 'back\slash'; echo "$line"; read line <<< 'back\slash'; echo "$line"
