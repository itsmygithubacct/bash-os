# shell/regex-match: [[ =~ ]] with BASH_REMATCH and quoting
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
s='key=value; other=42'; if [[ $s =~ ([a-z]+)=([0-9]+) ]]; then echo "${BASH_REMATCH[0]} ${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"; fi
re='^[0-9]+$'; [[ 123 =~ $re ]] && echo num; [[ 'a.b' =~ a.b ]] && echo dot; [[ 'axb' =~ "a.b" ]] || echo quoted-literal
[[ abc == a* ]] && echo glob; shopt -s nocasematch; [[ ABC == abc ]] && echo nocase
