set -eu
umask 022
value=before
change() { value=after; }
change
[[ $value == after ]]
declare -A counts=([one]=1 [two]=2)
printf '%s %s %s\n' "$value" "${counts[one]}" "$1"
IFS= read -r line
printf 'input=<%s>\n' "$line"
mkdir -p nested
printf 'a\0b\n' > nested/data
ln nested/data nested/hard
ln -s data nested/link
chmod 640 nested/data
printf 'warning\n' >&2
