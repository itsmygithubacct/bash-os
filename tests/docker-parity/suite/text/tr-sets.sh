# text/tr-sets: tr ranges, classes, -d -s -c
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
echo 'Hello, World 123' | tr a-z A-Z
echo 'Hello, World 123' | tr -d '[:digit:]'
echo 'aaabbbccc  dd' | tr -s 'a-c '
echo 'Hello, World 123' | tr -cd '[:alpha:]\n'
echo 'Hello, World' | tr '[:upper:][:lower:]' '[:lower:][:upper:]'
echo 'a-b_c' | tr -- '-_' '  '
echo 'abc' | tr 'abc' 'x'
echo 'abcabc' | tr -s 'a-z' 'A-Z'
printf 'a\tb\n' | tr '\t' '|'
echo 'tab' | tr 'a-c' '[x*]'
echo 'hello' | tr -c 'l\n' '.'
