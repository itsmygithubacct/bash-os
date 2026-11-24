# awk/awk-regex: dynamic regex, ~ !~, character classes, escaped slashes
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'abc123\nXYZ\nfoo/bar\n\n' | awk '/[[:digit:]]+/{print "d:"$0} $0 ~ "^[A-Z]+$"{print "u:"$0} /\//{print "s:"$0} !/./{print "empty"}'
awk 'BEGIN{r="^a.c$"; print ("abc" ~ r), ("abd" !~ r), ("a+c" ~ /a\+c/), match("xxabbb", /ab+/), RLENGTH; print ("ab" ~ /a{2}/), ("aab" ~ /a{2}/)}'
