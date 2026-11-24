# text/csplit-options: csplit -k, -z, offsets, --suppress-matched
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\n--\nb\n--\n--\nc\n' > f
csplit -z -s f '/--/' '{*}'; for x in xx*; do printf '%s=' "$x"; tr '\n' , < "$x"; echo; done; rm -f xx*
csplit -s --suppress-matched f '/--/' '{*}'; for x in xx*; do printf '%s=' "$x"; tr '\n' , < "$x"; echo; done; rm -f xx*
seq 1 10 > g; csplit -s g '/3/+2' '%7%'; for x in xx*; do printf '%s=' "$x"; tr '\n' , < "$x"; echo; done; rm -f xx*
