# files/mktemp-patterns: mktemp file and dir names follow the template
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
f=$(mktemp -p . tmp.XXXXXX); [[ $f =~ ^\./tmp\.[A-Za-z0-9]{6}$ ]] && echo file-ok; stat -c %a "$f"; rm "$f"
d=$(mktemp -d -p . dXXXX); [[ $d =~ ^\./d[A-Za-z0-9]{4}$ ]] && echo dir-ok; stat -c %a "$d"; rmdir "$d"
s=$(mktemp -p . --suffix=.txt aXXX); [[ $s == ./a???.txt ]] && echo suffix-ok; rm "$s"
u=$(mktemp -u -p . uXXXXXX); [[ -e $u ]] || echo dry-run-ok
mktemp -p . bad; echo "rc=$?"; mktemp -p . aXX; echo "rc=$?"
t=$(TMPDIR=$PWD mktemp -t zzXXXXXX); [[ $t == "$PWD"/zz* ]] && echo tmpdir-ok; rm "$t"
