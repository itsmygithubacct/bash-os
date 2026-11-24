# files/stat-formats: stat -c directives on fixed files
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p d/sub; printf 'hello\n' > d/a; printf '' > d/empty; printf '%0100d' 0 > d/big
ln -s a d/link; ln d/a d/hard; chmod 750 d/sub; chmod 600 d/big
touch -h -d @1700000000 d/a d/empty d/big d/link d/sub d
stat -c '%n|%s|%a|%A|%F|%h|%Y|%X' d/a d/big d/sub d/link | sort
stat -c '%y' d/a; stat -c '%N' d/link; stat -L -c '%F %s' d/link; stat --printf '%n:%s\n' d/a d/empty
stat -c '%x' d/a; stat -c '%W' d/a >/dev/null && echo has-W; stat -t d/a | cut -d' ' -f1-3
# --- stat -c with %s of symlink and directory and --terse fields
mkdir part-stat-fs-free && (cd part-stat-fs-free || exit
printf 'abc' > f; ln -s f l
stat -c '%s %F' l; stat -L -c '%s %F' l; stat -c '%a %F' . | cut -d' ' -f2-
)
