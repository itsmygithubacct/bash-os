# shell/glob-options: globbing with nullglob, extglob, globstar, dotglob
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
shopt -s extglob
mkdir -p d/e; touch d/a.txt d/b.log d/.h d/e/c.txt
echo d/*.txt; shopt -s nullglob; echo d/*.none; shopt -u nullglob; echo d/*.none; echo d/!(*.txt); echo d/@(a|b).*
shopt -s globstar; echo d/**/*.txt; shopt -s dotglob; echo d/*; echo d/[ab].*
