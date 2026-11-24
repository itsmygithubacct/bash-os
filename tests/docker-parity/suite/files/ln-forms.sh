# files/ln-forms: ln hard, -s, -sf, -r, -T, -n
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'x\n' > t; mkdir d
ln t h; stat -c %h t; ln -s t s; readlink s; ln -sf h s; readlink s; ln -sr t d/rel; readlink d/rel
ln -s d dl; ln -sfn t dl; readlink dl; ln -s t d/; ls d; ln -sT t named; readlink named
ln --backup=numbered -s h s; ls s*
# --- ln onto existing files and missing targets
mkdir part-ln-errors && (cd part-ln-errors || exit
touch a b
ln a b; echo "rc=$?"; ln -s a b; echo "rc=$?"; ln nosuch c; echo "rc=$?"; ln -f a b; [ a -ef b ] && echo forced
)
