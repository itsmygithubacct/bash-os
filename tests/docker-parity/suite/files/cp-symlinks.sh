# files/cp-symlinks: cp -L -P -H on symlinks, cp -s and -l
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'x\n' > t; ln -s t l
cp -P l p; stat -c '%n %F' p; cp -L l q; stat -c '%n %F' q; cp -s t s; readlink s; cp -l t h; [ t -ef h ] && echo same
mkdir sd; ln -s ../t sd/up; cp -rH sd sh; stat -c '%F' sh/up; cp -rL sd sl; stat -c '%F' sl/up
