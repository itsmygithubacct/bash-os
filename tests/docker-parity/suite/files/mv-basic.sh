# files/mv-basic: mv rename, into directories, -n, -t, -T, -b
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'a\n' > a; printf 'b\n' > b; mkdir dir
mv a c; ls; mv c dir; ls dir; printf 'x\n' > x; mv -n b x; cat x b
mv -t dir b x; ls dir; mkdir e; mv -T e f; ls -d f
printf 'one\n' > p; printf 'two\n' > q; mv -b p q; ls q*; cat q q~
# --- mv a missing source and a directory onto a file
mkdir part-mv-errors && (cd part-mv-errors || exit
touch f; mkdir d
mv nosuch x; echo "rc=$?"; mv d f; echo "rc=$?"; mv d d/inner; echo "rc=$?"
)
