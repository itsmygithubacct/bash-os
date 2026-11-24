# files/cp-basic: cp files, -r, -p modes, -n, -T, -t
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p d/sub; printf 'hello\n' > d/a; printf '' > d/empty; printf '%0100d' 0 > d/big
ln -s a d/link; ln d/a d/hard; chmod 750 d/sub; chmod 600 d/big
touch -h -d @1700000000 d/a d/empty d/big d/link d/sub d
cp d/a copy; cat copy; cp -r d d2; ls -R d2; cp -p d/big big2; stat -c '%a %s %Y' big2
printf 'orig\n' > keep; cp -n d/a keep; cat keep
mkdir dest; cp -t dest d/a d/empty; ls dest; cp -rT d d3; ls d3
# --- cp without -p applies the umask to new files
mkdir part-cp-preserve-mode && (cd part-cp-preserve-mode || exit
printf 'x\n' > f; chmod 777 f; cp f g; stat -c %a g; umask 077; cp f h; stat -c %a h; cp --preserve=mode f i; stat -c %a i
)
# --- cp into a missing directory, onto itself, dir without -r
mkdir part-cp-errors && (cd part-cp-errors || exit
printf 'x\n' > f; mkdir d
cp f nodir/; echo "rc=$?"; cp f f; echo "rc=$?"; cp d e; echo "rc=$?"; cp nosuch g; echo "rc=$?"
)
