# files/ls-formats: ls -1 -m -x -C -F -p -Q -i free columns
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p d/sub; printf 'hello\n' > d/a; printf '' > d/empty; printf '%0100d' 0 > d/big
ln -s a d/link; ln d/a d/hard; chmod 750 d/sub; chmod 600 d/big
touch -h -d @1700000000 d/a d/empty d/big d/link d/sub d
ls -1 d; echo --; ls -m d; echo --; ls -F d; echo --; ls -p d; echo --; ls -Q d; echo --
COLUMNS=30 ls -C d; echo --; COLUMNS=30 ls -x d; echo --; ls -w 20 d; echo --; ls -A d/sub; ls -a d | head -2
# --- ls on a missing operand mixed with good ones
mkdir part-ls-errors && (cd part-ls-errors || exit
touch a; ls a nosuch; echo "rc=$?"; ls -d nosuch1 nosuch2; echo "rc=$?"
)
