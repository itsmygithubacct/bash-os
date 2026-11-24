# files/readlink-realpath: readlink -f -e -m, realpath --relative-to, -s, -m
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p a/b; touch a/b/f; ln -s b a/lb; ln -s a/lb/f top; ln -s nowhere dang
readlink top; readlink -f top; readlink -e top; readlink -m x/../y; readlink -e dang; echo "rc=$?"
realpath top; realpath -s top; realpath --relative-to=a a/b/f; realpath -m no/such/../z; realpath -e dang; echo "rc=$?"
realpath --relative-base=a a/b/f "$PWD"; realpath -z a | od -An -c
