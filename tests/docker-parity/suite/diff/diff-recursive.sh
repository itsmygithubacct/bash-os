# diff/diff-recursive: -r, -N, -q, -s and only-in reports
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p a/s b/s; printf '1\n' > a/f; printf '2\n' > b/f; printf 'x\n' > a/only; printf 'y\n' > b/s/new; printf 'same\n' > a/s/eq; printf 'same\n' > b/s/eq
touch -d @1700000000 a/* a/s/* b/* b/s/*
diff -r a b; echo "rc=$?"; diff -rq a b; echo --; diff -rs a b | sort; echo --; diff -ruN a b; echo "rc=$?"
# --- diff - and -x exclusion in -r
mkdir part-diff-stdin-exclude && (cd part-diff-stdin-exclude || exit
printf 'a\n' > f; printf 'b\n' | diff f -; echo "rc=$?"
mkdir -p p q; printf '1\n' > p/keep; printf '2\n' > q/keep; printf 'o\n' > p/skip.o; diff -r -x '*.o' p q; echo "rc=$?"
)
