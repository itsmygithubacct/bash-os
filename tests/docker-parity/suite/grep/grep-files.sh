# grep/grep-files: -l -L -H -h -r -R --include --exclude, and statuses
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p d/s; printf 'hit\n' > d/a.txt; printf 'miss\n' > d/b.txt; printf 'hit\n' > d/s/c.log; ln -s ../a.txt d/s/link
grep -l hit d/a.txt d/b.txt; echo "rc=$?"; grep -L hit d/a.txt d/b.txt; echo "rc=$?"; grep -H hit d/a.txt; grep -h hit d/a.txt d/s/c.log
grep -r hit d | sort; echo --; grep -R hit d | sort; echo --; grep -r --include='*.txt' hit d | sort; echo --; grep -r --exclude='*.txt' hit d | sort
echo --; grep -rl hit d | sort; echo --; grep -rc hit d | sort; echo --; grep -r --exclude-dir=s hit d
