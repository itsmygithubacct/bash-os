# archive/tar-incremental-past-mtime: -g level 1 with a modified file whose mtime is set into the past
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir data; printf '1\n' > data/keep; printf '2\n' > data/change; touch -d @1600000000 data/* data
cd /tmp; tar -cf l0.tar -g snap -C /work data; cd /work
sleep 1.1  # the change (and its ctime) falls in a later second than the level-0 dump
printf 'changed\n' > data/change; touch -d @1700000000 data/change
cd /tmp; tar -cf l1.tar -g snap -C /work data; tar -tf l1.tar | sort
