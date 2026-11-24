# archive/tar-incremental: -g level 0 and level 1 chain (G111 seed)
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir data; printf '1\n' > data/keep; printf '2\n' > data/change; printf '3\n' > data/gone; touch -d @1600000000 data/* data
cd /tmp; tar -cf l0.tar -g snap -C /work data; tar -tf l0.tar | sort; cd /work
sleep 1.1  # the level-1 changes must fall in a later second than the level-0 dump
printf 'changed\n' > data/change; rm data/gone; printf 'new\n' > data/added
cd /tmp; tar -cf l1.tar -g snap -C /work data; tar -tf l1.tar | sort; cd /work
mkdir r; tar -xf /tmp/l0.tar -g /dev/null -C r; tar -xf /tmp/l1.tar -g /dev/null -C r; find r -type f | sort; cat r/data/change
