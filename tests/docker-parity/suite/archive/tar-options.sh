# archive/tar-options: --strip-components, --exclude, -O, member selection
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
mkdir -p src/sub; printf 'alpha\n' > src/a; printf 'beta\n' > src/sub/b; ln -s a src/link; chmod 640 src/a; chmod 750 src/sub
touch -h -d @1700000000 src/a src/sub/b src/link src/sub src
A=/tmp/x.tar; tar -cf $A src; mkdir s; tar -xf $A -C s --strip-components=1; ls -R s; tar -xOf $A src/sub/b
mkdir e; tar -xf $A -C e --exclude='b'; find e | sort; mkdir m; tar -xf $A -C m src/a; find m | sort
tar -tf $A --wildcards '*/b'; tar -tf $A nosuch; echo "rc=$?"
