# text/nl-sections: nl logical page sections
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '\\:\\:\\:\nhead\n\\:\\:\nbody1\nbody2\n\\:\nfoot\n\\:\\:\nbody3\n' > f
nl f; echo --; nl -ha -fa f; echo --; nl -p f
