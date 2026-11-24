# sed/sed-regex: BRE/ERE classes, intervals, anchors, backrefs
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf 'aaa\nab12\nx  y\nfoo.bar\nABab\n' > f
sed -n '/^a\{2,\}$/p' f; sed -nE '/[0-9]{2}/p' f; sed -n '/[[:space:]]\{2\}/p' f; sed -n '/\./p' f; sed 's/[[:upper:]]/U/g' f
sed -nE '/(a)\1/p' f; sed -n '/a\|y/p' f; sed -nE 's/^(.)(.)/\2\1/p' f; sed 's/\bb/B/g' f; sed -n '/^[^a]/p' f; sed 's/a*/X/g' f
