#!/usr/bin/env bash
# Focused isolated-root proof for the static grep selection; no compilation.
set -euo pipefail
binary=$(readlink -f "${1:?static binary required}")
file "$binary" | grep -q 'statically linked'
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/bin" "$root/proc" "$root/dev" "$root/tmp"
cp "$binary" "$root/bin/bash"
cat > "$root/check.sh" <<'SH'
set -e
PATH=
[[ $(type -t grep) == builtin ]]
printf 'foo\nbar\nfoobar\n' > /tmp/text
[[ $(grep -Pc 'foo(?=bar)' /tmp/text) == 1 ]]
[[ $(grep -Pwc 'foo|bar' /tmp/text) == 2 ]]
[[ $(printf 'a\nb\0aa\0' | grep -Pzc '(?s)a.b') == 1 ]]
{ grep -m1 .; grep -m1 .; grep -m1 .; } < /tmp/text > /tmp/seen
[[ $(grep -c . /tmp/seen) == 3 ]]
grep -P '[' /tmp/text 2>/dev/null && exit 3 || [[ $? == 2 ]]
printf 'sol-grep-rootfs: PASS (only static Bash and fixtures)\n'
SH
bwrap --setenv LC_ALL C --unshare-all --uid 0 --gid 0 \
  --bind "$root" / --proc /proc --dev /dev --tmpfs /tmp /bin/bash /check.sh
