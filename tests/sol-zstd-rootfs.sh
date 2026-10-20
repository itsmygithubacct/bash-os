#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Optional isolated-root static qualification; 77 means unavailable, never pass.
set -euo pipefail
BX=$(readlink -f "${1:?static binary required}")
file "$BX" | grep -q 'statically linked' || { echo 'FAIL: static binary required'; exit 1; }
command -v bwrap >/dev/null || { echo 'UNAVAILABLE: bubblewrap missing'; exit 77; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/root/proc" "$d/root/dev" "$d/root/tmp"
cp "$BX" "$d/root/bash"
cat > "$d/root/test.sh" <<'IN'
set -euo pipefail
PATH=
cd /tmp
printf 'standalone static stream\n' > input
zstd -1 -o one.zst input
[[ $(zstdcat one.zst) == 'standalone static stream' ]]
printf 'named stdin' | zstd -19 -o stdin.zst -
[[ $(zstd -dc stdin.zst) == 'named stdin' ]]
for ((i=0;i<20;i++)); do
  zstd -3 -f -o repeat.zst input
  zstd -df -o restored repeat.zst
  [[ $(zstd -c restored | zstd -dc -) == 'standalone static stream' ]]
done
printf 'bad input' > broken.zst
printf 'old destination' > keep
if zstd -df --rm -o keep broken.zst; then exit 1; fi
[[ -f broken.zst && -f keep ]]
# Compression of the sentinel makes its content observable using only native tools.
[[ $(zstd -c keep | zstd -dc -) == 'old destination' ]]
zstd --rm -f -o final.zst restored
[[ ! -e restored && $(zstdcat final.zst) == 'standalone static stream' ]]
echo 'sol-zstd-rootfs: PASS (only static shell and test script in root)'
IN
if ! bwrap --setenv LC_ALL C --setenv LANG C --unshare-all --ro-bind "$d/root" / --proc /proc --dev /dev --tmpfs /tmp /bash -c ':' > "$d/probe.log" 2>&1; then
  echo 'UNAVAILABLE: isolated root namespaces cannot be created'
  cat "$d/probe.log"
  exit 77
fi
bwrap --setenv LC_ALL C --setenv LANG C --unshare-all --ro-bind "$d/root" / --proc /proc --dev /dev --tmpfs /tmp /bash /test.sh
