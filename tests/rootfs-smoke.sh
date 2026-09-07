#!/usr/bin/env bash
# tests/rootfs-smoke.sh [STATIC-BINARY] — the userland claim, made concrete:
# a root filesystem holding ONLY the static bash-os (plus a two-line passwd
# and group) runs a script that uses a dozen commands. Needs bubblewrap
# (bwrap) and user namespaces; skips cleanly without them.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=${1:-$HERE/out/bash-static}
command -v bwrap >/dev/null || { echo "rootfs-smoke: SKIP (no bwrap)"; exit 0; }
[[ -x "$BX" ]] || { echo "rootfs-smoke: no static binary at $BX (./build.sh --static)"; exit 1; }
file "$BX" 2>/dev/null | grep -q 'statically linked' || { echo "rootfs-smoke: $BX is not static"; exit 1; }
R=$(mktemp -d); trap 'rm -rf "$R"' EXIT
mkdir -p "$R/bin" "$R/proc" "$R/dev" "$R/tmp" "$R/etc"; cp "$BX" "$R/bin/bash"
echo "root:x:0:0:root:/:/bin/bash" > "$R/etc/passwd"; echo "root:x:0:" > "$R/etc/group"
cat > "$R/etc/script.sh" <<'IN'
set -e; PATH=
[[ -n "$(hostname)" ]]
mkdir -p /tmp/w/a/b; printf 'alpha\nbeta\ngamma\n' > /tmp/w/list
[[ "$(grep -c a /tmp/w/list)" == 3 ]]
[[ "$(sed -n 's/^be/BE/p' /tmp/w/list)" == BEta ]]
[[ "$(printf 'b\na\nb\n' | sort | uniq | head -1)" == a ]]
[[ "$(find /tmp/w -type d | wc -l)" == 3 ]]
[[ "$(stat -c '%s %F' /tmp/w/list)" == "17 regular file" ]]
[[ "$(ps | wc -l)" -ge 2 ]]
[[ "$(df / | tail -1 | wc -w)" -ge 5 ]]
[[ "$(date +%Y)" -ge 2026 ]]; [[ -n "$(uname -m)" ]]
[[ "$(env | grep ^PATH= | cut -d= -f1)" == PATH ]]
[[ "$(env -i NAME=child nice -n 0 printenv NAME)" == child ]]
[[ "$(nohup printf builtin)" == builtin ]]
[[ "$(printf 'one\ntwo\n' | xargs -n 1 -P 2 printf '%s\n' | sort | wc -l)" == 2 ]]
[[ "$(find /tmp/w -type f -exec printf '%s\n' '{}' ';' | wc -l)" == 1 ]]
( cd /tmp/w && pax -w list | pax | grep -qx list )          # archive through a pipe
[[ "$(id -u)" == 0 && "$(whoami)" == root ]]
[[ "$(enable -a | wc -l)" -gt 120 ]]
[[ "$(printf 'compressed payload' | zstd -c - | zstd -dc -)" == 'compressed payload' ]]
echo ONLY-BASH-ROOTFS-OK
IN
out=$(bwrap --setenv LC_ALL C --setenv LANG C --unshare-all --uid 0 --gid 0 --bind "$R" / --proc /proc --dev /dev --tmpfs /tmp /bin/bash /etc/script.sh 2>&1) && [[ "$out" == *ONLY-BASH-ROOTFS-OK* ]] \
  || { echo "rootfs-smoke: FAIL"; echo "$out" | tail -5; exit 1; }
# pax with a uid the 7-digit ustar field cannot hold: it goes into a PAX record
out=$(bwrap --setenv LC_ALL C --setenv LANG C --unshare-all --uid 3000000 --gid 3000000 --bind "$R" / --proc /proc --dev /dev --tmpfs /tmp /bin/bash -c \
  'PATH=; cd /tmp; printf x > f; pax -w f > a.tar; grep -a -c uid=3000000 a.tar; mkdir x; cd x; pax -r < ../a.tar; cat f' 2>&1)
[[ "$out" == $'1\nx' ]] || { echo "rootfs-smoke: FAIL (pax uid overflow): $out"; exit 1; }
echo "rootfs-smoke: PASS ($(find "$R" -type f ! -name script.sh | wc -l) files in the root filesystem; pax uid overflow -> PAX record)"
