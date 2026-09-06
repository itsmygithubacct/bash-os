#!/usr/bin/env bash
# tests/stat-parity.sh [BINARY] — this repo's stat against GNU coreutils' stat
# on the same files: every directive, -L -t, the default layout, --printf.
# Skips without a GNU stat on the host.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=${1:-$HERE/out/bash}
G=$(command -v stat); [[ -n "$G" ]] && "$G" --version 2>/dev/null | grep -q coreutils || { echo "stat-parity: SKIP (no GNU stat)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
printf 12345 > "$d/f"; chmod 4755 "$d/f"; mkdir "$d/dir"; ln -s f "$d/l"; touch "$d/f with space"; ln -s "f with space" "$d/sp"
FMT='%a|%A|%b|%B|%d|%D|%f|%F|%g|%G|%h|%i|%n|%N|%o|%s|%t|%T|%u|%U|%w|%W|%x|%X|%y|%Y|%z|%Z|%Hd|%Ld|%m|%-8s|%08s|%5u|%%'
fail=0; n=0
for t in "$d/f" "$d/dir" "$d/l" "$d/sp" "$d/f with space" /dev/null; do
  "$G" -c %x "$t" >/dev/null; "$BX" -c "PATH=; stat -c %x \"$t\"" >/dev/null   # settle relatime on fresh symlinks
  F=$FMT; link=0; [[ -L "$t" ]] && link=1
  for args in "-c FMT" "-L -t" "" "--printf=%s\t%N\n"; do
    # readlink bumps a link's own atime between the two runs: leave %x/%X and the
    # Access line out for a link that is not followed
    if [[ $link == 1 && "$args" != *-L* ]]; then F=${FMT/'%x|%X|'/}; else F=$FMT; fi
    args=${args/FMT/$F}
    # the arguments reach both stats as argv words, never re-parsed by a shell
    n=$((n+1)); a=$("$G" $args "$t" 2>&1); b=$("$BX" -c 'PATH=; stat "$@"' _ $args "$t" 2>&1)
    if [[ $link == 1 && "$args" != *-L* ]]; then a=$(sed '/^Access: [0-9]/d' <<<"$a"); b=$(sed '/^Access: [0-9]/d' <<<"$b"); fi
    [[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF stat $args $t"; diff <(echo "$a") <(echo "$b") | head -4 | sed 's/^/    /'; }
  done
done
echo "stat-parity: $((n-fail))/$n identical to $("$G" --version | head -1)"; exit $(( fail>0 ? 1 : 0 ))
