#!/usr/bin/env bash
# Instrument the terminal modules, then load them into a built dynamic Bash.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined
       -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -Iloadables/common
       -I"$BT/builtins" -I"$BT/examples/loadables")
printf 'set -e\n' > "$d/load.sh"
for group in 'buf undo clip nano2' 'fifo escdelay kgetch wgetch wget_wch mouse' \
             'termpixel termpixel_pong' 'pty expect watch script' 'wall'; do
  read -r -a names <<< "$group"
  sources=(); for name in "${names[@]}"; do sources+=("loadables/$name.c"); done
  lib="$d/${names[0]}.so"
  "$CC" "${flags[@]}" "${sources[@]}" -lm -o "$lib"
  [[ $group != wall ]] || names+=(write)
  for name in "${names[@]}"; do printf 'enable -f %q %q\n' "$lib" "$name" >> "$d/load.sh"; done
done
TERMINAL_LOAD_ENV="$d/load.sh" TERMINAL_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/terminal-smoke.py "${1:-out/bash}"
