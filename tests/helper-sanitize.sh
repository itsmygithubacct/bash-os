#!/usr/bin/env bash
# Instrument both wrappers and their selected helper implementations.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined
       -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -Iloadables/common
       -I"$BT/builtins" -I"$BT/examples/loadables")
printf 'set -e\n' > "$d/load.sh"
for group in 'pcre netids' 'zlib zcat' 'more less top slabtop ncdu tui vmstat vi dialog' \
             'toml' 'vt utf8' 'sqlite'; do
  read -r -a names <<< "$group"
  sources=(); libs=(-lm)
  for name in "${names[@]}"; do sources+=("loadables/$name.c"); done
  case ${names[0]} in
    pcre) libs+=(-lpcre2-8) ;;
    zlib) libs+=(-lz -llzma -lzstd -lbz2) ;;
    more) sources+=("$BT"/builtins/_bl_key_*.c "$BT"/builtins/_bl_screen_*.c "$BT"/builtins/_bl_proc_*.c); names+=(whiptail) ;;
    toml) sources+=("$BT"/builtins/_tomlc17_*.c) ;;
    vt) sources+=("$BT"/builtins/_libgrapheme_*.c) ;;
    sqlite) sources+=("$BT"/builtins/_sqlite_*.c); libs+=(-ldl -lpthread) ;;
  esac
  lib="$d/${names[0]}.so"
  "$CC" "${flags[@]}" "${sources[@]}" "${libs[@]}" -o "$lib"
  for name in "${names[@]}"; do printf 'enable -f %q %q\n' "$lib" "$name" >> "$d/load.sh"; done
done
HELPER_LOAD_ENV="$d/load.sh" HELPER_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/helper-smoke.py "${1:-out/bash}"
