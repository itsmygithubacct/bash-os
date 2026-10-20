#!/usr/bin/env bash
# Run through the build gate. No tests or measurements here.
set -euo pipefail
cd "$(dirname "$0")/.."
destination=$1
source_file=${2:-$PWD/loadables/buf.c}
mkdir -p "$destination"
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
flags=(-g -fPIC -shared -Wl,-Bsymbolic -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" -Iloadables/common)
cc -O2 "${flags[@]}" "-DBUF_SOURCE=\"$source_file\"" tests/sol-buf-probe.c loadables/undo.c loadables/clip.c -o "$destination/probe.so"
cc -O1 -fsanitize=address,undefined "${flags[@]}" "-DBUF_SOURCE=\"$source_file\"" tests/sol-buf-probe.c loadables/undo.c loadables/clip.c -o "$destination/sanitize.so"
cc -print-file-name=libasan.so > "$destination/asan-runtime.txt"
for variant in probe sanitize; do
  for name in buf bufprobe undo clip; do
    printf 'enable -f %q %q || exit\n' "$destination/$variant.so" "$name"
  done > "$destination/$variant.sh"
done
cc -O2 -Wall -Wextra tests/sol-buf-rusage.c -o "$destination/rusage"
