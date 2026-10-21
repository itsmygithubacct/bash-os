#!/usr/bin/env bash
# Build the clip probe modules. Run through the build gate; no tests here.
#   tests/sol-clip-build-probe.sh OUTPUT [CLIP_SOURCE [BUF_SOURCE]]
# probe.so    genuine buf.c + clip.c with counters and allocation faults
# sanitize.so the same, built with ASan/UBSan
# plain.so    unmodified buf.c + clip.c, ASan/UBSan, for the functional suite
set -euo pipefail
cd "$(dirname "$0")/.."
destination=$1
clip_source=${2:-$PWD/loadables/clip.c}
buf_source=${3:-$PWD/loadables/buf.c}
mkdir -p "$destination"
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
flags=(-g -Wall -Wextra -Wno-unused-parameter -fPIC -shared -Wl,-Bsymbolic -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" -Iloadables/common)
defs=("-DBUF_SOURCE=\"$buf_source\"" "-DCLIP_SOURCE=\"$clip_source\"")
cc -O2 "${flags[@]}" "${defs[@]}" tests/sol-clip-probe.c -o "$destination/probe.so"
cc -O1 -fsanitize=address,undefined "${flags[@]}" "${defs[@]}" tests/sol-clip-probe.c -o "$destination/sanitize.so"
cc -O1 -fsanitize=address,undefined "${flags[@]}" "$buf_source" "$clip_source" -o "$destination/plain.so"
cc -print-file-name=libasan.so > "$destination/asan-runtime.txt"
for variant in probe sanitize; do
  for name in buf clip clipprobe; do
    printf 'enable -f %q %q || exit\n' "$destination/$variant.so" "$name"
  done > "$destination/$variant.sh"
done
for name in buf clip; do
  printf 'enable -f %q %q || exit\n' "$destination/plain.so" "$name"
done > "$destination/plain.sh"
