#!/bin/bash
# Compile only the real loadable and its crypto helper for sanitizer validation.
# Invoke through the campaign build gate after a targeted cluster Bash build.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
destination=${1:?usage: sol-cluster-sanitizer-build.sh OUTPUT_DIRECTORY}
source_tree="$root/build/bash-5.3"
exec {header_lock}> "$root/build/.lock"
flock "$header_lock"
mkdir -p "$destination"
cc -shared -fPIC -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined \
  -Wl,-Bsymbolic -DHAVE_CONFIG_H -DSHELL \
  -I"$source_tree" -I"$source_tree/include" -I"$source_tree/lib" \
  -I"$source_tree/builtins" -I"$source_tree/examples/loadables" \
  -I"$root/loadables/common" \
  "$root/loadables/cluster.c" "$root/loadables/_monocypher/monocypher.c" \
  -o "$destination/cluster-sanitized.so"
cc -print-file-name=libasan.so > "$destination/asan-runtime.txt"
sha256sum "$root/loadables/cluster.c" "$destination/cluster-sanitized.so"
