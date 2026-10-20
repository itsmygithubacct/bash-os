#!/usr/bin/env bash
# Build only; invoke through the campaign build gate. Tests do not compile.
set -euo pipefail
cd "$(dirname "$0")/.."
dest=${1:?fixture output directory required}
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)
bt="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
cc -O2 -fPIC -shared tests/sol-sv-write-shim.c -o "$dest/write-shim.so"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -Iloadables/common \
  -I"$bt/builtins" -I"$bt/examples/loadables" loadables/sv.c -o "$dest/sv-asan.so"
printf 'enable -f %q sv\n' "$dest/sv-asan.so" > "$dest/asan-env.sh"
cc -print-file-name=libasan.so > "$dest/asan-library.txt"

# Optional original source snapshot, used only for the paired framing profile.
if [[ -n ${2:-} ]]; then
  for version in before after; do
    source_file="$PWD/loadables/sv.c"
    [[ $version != before ]] || source_file="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
    cc -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections \
      -DHAVE_CONFIG_H -DSV_SOURCE="\"$source_file\"" \
      -I"$bt" -I"$bt/include" -Iloadables/common -I"$bt/builtins" \
      -I"$bt/examples/loadables" tests/sol-sv-framing.c -o "$dest/framing-$version"
  done
fi
