#!/usr/bin/env bash
# Invoke only through the campaign build gate. No measurements here.
set -euo pipefail
out=${1:?output directory required}
mkdir -p "$out"
bt=build/bash-5.3
inc=(-DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables")
wrap=()
for call in open openat fopen getrandom ioctl read write fsync close fchmod renameat unlinkat flock fstat; do
  wrap+=("-Wl,--wrap=$call")
done
cc -O2 -g -Wall -Wextra "${inc[@]}" -U_FORTIFY_SOURCE loadables/rngseed.c tests/sol-rngseed-host.c "${wrap[@]}" -o "$out/rngseed-host"
cc -O1 -g -fno-omit-frame-pointer -fno-pie -no-pie -fsanitize=address,undefined -Wall -Wextra "${inc[@]}" -U_FORTIFY_SOURCE loadables/rngseed.c tests/sol-rngseed-host.c "${wrap[@]}" -o "$out/rngseed-host-sanitize"
cc -O1 -g -fno-pie -no-pie -fsanitize=address,undefined "${inc[@]}" loadables/rngseed.c tests/rngseed-host.c -o "$out/rngseed-legacy-sanitize"
sha256sum loadables/rngseed.c tests/rngseed-host.c tests/sol-rngseed-host.c tests/sol-rngseed-build.sh > "$out/build-inputs.sha256"
sha256sum "$out/rngseed-host" "$out/rngseed-host-sanitize" "$out/rngseed-legacy-sanitize" > "$out/build-binaries.sha256"
