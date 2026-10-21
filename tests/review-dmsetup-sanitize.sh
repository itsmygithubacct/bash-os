#!/usr/bin/env bash
# Private ioctl fixture; compile through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
bin=$(realpath "${1:-out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
bt="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined -DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables" loadables/dmsetup.c -o "$d/dmsetup.so"
cc -std=gnu11 -O2 -U_FORTIFY_SOURCE -Wall -Wextra -fPIC -shared tests/opus-dmsetup-fixture.c -ldl -o "$d/fixture.so"
printf 'enable -f %q dmsetup || exit
' "$d/dmsetup.so" > "$d/load.sh"
# The fixture supplies LD_PRELOAD; put libasan first in the executed shell.
printf '#!/bin/bash
export BASH_ENV=%q
export LD_PRELOAD=%q:"${LD_PRELOAD:-}"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1
exec %q "$@"
' "$d/load.sh" "$(cc -print-file-name=libasan.so)" "$bin" > "$d/bash-dmsetup"
chmod +x "$d/bash-dmsetup"
DMSETUP_FIXTURE_SO="$d/fixture.so" python3 tests/opus-dmsetup-ioctl.py "$d/bash-dmsetup"
