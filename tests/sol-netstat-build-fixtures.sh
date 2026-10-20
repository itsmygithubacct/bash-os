#!/bin/bash
# SPDX-License-Identifier: MIT
# Run through the campaign build gate. This script never runs measurements.
set -euo pipefail
cd "$(dirname "$0")/.."
dest=${1:?artifact directory required}
mkdir -p "$dest"
cc -O2 -Wall -Wextra -Werror -fPIC -shared tests/sol-netstat-shim.c -ldl -o "$dest/shim.so"
. config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic -DHAVE_CONFIG_H
  -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables")
# Loading this pair into the same Bash executes the actual source with
# ASan/UBSan, including static transport and proc parsing helpers.
cc "${flags[@]}" -fsanitize=address,undefined loadables/ss.c loadables/netstat.c -o "$dest/sanitize.so"
cc -print-file-name=libasan.so > "$dest/asan-path"
cat > "$dest/sanitize-env.sh" <<EOF_ENV
enable -f '$dest/sanitize.so' bashnetstat || exit
netstat() { bashnetstat "\$@"; }
EOF_ENV
if [[ -f "$dest/netstat-before.c" ]]; then
  cc "${flags[@]}" loadables/ss.c "$dest/netstat-before.c" -o "$dest/before.so"
fi
