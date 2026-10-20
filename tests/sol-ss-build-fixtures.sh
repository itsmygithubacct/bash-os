#!/bin/bash
# SPDX-License-Identifier: MIT
# Must run through the build gate, after the targeted product build.
set -euo pipefail
cd "$(dirname "$0")/.."
dest=${1:?artifact directory required}
mkdir -p "$dest"
cc -O2 -Wall -Wextra -Werror -fPIC -shared tests/sol-ss-shim.c -ldl -o "$dest/ss-shim.so"
. config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -DHAVE_CONFIG_H \
  -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables" \
  -fsanitize=address,undefined loadables/ss.c loadables/netstat.c -o "$dest/ss-sanitize.so"
cc -print-file-name=libasan.so > "$dest/ss-asan-path"
cat > "$dest/ss-sanitize-env.sh" <<EOF_ENV
enable -f '$dest/ss-sanitize.so' bashss || exit
enable -f '$dest/ss-sanitize.so' bashnetstat || exit
ss() { bashss "\$@"; }
netstat() { bashnetstat "\$@"; }
EOF_ENV
