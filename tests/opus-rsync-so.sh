#!/usr/bin/env bash
# Build loadables/rsync.c (with its _md4 helper) as a loadable object for
# `enable -f`, optionally under ASan/UBSan. Compiles, so run it through the
# campaign build gate. Usage: tests/opus-rsync-so.sh OUT.so [asan]
# RSYNC_SRC=FILE builds another copy of the source (e.g. a baseline).
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
out=$(realpath -m "$1"); mode=${2:-plain}
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" rsync
flags=(-O2 -g -fPIC -Wall -Wno-unused-function -DHAVE_CONFIG_H
       -I"$BT" -I"$BT/include" -I"$d/helpers/builtins" -Iloadables/common
       -I"$BT/builtins" -I"$BT/examples/loadables")
[[ $mode == asan ]] && flags+=(-O1 -fno-omit-frame-pointer -fsanitize=address,undefined)
"$CC" "${flags[@]}" -shared -Wl,-Bsymbolic "$d/helpers/builtins/"*.c "${RSYNC_SRC:-loadables/rsync.c}" -lz -o "$out"
echo "built $out ($mode)"
