#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Target SIGPIPE and SIGHUP dispositions under ASan and UBSan.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
source config/versions.sh
BT="build/bash-$BASH_SRC_VERSION"
[[ -d $BT ]] || { echo 'secreview-target-disposition-sanitize: build tree missing'; exit 1; }
target=$(realpath "${1:-out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
asan=$("$CC" -print-file-name=libasan.so)
flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -Iloadables/common
  -I"$BT/builtins" -I"$BT/examples/loadables")

"$CC" "${flags[@]}" loadables/pty.c -o "$d/pty.so"
SECREVIEW_LOADABLE="$d/pty.so" SECREVIEW_BUILTIN=pty SECREVIEW_ASAN_LIB="$asan" \
  python3 tests/secreview-shell-sigpipe.py "$target" pty-target

"$CC" "${flags[@]}" loadables/sv.c -o "$d/sv.so"
SECREVIEW_LOADABLE="$d/sv.so" SECREVIEW_BUILTIN=sv SECREVIEW_ASAN_LIB="$asan" \
  python3 tests/secreview-shell-sigpipe.py "$target" sv-target

mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" git >/dev/null
HB="$d/helpers/builtins"
"$CC" "${flags[@]}" -I"$HB" loadables/git.c "$HB"/_git_*.c -lz -lm -o "$d/git.so"
SECREVIEW_LOADABLE="$d/git.so" SECREVIEW_BUILTIN=git SECREVIEW_ASAN_LIB="$asan" \
  python3 tests/secreview-shell-sigpipe.py "$target" git-target
