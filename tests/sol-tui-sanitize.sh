#!/usr/bin/env bash
# Invoke through the campaign build gate; instruments genuine production sources.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
evidence=${BASHOS_TASK_DIR:?}
binary=$(realpath "${1:-out/bash-sol-tui}")
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
dir="$evidence/tui-sanitize"
mkdir -p "$dir/builtins" "$dir/examples/loadables"
python3 config/stage-helpers.py --stage "$ROOT" "$dir" tui
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$dir/builtins" -I"$BT" -I"$BT/include" \
  -I"$BT/builtins" -I"$BT/examples/loadables" -Iloadables/common \
  loadables/tui.c "$dir/builtins/_bl_screen_screen.c" "$dir/builtins/_bl_key_bl_key.c" \
  -o "$dir/tui.so"
printf 'enable -f %q tui || exit 91\n' "$dir/tui.so" > "$dir/load.sh"
cat > "$dir/bash-tui" <<EOF
#!/bin/bash
export LD_PRELOAD=$(cc -print-file-name=libasan.so)
export BASH_ENV=$dir/load.sh
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
exec $binary "\$@"
EOF
chmod +x "$dir/bash-tui"
# A compiled-in builtin cannot be deleted; require the dynamic replacement.
"$dir/bash-tui" -c 'enable -d tui'
python3 tests/sol-tui-check.py "$dir/bash-tui"
