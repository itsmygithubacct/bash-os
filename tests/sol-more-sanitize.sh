#!/usr/bin/env bash
# Compile only more and the actual shared key decoder. Invoke via build gate.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
evidence=${BASHOS_TASK_DIR:?set BASHOS_TASK_DIR to an evidence directory}
binary=$(realpath "${1:-out/bash-sol-more-after}")
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
mkdir -p "$evidence/sanitize/builtins" "$evidence/sanitize/examples/loadables"
python3 config/stage-helpers.py --stage "$ROOT" "$evidence/sanitize" more
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$evidence/sanitize/builtins" -I"$BT" -I"$BT/include" \
  -I"$BT/builtins" -I"$BT/examples/loadables" -Iloadables/common \
  loadables/more.c "$evidence/sanitize/builtins/_bl_key_bl_key.c" \
  -o "$evidence/sanitize/more.so"
printf 'enable -f %q more\n' "$evidence/sanitize/more.so" > "$evidence/sanitize/load.sh"
# Interactive shells ignore BASH_ENV, so the executable wrapper explicitly
# prepends the loader to -i shell startup through --rcfile.
cat > "$evidence/sanitize/bash-more" <<EOF
#!/bin/bash
export LD_PRELOAD=$(cc -print-file-name=libasan.so)
export BASH_ENV=$evidence/sanitize/load.sh
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
args=()
for arg; do [[ \$arg == --norc ]] || args+=("\$arg"); done
exec $binary --rcfile $evidence/sanitize/load.sh "\${args[@]}"
EOF
chmod +x "$evidence/sanitize/bash-more"
python3 tests/sol-more-check.py "$evidence/sanitize/bash-more"
