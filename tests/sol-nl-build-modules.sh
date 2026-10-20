#!/usr/bin/env bash
# Compile only; run this script through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
# Serialize access to the staged Bash headers with build.sh in this worktree.
exec {module_lock}>build/.lock
flock "$module_lock"
d=${1:?artifact directory required}
mkdir -p "$d"
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
CC=${CC:-cc}
sha256sum loadables/nl.c loadables/common/nl-regex.h > "$d/source.sha256"
set -x
for mode in native fallback; do
  flags=()
  [[ $mode != fallback ]] || flags+=(-DBNL_NO_STARTEND=1)
  for kind in plain sanitized; do
    sanitize=()
    optimization=-O2
    if [[ $kind == sanitized ]]; then
      optimization=-O1
      sanitize+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
    fi
    "$CC" "$optimization" -g -fPIC -shared -Wl,-Bsymbolic "${sanitize[@]}" "${flags[@]}" \
      -DHAVE_CONFIG_H -Iloadables/common -I"$BT" -I"$BT/include" -I"$BT/builtins" \
      -I"$BT/examples/loadables" loadables/nl.c -o "$d/nl-$mode-$kind.so"
  done
done
# Optional original-source control: exercise its actual no-REG_STARTEND branch.
baseline=${BNL_BASELINE_SOURCE:-${BASHOS_TASK_DIR:-}/baseline/nl.c}
if [[ -f $baseline ]]; then
  printf '#include <regex.h>\n#undef REG_STARTEND\n' > "$d/no-startend.h"
  "$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -include "$d/no-startend.h" \
    -DHAVE_CONFIG_H -Iloadables/common -I"$BT" -I"$BT/include" -I"$BT/builtins" \
    -I"$BT/examples/loadables" "$baseline" -o "$d/nl-original-fallback.so"
fi
"$CC" --version > "$d/compiler.txt"
"$CC" -print-file-name=libasan.so > "$d/asan-path.txt"
