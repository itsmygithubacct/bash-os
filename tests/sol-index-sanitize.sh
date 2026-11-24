#!/usr/bin/env bash
# Instrument index, git, obj and their staged helpers, then run the index
# suites. Leak detection stays off. This is not a leak-clean claim.
#
# formats, regressions and sol-index-check.py keep BASH_ENV, so they load
# one shared object and preload libasan. sol-index-check.py also preloads
# the fault shim after libasan; that is the order its harness already uses.
# parity, index-cache, git-integrity and git-parity replace or forward the
# environment, so a module cannot be the code that runs. Those use the
# 28-builtin indexcheck binary built with the review's sanitizer flags and
# tests/sol-index-map-recorder.c linked in: each of its processes records
# its own maps at start-up, so every process that ran is checked, however
# short-lived, with no outside /proc watcher to race.
# sol-index-bench-check.py never starts index.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
[[ -d $BT ]] || { echo 'sol-index-sanitize: build tree missing; run ./build.sh first'; exit 1; }
target=$(realpath "${1:-out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables" "$d/objects" "$d/maps"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" index git obj >/dev/null
flags=(-O1 -g -fPIC -fno-omit-frame-pointer -fsanitize=address,undefined
       -fno-sanitize-recover=all -DHAVE_CONFIG_H
       -I"$d/helpers/builtins" -I"$BT" -I"$BT/include" -I"$BT/builtins"
       -I"$BT/examples/loadables" -Iloadables/common)
i=0
for source in "$d/helpers/builtins/"*.c loadables/index.c loadables/git.c loadables/obj.c; do
  obj=$(printf '%03d-%s.o' "$i" "$(basename "${source%.c}")")
  "$CC" "${flags[@]}" -c "$source" -o "$d/objects/$obj"
  i=$((i+1))
done
"$CC" -shared -Wl,-Bsymbolic -fsanitize=address,undefined -fno-sanitize-recover=all \
  "$d/objects/"*.o -lz -lm -o "$d/index.so"
asan=$("$CC" -print-file-name=libasan.so)
[[ -f $asan ]] || { echo "sol-index-sanitize: libasan missing ($asan)"; exit 1; }
printf '%s\n' "$asan" > "$d/asan-path"
# $BASH is the binary the suite executed. Another shell must not enable this ABI.
{
  printf '[[ $BASH == %q ]] || return 0\n' "$target"
  printf 'enable -f %q index || exit 1\n' "$d/index.so"
  printf 'enable -f %q git || exit 1\n' "$d/index.so"
  printf 'enable -f %q obj || exit 1\n' "$d/index.so"
  # sol-index-check.py drops every SOL_INDEX_* variable, so the directory is
  # written into this script. The dump is the process that just enabled index.
  printf 'cat /proc/self/maps > %q/$$.maps || true\n' "$d/maps"
} > "$d/load.sh"
"$CC" -O2 -Wall -Wextra -Werror -fPIC -shared tests/sol-index-faults.c -ldl -o "$d/faults.so"

"$CC" -O2 -Wall -Wextra -Werror -fno-pie -c tests/sol-index-map-recorder.c -o "$d/map-recorder.o"
if [[ -n ${SOL_INDEX_ASAN_BASH:-} ]]; then
  asan_bash=$(realpath "$SOL_INDEX_ASAN_BASH")
else
  env CFLAGS="-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -fno-pie" \
    LDFLAGS_EXTRA="-fsanitize=address,undefined -no-pie $d/map-recorder.o" \
    ./build.sh --include git,obj,index,pack,cat,chmod,cp,ln,mkdir,mv,rm,rmdir,sed,sleep,wc,head,cut,sort,tr,ls,grep,cksum,tail,seq,od,cmp,touch,env \
    --name indexcheck-asan --no-strip
  asan_bash=$(realpath out/bash-indexcheck-asan)
fi
[[ -x $asan_bash ]] || { echo "sol-index-sanitize: indexcheck binary missing"; exit 1; }
echo "asan-binary $asan_bash"
readelf -d "$asan_bash" | grep NEEDED
# An imported __asan_ symbol is the dynamic link. Do not pipe nm into
# grep -m1: that closes the pipe early, and pipefail then looks like a miss.
nm -D "$asan_bash" > "$d/nm-dynamic.txt"
grep -m1 '__asan_' "$d/nm-dynamic.txt" || { echo 'sol-index-sanitize: indexcheck binary is not linked with ASan'; exit 1; }
grep -q -a 'bash-os index sanitizer map recorder v1' "$asan_bash" \
  || { echo 'sol-index-sanitize: indexcheck binary lacks tests/sol-index-map-recorder.c'; exit 1; }
records="$asan_bash.maps"
[[ ! -e $records ]] || { echo "sol-index-sanitize: $records exists; is another run using this binary?"; exit 1; }
trap 'rm -rf "$d" "$records"' EXIT
echo "asan-options detect_leaks=0"

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1

reset_maps() { rm -f "$d/maps"/*.maps; }
require_so_maps() {
  local label=$1 found= f
  for f in "$d/maps"/*.maps; do
    [[ -e $f ]] || continue
    if grep -q libasan "$f" && grep -F -q "$d/index.so" "$f"; then
      found=$f
      break
    fi
  done
  [[ -n $found ]] || { echo "sol-index-sanitize: $label did not map libasan and $d/index.so" >&2; exit 1; }
  echo "asan-map $label"
  grep libasan "$found"
  grep -F "$d/index.so" "$found"
}

# Each process of $asan_bash wrote PID-N.cmdline and PID-N.maps into
# $records at start-up (tests/sol-index-map-recorder.c). Every recorded
# process must have mapped libasan, and at least one must have run.
start_watch() {
  rm -rf "$records"
  mkdir -m 700 "$records"
}
stop_watch() {
  local label=$1 want=$2 count=0 ran=0 cmd maps argv
  for cmd in "$records"/*.cmdline; do
    [[ -e $cmd ]] || continue
    maps=${cmd%.cmdline}.maps
    argv=$(tr '\0' ' ' <"$cmd")
    grep -q libasan "$maps" 2>/dev/null \
      || { echo "sol-index-sanitize: $label: process ${cmd##*/} ($argv) did not map libasan" >&2; exit 1; }
    count=$((count+1))
    [[ -z $want || $argv == *"$want"* ]] && ran=$((ran+1))
  done
  (( count > 0 )) || { echo "sol-index-sanitize: $label recorded no process of $asan_bash" >&2; exit 1; }
  (( ran > 0 )) || { echo "sol-index-sanitize: $label recorded no process running '$want'" >&2; exit 1; }
  echo "asan-map $label: $count of $count recorded processes mapped libasan${want:+ ($ran ran $want)}"
  grep -m1 libasan "$maps"
  rm -rf "$records"
}
run_watched() {
  local label=$1 want=$2
  shift 2
  start_watch
  set +e
  "$@"
  local rc=$?
  set -e
  stop_watch "$label" "$want"
  return "$rc"
}

reset_maps
env BASH_ENV="$d/load.sh" LD_PRELOAD="$asan" SOL_INDEX_MAP_DIR="$d/maps" \
  python3 tests/sol-index-formats.py --binary "$target"
require_so_maps formats

reset_maps
env BASH_ENV="$d/load.sh" LD_PRELOAD="$asan" SOL_INDEX_MAP_DIR="$d/maps" \
  python3 tests/sol-index-regressions.py --binary "$target" --case stages
require_so_maps regressions-stages
reset_maps
env BASH_ENV="$d/load.sh" LD_PRELOAD="$asan" SOL_INDEX_MAP_DIR="$d/maps" \
  python3 tests/sol-index-regressions.py --binary "$target" --case null-id
require_so_maps regressions-null-id
reset_maps
env BASH_ENV="$d/load.sh" LD_PRELOAD="$asan" SOL_INDEX_MAP_DIR="$d/maps" \
  python3 tests/sol-index-regressions.py --binary "$target" --case v3
require_so_maps regressions-v3
reset_maps
env BASH_ENV="$d/load.sh" LD_PRELOAD="$asan" SOL_INDEX_MAP_DIR="$d/maps" \
  python3 tests/sol-index-regressions.py --binary "$target" --case bounds
require_so_maps regressions-bounds

# The harness prepends libasan, then the fault shim. Do not also export
# LD_PRELOAD: this suite copies the parent environment into host git.
reset_maps
env SOL_INDEX_MAP_DIR="$d/maps" \
  python3 tests/sol-index-check.py --binary "$target" --shim "$d/faults.so" \
  --loader "$d/load.sh" --asan "$asan" --output "$d/index-check.json"
require_so_maps index-check
python3 - "$d/index-check.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
print(f"index-check passed={report['passed']} failed={report['failed']} sanitized={report['sanitized']}")
if report['failed']:
    raise SystemExit(1)
PY

for case in v1-over-refusal v2-mismatch v3-split-literal v3-untr; do
  run_watched "parity-$case" index \
    python3 tests/sol-index-parity.py --binary "$asan_bash" --case "$case"
done
run_watched index-cache '' python3 tests/index-cache.py "$asan_bash"
run_watched git-integrity '' python3 tests/git-integrity.py "$asan_bash"
run_watched git-parity '' python3 tests/git-parity.py "$asan_bash"
python3 tests/sol-index-bench-check.py
echo 'bench-check does not start index; no ASan map applies'
echo 'sol-index-sanitize: passed'
