#!/usr/bin/env bash
# Instrument the final wrappers and all of their vendored C dependencies.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
names=(crypto claude ldap integrity dns login passwd auth su doas cksum obj index pack
       ssh pkg ntp mail rsync wg acme uuidgen screen sshd tiv kitty sixel nano ts hl sudo)
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" "${names[@]}"
sources=("$d/helpers/builtins/"*.c)
for name in "${names[@]}"; do sources+=("loadables/$name.c"); done
flags=(-O1 -g -fPIC -fsanitize=address,undefined -DHAVE_CONFIG_H
       -I"$BT" -I"$BT/include" -I"$d/helpers/builtins" -Iloadables/common
       -I"$BT/builtins" -I"$BT/examples/loadables")
python3 - "$CC" "$d" "${flags[@]}" -- "${sources[@]}" <<'PY'
import concurrent.futures, os, subprocess, sys
from pathlib import Path
cc, directory, *args = sys.argv[1:]
split = args.index('--'); flags, sources = args[:split], args[split+1:]
objects = Path(directory)/'objects'; objects.mkdir()
def compile_source(source):
    obj = objects/(Path(source).stem+'.o')
    p = subprocess.run([cc, *flags, '-c', source, '-o', str(obj)],capture_output=True)
    return p.returncode, p.stdout+p.stderr
failed = False
with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,int(os.environ.get('JOBS','4')))) as pool:
    for rc, output in pool.map(compile_source,sources):
        if output: sys.stdout.buffer.write(output)
        failed |= bool(rc)
if failed: raise SystemExit(1)
PY
"$CC" -shared -Wl,-Bsymbolic -fsanitize=address,undefined "$d/objects/"*.o \
  -lm -lz -llzma -ldl -lpthread -o "$d/final.so"
# The SSH server may exec the host's /bin/bash. Load these objects only in
# the tested Bash ABI, while keeping the server and helpers instrumented.
target=$(realpath "${1:-out/bash}")
printf '[[ $BASH == %q ]] || return 0\nset -e\n' "$target" > "$d/load.sh"
for name in "${names[@]}"; do printf 'enable -f %q %q\n' "$d/final.so" "$name" >> "$d/load.sh"; done
FINAL_LOAD_ENV="$d/load.sh" FINAL_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/final-smoke.py "${1:-out/bash}"
