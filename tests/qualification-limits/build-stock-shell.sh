#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build-host only: separate GNU Bash shell without any injected builtins.
# Usage: build-stock-shell.sh native|i686 BASH_TARBALL PATCH_DIRECTORY NEW_OUTPUT_DIRECTORY
set -euo pipefail
[[ ${BASHOS_QUALIFICATION_BUILD:-} == 1 ]] || { echo 'build-host authorization required' >&2; exit 125; }
[[ $# == 4 ]] || exit 2
mode=$1
archive=$(realpath "$2")
patchdir=$(realpath "$3")
root=$(cd "$(dirname "$0")/../.." && pwd)
source "$root/config/versions.sh"
[[ $BASH_SRC_VERSION == 5.3 && $BASH_PATCHLEVEL == 20 && ${#BASH_PATCHES[@]} == 20 ]] || {
  echo '0.1.4 qualification requires the Bash 5.3.20 pin set' >&2; exit 125;
}
for ((i=0; i<20; i++)); do
  read -r name hash <<< "${BASH_PATCHES[i]}"
  printf -v expected 'bash53-%03d' "$((i+1))"
  [[ $name == "$expected" && $hash =~ ^[0-9a-f]{64}$ ]] || {
    echo 'requires ordered, hash-pinned bash53-001 through bash53-020' >&2; exit 125;
  }
done
[[ ! -e $4 ]] || { echo 'output directory must be new' >&2; exit 125; }
case "$mode" in native|i686) ;; *) exit 2 ;; esac
mkdir -p "$4"
out=$(cd "$4" && pwd)
printf '%s  %s\n' "$BASH_SRC_SHA256" "$archive" | sha256sum -c -
# Only the pinned archive is unpacked. All mutations stay under the new output.
tar -xzf "$archive" -C "$out"
cd "$out/bash-$BASH_SRC_VERSION"
for item in "${BASH_PATCHES[@]}"; do
  read -r name hash <<< "$item"
  printf '%s  %s\n' "$hash" "$patchdir/$name" | sha256sum -c -
  patch --batch --fuzz=0 -p0 < "$patchdir/$name"
done
python3 - patchlevel.h <<'PY'
from pathlib import Path
import re,sys
if not re.search(r'^#define[ \t]+PATCHLEVEL[ \t]+20[ \t]*$',Path(sys.argv[1]).read_text(),re.M):
    raise SystemExit('patched source is not Bash 5.3.20')
PY
cc=${CC:-cc}
flags="-O2 -fno-tree-vectorize -ffile-prefix-map=$out=qualification-build"
configure_args=(--disable-nls --without-bash-malloc --enable-dynamic-loading)
if [[ $mode == i686 ]]; then
  flags="$flags -m32 -march=i686 -mno-sse -mno-sse2 -mfpmath=387"
  configure_args+=(--host=i686-linux-gnu --build="$(cc -dumpmachine)")
fi
./configure "${configure_args[@]}" CC="$cc" CFLAGS="$flags"
printf '%s\n' "$BASH_BUILD_NUMBER" > .build
make -j"${JOBS:-2}"
cp bash "$out/bash-stock"
readelf -h "$out/bash-stock" > "$out/elf-header.txt"
sha256sum "$out/bash-stock" > "$out/bash-stock.sha256"
"$cc" --version > "$out/compiler.txt"
"$cc" -dumpmachine > "$out/compiler-target.txt"
printf '%s\n' "$flags" > "$out/cflags.txt"
python3 - "$out" "$archive" "$patchdir" "$root/config/versions.sh" "$mode" "$cc" "${configure_args[@]}" <<'PY'
import hashlib,json,sys
from pathlib import Path
out,archive,patchdir,versions = map(Path,sys.argv[1:5])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
patches = {f'bash53-{i:03d}':sha(patchdir/f'bash53-{i:03d}') for i in range(1,21)}
(out/'stock-build.json').write_text(json.dumps(dict(mode=sys.argv[5],compiler=sys.argv[6],
    required_bash='5.3.20',patchlevel_h_sha256=sha(out/'bash-5.3/patchlevel.h'),
    configure_args=sys.argv[7:],archive_sha256=sha(archive),versions_sha256=sha(versions),
    patch_inputs_sha256=patches,config_h_sha256=sha(out/'bash-5.3/config.h'),
    shell_sha256=sha(out/'bash-stock'),behavior_executed=False),indent=2)+'\n')
PY
# Deliberately no shell --version, module loading, or test invocation here.
