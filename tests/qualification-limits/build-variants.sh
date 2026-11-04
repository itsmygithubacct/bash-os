#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build-host only. No artifact produced here is executed by this script.
# Usage: build-variants.sh native|i686 CONFIGURED_BASH_TREE NEW_OUTPUT_DIRECTORY
set -euo pipefail
[[ ${BASHOS_QUALIFICATION_BUILD:-} == 1 ]] || { echo 'build-host authorization required' >&2; exit 125; }
[[ $# == 3 ]] || exit 2
mode=$1
headers=$(cd "$2" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)
src="$root/tests/qualification-limits"
[[ -f "$headers/config.h" && -f "$headers/examples/loadables/loadables.h" ]] || exit 125
[[ ! -e $3 ]] || { echo 'output directory must be new' >&2; exit 125; }
case "$mode" in native|i686) ;; *) exit 2 ;; esac
# Header provenance is checked as data, without running the configured shell.
python3 - "$headers" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1])
for name,pattern in [('patchlevel.h',r'^#define[ \t]+PATCHLEVEL[ \t]+20[ \t]*$'),
                     ('version.h',r'^#define[ \t]+DISTVERSION[ \t]+"5\.3"[ \t]*$')]:
    if not re.search(pattern,(p/name).read_text(),re.M):
        raise SystemExit('0.1.4 qualification requires configured Bash 5.3.20 headers')
PY
python3 "$src/prepare.py" "$3"
out=$(cd "$3" && pwd)
cc=${CC:-cc}
flags=(-D_GNU_SOURCE -DHAVE_CONFIG_H -O2 -Wall -Wextra -Wno-unused-parameter
       -ffunction-sections -fdata-sections "-ffile-prefix-map=$root=."
       "-ffile-prefix-map=$headers=bash-headers" "-ffile-prefix-map=$out=qualification-output"
       -I"$headers" -I"$headers/include" -I"$headers/builtins"
       -I"$headers/examples/loadables" -I"$root/loadables/common")
if [[ $mode == native ]]; then
  # The source build flattens these two vendored headers for builtin includes.
  cp "$root/loadables/_libgrapheme/grapheme.h" "$out/_libgrapheme_grapheme.h"
  cp "$root/loadables/_libgrapheme/utf8_norm_data.h" "$out/_libgrapheme_utf8_norm_data.h"
  flags+=(-I"$out")
  "$cc" "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic "$root/loadables/dmesg.c" -o "$out/dmesg-014.so"
  "$cc" "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic "$root/loadables/tput.c" \
      "$root/loadables/tinfo.c" -o "$out/tput-014.so"
  "$cc" "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic "$root/loadables/wgetch.c" -o "$out/wgetch-014.so"
  "$cc" "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic "$root/loadables/utf8.c" \
      "$root"/loadables/_libgrapheme/*.c -o "$out/utf8-014.so"
  "$cc" "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic "$root/loadables/bashpoll.c" -o "$out/bashpoll.so"
  "$cc" "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic \
      -Dbashpoll_builtin_unload=qualification_omitted_unload \
      "$root/loadables/bashpoll.c" -o "$out/bashpoll-omitted-hook.so"
  for variant in original extended; do
    "$cc" "${flags[@]}" "-DQUAL_WGETCH_SOURCE=\"$out/wgetch-$variant.c\"" \
        -Wl,--gc-sections "$src/wgetch-clock.c" -o "$out/wgetch-$variant"
  done
  "$cc" "${flags[@]}" "-DQUAL_WGETCH_SOURCE=\"$out/wgetch-original.c\"" \
      -DQUAL_RUNTIME_KEYS -Wl,--gc-sections "$src/wgetch-clock.c" -o "$out/wgetch-runtime"
  "$cc" "${flags[@]}" "-DQUAL_DMESG_SOURCE=\"$root/loadables/dmesg.c\"" \
      -Wl,--gc-sections "$src/dmesg-record-probe.c" -o "$out/dmesg-record-probe"
  for variant in real truncating; do
    defs=(); [[ $variant != truncating ]] || defs=(-DQUALIFY_TRUNCATE_NUL)
    "$cc" "${flags[@]}" "${defs[@]}" -I"$root/loadables/_libgrapheme" \
        "$src/grapheme-probe.c" "$root"/loadables/_libgrapheme/*.c \
        -Wl,--gc-sections -o "$out/grapheme-$variant"
  done
else
  # The AVX2 target functions remain in the object; real CPUID must gate them.
  # This is an i686 build, never an SSE2-disabled x86-64 artifact.
  flags+=(-m32 -march=i686 -mno-sse -mno-sse2 -mfpmath=387 -fno-tree-vectorize)
  # A native config.h silently supplies the wrong Bash structure/ABI sizes.
  python3 - "$headers/config.h" <<'PY'
from pathlib import Path
import re,sys
s = Path(sys.argv[1]).read_text()
for name in ('SIZEOF_LONG','SIZEOF_CHAR_P'):
    assert re.search(r'^#define '+name+r' 4$',s,re.M), 'requires the i686 Bash configuration'
PY
  "$cc" "${flags[@]}" -dM -E "$root/loadables/vec.c" > "$out/vec-macros.txt"
  python3 - "$out/vec-macros.txt" <<'PY'
from pathlib import Path
import sys
s = Path(sys.argv[1]).read_text()
assert '#define __i386__ 1' in s
assert '#define __SSE2__' not in s and '#define BVEC_HAVE_SSE2' not in s
PY
  "$cc" "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic "$root/loadables/vec.c" -lm -o "$out/vec-i686.so"
  "$cc" "${flags[@]}" "$src/cpu-probe.c" -o "$out/cpu-i686"
fi
"$cc" --version > "$out/compiler.txt"
"$cc" -dumpmachine > "$out/compiler-target.txt"
python3 - "$out" "$headers" "$mode" "$root" "$cc" "${flags[@]}" <<'PY'
import hashlib,json,sys
from pathlib import Path
out,headers = map(Path,sys.argv[1:3])
root = Path(sys.argv[4])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
inputs = {str(p.relative_to(root)):sha(p) for folder in
          ('tests/qualification-limits','loadables/common','loadables/_libgrapheme')
          for p in (root/folder).rglob('*') if p.is_file() and p.suffix in ('.c','.h','.py','.sh')}
header_hashes = {str(p.relative_to(headers)):sha(p) for p in headers.rglob('*.h') if p.is_file()}
files = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file()}
config = hashlib.sha256((headers/'config.h').read_bytes()).hexdigest()
(out/'build.json').write_text(json.dumps(dict(mode=sys.argv[3],config_h_sha256=config,
    required_bash='5.3.20',patchlevel_h_sha256=sha(headers/'patchlevel.h'),
    scope='separate qualification builds',behavior_executed=False,files_sha256=files,
    compiler=sys.argv[5],common_flags=sys.argv[6:],source_inputs_sha256=inputs,
    bash_headers_sha256=header_hashes),indent=2)+'\n')
PY
