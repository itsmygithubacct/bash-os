#!/usr/bin/env bash
# Run bounded libFuzzer sessions against actual parser implementations.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${FUZZ_CC:-clang}
BT=${BASH_OS_BUILD_TREE:-build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")}
seconds=${FUZZ_SECONDS:-30}
[[ $seconds =~ ^[1-9][0-9]*$ ]] || { echo 'FUZZ_SECONDS must be a positive integer' >&2; exit 2; }
[[ -f "$BT/config.h" ]] || { echo 'Build Bash before running parser fuzzing' >&2; exit 1; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables" out/fuzz
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" ldap crypto >/dev/null
flags=(-O1 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
       -ffunction-sections -fdata-sections -Wl,--gc-sections)
"$CC" "${flags[@]}" -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" -I"$d/helpers/builtins" -Iloadables/common tests/fuzz-ldap.c -o out/fuzz/ldap
"$CC" "${flags[@]}" tests/fuzz-image.c -lm -o out/fuzz/image
"$CC" "${flags[@]}" tests/fuzz-toml.c loadables/_tomlc17/tomlc17.c -lm -o out/fuzz/toml
"$CC" "${flags[@]}" -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" -Iloadables/common tests/fuzz-pack.c \
  loadables/_sha1dc/sha1.c loadables/_sha1dc/ubc_check.c -lz -o out/fuzz/pack
"$CC" "${flags[@]}" -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" -Iloadables/common tests/fuzz-index.c \
  loadables/_sha1dc/sha1.c loadables/_sha1dc/ubc_check.c -o out/fuzz/index
python3 - <<'PY'
from pathlib import Path
import struct,zlib
seeds={'ldap':[b'\x01(cn=*)',b'\x01(&(uid=test)(!(cn=x)))',bytes.fromhex('300c02010161070a010004000400')],
       'toml':[b'[table]\nx = [1, 2, 3]\n',b'date = 1979-05-27T07:32:00Z\n',b'name = "example"\n'],
       'image':[],
       'pack':[],
       'index':[]}
def chunk(kind,data):
    return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data))
seeds['image'].append(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',1,1,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(b'\0\xff\0\0\xff'))+chunk(b'IEND',b''))
seeds['image'].append(seeds['image'][0][:33]+chunk(b'IDAT',b'')+seeds['image'][0][33:])
# A pack of one small object, an index for it, a delta and a pair to make
# one from: the first two bytes of each seed say which case it is.
import hashlib
body = b'blob 5\0hello'
packed = b'PACK'+struct.pack('>II',2,1)+bytes([0x33,0x05])+zlib.compress(b'hello')
packed += hashlib.sha1(packed).digest()
seeds['pack'].append(bytes([1,128])+packed)
seeds['pack'].append(bytes([0,64])+b'hello'+b'\x05\x05\x90\x05')
seeds['pack'].append(bytes([3,128])+b'a line of text, and another\n'*4)
seeds['pack'].append(bytes([2,128])+b'\xfftOc'+struct.pack('>I',2)+b'\0'*(256*4))
# An index of one entry, with the trailer it must carry.
entry = struct.pack('>10I',1,2,3,4,5,6,0o100644,7,8,5)+bytes.fromhex('b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0')
entry += struct.pack('>H',5)+b'hello'+b'\0'*(8-((62+5)%8))
index = b'DIRC'+struct.pack('>II',2,1)+entry
seeds['index'].append(index+hashlib.sha1(index).digest())
for name,entries in seeds.items():
    d=Path('out/fuzz')/(name+'-corpus'); d.mkdir(exist_ok=True)
    for n,data in enumerate(entries): (d/('seed-'+str(n))).write_bytes(data)
PY
for name in ldap image toml pack index; do
  ASAN_OPTIONS=detect_leaks=1:quarantine_size_mb=64 UBSAN_OPTIONS=halt_on_error=1 \
    "out/fuzz/$name" "out/fuzz/$name-corpus" -max_total_time="$seconds" \
    -timeout=3 -rss_limit_mb=512 -max_len=4096 -artifact_prefix="out/fuzz/$name-" \
    >"out/fuzz/$name.log" 2>&1 || { tail -50 "out/fuzz/$name.log"; exit 1; }
  tail -1 "out/fuzz/$name.log"
done
printf 'fuzz: LDAP BER/filters, image decoding, TOML, packfiles and the index passed bounded runs\n'
