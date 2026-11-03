#!/bin/bash
# SPDX-License-Identifier: MIT
# Run as a nonroot user inside the Debian reference image.
set -euo pipefail
[[ $(id -u) != 0 ]]
[[ $BASH_VERSION == 5.3.20* ]]
[[ $(type -t ls) == file ]]
[[ -w /work ]]
cd "$(mktemp -d)"
printf 'test\n' > data
[[ $(printf abc | base64 -w0) == YWJj ]]
[[ $(printf abc | sha256sum | cut -d ' ' -f 1) == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ]]
gzip -c data > data.gz
gzip -dc data.gz | cmp -s - data
zstd -qc data > data.zst
zstd -qdc data.zst | cmp -s - data
tar -cf data.tar data
mkdir unpack
tar -xf data.tar -C unpack
cmp data unpack/data
[[ $(printf '{"z":[2,3],"a":1}' | jq -cS .) == '{"a":1,"z":[2,3]}' ]]
[[ $(printf '2^10\n' | bc) == 1024 ]]
[[ $(gawk 'BEGIN { print 6*7 }') == 42 ]]
[[ $(sqlite3 :memory: 'SELECT 6*7;') == 42 ]]
[[ $(perl -e 'print 6*7') == 42 ]]
[[ $(git hash-object data) == 9daeafb9864cf43055ae93beb0afd6c7d144bfa4 ]]
[[ $(man -w ls) == */ls.1* ]]
[[ $(man -w bash) == /opt/bash-reference/share/man/man1/bash.1* ]]
[[ $(man -w write) == /opt/util-linux-reference/share/man/man1/write.1* ]]
[[ $(tput -T xterm-256color colors) == 256 ]]
write --version | grep -q 'util-linux 2.41.5'
utmpdump --version | grep -q 'util-linux 2.41.5'
uv --version | grep -Eq '^uv 0\.12\.15( |$)'
python3 - <<'PY'
import json,sqlite3,tomllib,regex,numpy,pyte
from PIL import Image
import OpenGL.EGL
assert tomllib.loads('value = 42')['value']==42
assert regex.findall(r'\X','a\u0308b')==['a\u0308','b']
assert numpy.add([1,2],[3,4]).tolist()==[4,6]
assert sqlite3.connect(':memory:').execute('SELECT 42').fetchone()==(42,)
screen=pyte.Screen(10,2);stream=pyte.Stream(screen);stream.feed('hello')
assert screen.display[0]=='hello     '
Image.new('RGB',(2,2),(255,0,0)).save('image.png')
assert Image.open('image.png').getpixel((0,0))==(255,0,0)
PY
img2sixel image.png > image.sixel
[[ -s image.sixel ]]
printf '{"nonroot_userland_smoke":"PASS","uid":%s}\n' "$(id -u)"
