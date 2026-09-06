#!/usr/bin/env bash
# tests/wc-tail-parity.sh [BINARY] — wc and tail against GNU coreutils on the
# same inputs, including the cases a block-reading wc and a seeking tail can
# get wrong: a multibyte space cut at the 64 KB block edge on either side, the
# C locale, and a stream that is not at its start. Skips without GNU tools.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=$(readlink -f "${1:-$HERE/out/bash}")
for t in wc tail; do command -v $t >/dev/null && $t --version 2>/dev/null | grep -q coreutils || { echo "wc-tail-parity: SKIP (no GNU $t)"; exit 0; }; done
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; cd "$d"
n=0; fail=0
cmp_out(){ # cmp_out LABEL LOCALE ARGS... (stdin from $STDIN if set)
  local label=$1 loc=$2; shift 2; n=$((n+1)); local a b
  if [[ -n "${STDIN:-}" ]]; then a=$(LC_ALL=$loc "$TOOL" "$@" < "$STDIN" 2>&1); b=$(LC_ALL=$loc "$BX" -c 'PATH=; '"$TOOL"' "$@"' _ "$@" < "$STDIN" 2>&1)
  else a=$(LC_ALL=$loc "$TOOL" "$@" 2>&1); b=$(LC_ALL=$loc "$BX" -c 'PATH=; '"$TOOL"' "$@"' _ "$@" 2>&1); fi
  [[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF $TOOL [$loc] $label: $*"; diff <(echo "$a") <(echo "$b") | head -4 | sed 's/^/    /'; }
}
# --- inputs
printf 'one two  three\n\tfour\n' > ascii
: > empty
printf 'no newline at end' > nonl
printf 'a\xc2\xa0b c\xe2\x80\x83d e\xe3\x80\x80f\xe2\x80\xa8g\n' > uspace          # NBSP, EM SPACE, IDEOGRAPHIC, LINE SEP
python3 - <<'PYX'
import os
# a NBSP whose lead byte sits just before the carry region (block edge 65534) …
open("edge_before","wb").write(b"a"*65533 + b"\xc2\xa0" + b" b\n")
# … and a 3-byte space starting at the last scanned byte, and one fully inside the carry
open("edge3","wb").write(b"a"*65533 + b"\xe2\x80\x83" + b" b\n")
open("edge_in_carry","wb").write(b"a"*65534 + b"\xc2\xa0" + b" b\n")
open("edge_exact","wb").write(b"a"*65535 + b"\xc2\xa0" + b" b\n")
open("random","wb").write(os.urandom(300*1024))
open("big","w").write("".join(f"line {i} some words here\n" for i in range(20000)))
PYX
# --- wc
TOOL=wc; STDIN=
for loc in C.UTF-8 C; do
  for f in ascii empty nonl uspace edge_before edge3 edge_in_carry edge_exact random big; do
    for args in "" "-l" "-w" "-c" "-lwc" "-m" "-L" "-lwcmL"; do cmp_out "$f" $loc $args "$f"; done
  done
  cmp_out "multi+total" $loc ascii uspace big edge_before
  STDIN=uspace cmp_out "stdin" $loc; STDIN=
done
# --- tail
TOOL=tail
for f in ascii empty nonl big; do for k in 1 2 5 100000; do cmp_out "$f" C -n $k "$f"; cmp_out "$f" C -n +$k "$f"; done; cmp_out "$f -c" C -c 10 "$f"; done
cmp_out "two files" C -n 2 ascii big
STDIN=big cmp_out "stdin file" C -n 3; STDIN=
n=$((n+1)); a=$( { read -r x; tail -n 100000; } < ascii ); b=$("$BX" -c 'PATH=; { read -r x; tail -n 100000; }' < ascii)
[[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF tail after a partial read of stdin"; diff <(echo "$a") <(echo "$b") | head -4 | sed 's/^/    /'; }
n=$((n+1)); a=$(cat big | tail -n 3); b=$("$BX" -c 'PATH=; cat big | tail -n 3'); [[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF tail on a pipe"; }
echo "wc-tail-parity: $((n-fail))/$n identical to GNU coreutils"; exit $(( fail>0 ? 1 : 0 ))
