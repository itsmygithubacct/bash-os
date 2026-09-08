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
printf 'a\xe2\x80\x83b c\xe3\x80\x80d\n' > uspace  # EM SPACE, IDEOGRAPHIC
printf 'a\xc2\xa0b c\xe2\x80\x83d e\xe3\x80\x80f\xe2\x80\xa8g\n' > word-spaces
python3 - <<'PYX'
import random
# a NBSP whose lead byte sits just before the carry region (block edge 65534) …
open("edge_before","wb").write(b"a"*65533 + b"\xc2\xa0" + b" b\n")
# … and a 3-byte space starting at the last scanned byte, and one fully inside the carry
open("edge3","wb").write(b"a"*65533 + b"\xe2\x80\x83" + b" b\n")
open("edge_in_carry","wb").write(b"a"*65534 + b"\xc2\xa0" + b" b\n")
open("edge_exact","wb").write(b"a"*65535 + b"\xc2\xa0" + b" b\n")
# ASCII keeps host parity valid with coreutils before 9.5, which ignored
# encoding errors and some nonprinting characters when counting words.
r = random.Random(7)
open("random","wb").write(bytes(r.choice(b"abcXYZ012 \t\r\v\f\n") for _ in range(300*1024)))
# Three words per row, including invalid UTF-8 and an embedded NUL. The
# fixed expectations below exercise both counting paths across block edges.
open("word-binary","wb").write(b"\xff a\0b \x80\n" * 50000)
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
# Coreutils 9.5 corrected these word-count semantics. Use explicit fixtures
# so older host wc versions cannot serve as an incorrect reference:
# https://lists.gnu.org/archive/html/coreutils-announce/2024-03/msg00000.html
check_words(){ # LOCALE FILE LINES WORDS CHARS BYTES WIDTH
  local loc=$1 file=$2 lines=$3 words=$4 chars=$5 bytes=$6 width=$7 args expected a
  local -a values
  for args in -w -mw -lwcmL; do
    case $args in
      -w) expected="$words" ;;
      -mw) expected="$words $chars" ;;
      *) expected="$lines $words $chars $bytes $width" ;;
    esac
    n=$((n+1))
    if a=$(LC_ALL=$loc "$BX" -c 'PATH=; wc "$1"' _ "$args" < "$file"); then
      read -ra values <<< "$a"
      [[ ${values[*]} == "$expected" ]] && continue
    fi
    fail=$((fail+1)); echo "  DIFF wc [$loc] $file $args: expected [$expected], got [$a]"
  done
}
check_words C.UTF-8 word-spaces 1 7 14 21 13
check_words C word-spaces 1 4 21 21 9
check_words C.UTF-8 word-binary 50000 150000 300000 400000 4
check_words C word-binary 50000 150000 400000 400000 4
# --- tail
TOOL=tail
for f in ascii empty nonl big; do for k in 1 2 5 100000; do cmp_out "$f" C -n $k "$f"; cmp_out "$f" C -n +$k "$f"; done; cmp_out "$f -c" C -c 10 "$f"; done
cmp_out "two files" C -n 2 ascii big
STDIN=big cmp_out "stdin file" C -n 3; STDIN=
n=$((n+1)); a=$( { read -r x; tail -n 100000; } < ascii ); b=$("$BX" -c 'PATH=; { read -r x; tail -n 100000; }' < ascii)
[[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF tail after a partial read of stdin"; diff <(echo "$a") <(echo "$b") | head -4 | sed 's/^/    /'; }
n=$((n+1)); a=$(cat big | tail -n 3); b=$("$BX" -c 'PATH=; cat big | tail -n 3'); [[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF tail on a pipe"; }
echo "wc-tail-parity: $((n-fail))/$n GNU parity and corrected word-count checks passed"; exit $(( fail>0 ? 1 : 0 ))
