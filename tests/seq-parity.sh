#!/usr/bin/env bash
# tests/seq-parity.sh [BINARY] — this repo's seq against GNU coreutils' seq,
# the same argv words to both: integers up and down, big counts, floats with
# one to six decimals, exponent forms, -w, -s, -f, the one- and two-operand
# forms, a pipe closed early, a full disk, and the error cases. Stdout must
# be byte-identical and the exit status equal; stderr text is not compared,
# but a failing builtin must have said something. Skips without a GNU seq.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=$(readlink -f "${1:-$HERE/out/bash}")
G=$(command -v seq); [[ -n "$G" ]] && "$G" --version 2>/dev/null | grep -q coreutils || { echo "seq-parity: SKIP (no GNU seq)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
n=0; fail=0
t(){ # t ARGS...
  n=$((n+1)); local ra rb
  "$G" "$@" > "$d/a" 2>/dev/null; ra=$?
  "$BX" -c 'PATH=; seq "$@"' _ "$@" > "$d/b" 2> "$d/berr"; rb=$?
  if [[ $ra != "$rb" ]] || ! cmp -s "$d/a" "$d/b"; then
    fail=$((fail+1)); echo "  DIFF seq $* : exit $ra vs $rb"
    diff <(head -c 300 "$d/a") <(head -c 300 "$d/b") | head -4 | sed 's/^/    /'
  elif [[ $ra != 0 && ! -s "$d/berr" ]]; then
    fail=$((fail+1)); echo "  DIFF seq $* : exit $ra with nothing on stderr"
  fi
}
# --- integers: one and two operands, up, down, leading zeros, signs, big counts
for a in 1 5 10 0 -0 007 00 000 1e3 0x10; do t "$a"; done
t 1 1; t 3 7; t 0 0; t 007 9; t 00 2; t 0 007; t 5 1; t 2 4; t -- -3 -1; t -1 1; t -5 5; t 1e2 1e2; t 1.5e1 2e1; t 0X3P0 5; t 0x1p1 0x1p2
t 1 2 9; t 1 3 10; t 2 2 10; t 007 1 9; t 007 2 9; t 1 2 007; t 0007 01 9; t 1 01 3; t 1 +1 3; t 1 1. 3; t 1 3 2
t 5 -1 1; t 10 -3 1; t 0 -1 -5; t -5 2 5; t -1 -1 -3; t 3 -1 5; t 1 -1 5; t -0 0; t -0 1 0; t 0 1 -0; t -00 5; t 3e0 -1 1
t 100000; t 1000000; t 1 2 1000000; t 1000000 -1 1; t 99999 100001; t 4294967290 4294967300
t 4611686018427387900 4611686018427387910; t 4611686018427387900 3 4611686018427387910; t -- -4611686018427387910 -4611686018427387900
t 9223372036854775807 9223372036854775809; t 18446744073709551615 18446744073709551617; t 18446744073709551615 1 18446744073709551617
t 18446744073709551615 2 18446744073709551620; t 99999999999999999999 100000000000000000001; t 99999999999999999999 01 100000000000000000001
t +99999999999999999999 100000000000000000001; t 1e19 1e19; t 1e400 1e400
# --- floats: one to six decimals, either direction, the value past LAST that rounds to it
t 0.5 3; t .5 3; t 1 .5 3; t 0 0.1 1; t 0 0.1 0.3; t 1 0.25 2; t 0.001 0.001 0.01; t 1 1e-6 1.00001; t 0.123456 0.000001 0.12346
t 1.5 -0.5 -1; t 0.3 -0.1 0; t 1.0 3; t 1 1.0 3; t 2. 4; t 2.e0 4; t .5 .5 2; t -0.5 0.5 1; t 1 .3 2.2; t 1.10 .3 2; t 1 .30 2
t 5 1.0; t 3 -1.0 1; t 1 .1 1.25; t 0.1 0.1 0.30000000000000001; t 1 0.7 3; t 0 0.6 1; t 0.1 0.1 0.5; t -1 -.5 -3; t 2.5 1
t 1 1e-3 1.002; t 1.5e-3 1e-3 4e-3; t 1e-2 1e-2 3e-2; t 0.5 0x1p-1 2; t 0x1.8p1 5; t 1e-5000 1
for k in 1 2 3 4 5 6; do z=$(printf '%*s' $((k-1)) '' | tr ' ' 0); t 0 0.${z}1 0.${z}5; t 1.${z}1 0.${z}1 1.${z}9; t 0 0.${z}5 1; t -w 0.${z}9 0.${z}1 1.${z}1; done
# --- -w
t -w 1 10; t -w 8 12; t -w -5 5; t -w 1 -1 -10; t -w 0.5 1.5; t -w 1 .5 3; t -w -0.5 0.5 1; t -w 000 3; t -w 0010 12; t -w 007 9
t -w 1e3; t -w 1.0e1 2e1; t -w 1e-2 2e-2; t -w 10 1e2; t -w 1 0.001 1.01; t -w 99 101; t -w -1 1; t -w 0x10 0x12; t -w 0x1p1 4
t -w 15e-1 2; t -w +1 10; t -w ' 1' 10; t -w 1 ' 10'; t -w 1 +10; t -w -.5 1; t -w 1 -.5 -1; t -w 12.5e-1 2; t -w 1.25e1 13; t -w 1.25e-1 .2
t -w 0.5e0 1; t -w 5e-1 1; t -w 00.50e0 1; t -w 1.0e0 2; t -w 100e-2 2; t -w 1e0 2; t -w 1 1.0e0 2; t -w 0.1 1e-2 0.13; t -w 1e-2 1e-2 3e-2
t -w -1e-2 1e-2 1e-2; t -w -.5e1 1 -3; t -w 1 5e-1 2; t -w 3e0 -1 1; t -w 10 -1e0 8; t -w 1.e1 12; t -w 1.e-1 .2; t -w .1e1 3; t -w 1 2.5; t -w 1.5 1 2
t -w 1 100000; t -w 9223372036854775807 9223372036854775809; t -w 99999999999999999998 100000000000000000001; t -w -0 0; t --equal-width 8 10
for width in 63 64 120 65540; do
  zeros=$(printf '%*s' "$width" '' | tr ' ' 0)
  t -w "${zeros}1" 2
  t -w "-${zeros}1" 1
done
# --- -s
t -s, 1 5; t -s , 1 5; t -s '' 1 3; t -s ab 1 3; t -s ' ' 1 3; t -s, -w 8 12; t -ws, 8 10; t -sw 1 3; t -s, 1; t -s, 0.5 2; t -s : 3 -1 1; t -s , 5 1
t -s, 1 100000; t -s ab 99999999999999999999 100000000000000000001; t -s, 99999999999999999999 100000000000000000001; t --separator=, 1 3; t --sep=, 1 3
# --- -f
t -f %g 1 3; t -f%g 1 2; t -f %.2f 1 3; t -f %5.1f 1 3; t -f '%-5g|' 1 2; t -f %e 1 3; t -f %E 1000 1000; t -f %.3e 1 3; t -f %a 1 2; t -f %A 1 2
t -f '%.2f%%' 1 2; t -f a%gb 1 2; t -f '%%%g' 1 2; t -f %10g 1 2; t -f '%#g' 1 1; t -f %+g 1 1; t -f '% g' 1 1; t -f %Lg 1 2; t -f %G 0.00001 0.00001 0.00002
t -f %f 0 0.1 0.3; t -f %.1f 0 0.1 0.3; t -f '%.1f%%' 0 0.1 0.3; t -f %.0f 0 0.6 1; t -f %.0f 0 0.6 1.2; t -f %.0f 0 0.4 1; t -f '[%.0f]' 0 0.6 1
t -f 'n=%g;' 1 3; t -f "%'g" 1000 1000; t -f %g 1 200000; t --format=%g 1 2; t --format %g 1 2; t -f %.3f 1 -0.25 0
# --- the error cases: a bad number, a zero step, a bad format, bad options, operand count
t; t 1 2 3 4; t 1 0 5; t 1 0.0 5; t 1 -0 5; t x; t 1x; t 1 2 x; t '1 '; t nan; t 1 -nan; t -- -nan 1; t - 3; t 1e5000; t 1 1e5000; t -inf 1
t -f %d 1; t -f x 1; t -f % 1; t -f '%g %g' 1; t -f %lf 1 2; t -f; t -s; t -f %g; t -w -f %g 1 3; t 1 -s, 5; t 1 -f %g 3; t 0.5 -w 1; t -q 1; t --bogus 1; t --equal-width=1 3
# --- a pipe closed early, and a write error
n=$((n+1)); a=$("$G" 1000000 | head -1); b=$("$BX" -c 'PATH=; seq 1000000 | head -1'); [[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF seq 1000000 | head -1"; }
if [[ -w /dev/full ]]; then
  n=$((n+1)); "$G" 3 > /dev/full 2>/dev/null; ra=$?; "$BX" -c 'PATH=; seq 3 > /dev/full' 2> "$d/berr"; rb=$?
  [[ $ra == "$rb" && -s "$d/berr" ]] || { fail=$((fail+1)); echo "  DIFF seq 3 > /dev/full : exit $ra vs $rb"; }
fi
# --- 120 seeded random triples with 0..6 decimals, some negative, some -w or -s, some two-operand
RANDOM=20260906
rnd(){ local d=$1 s=""; (( RANDOM % 4 == 0 )) && s="-"; if (( d > 0 )); then printf '%s%d.%0*d\n' "$s" $((RANDOM % 20)) "$d" $((RANDOM % (10**d))); else printf '%s%d\n' "$s" $((RANDOM % 20)); fi; }
for ((i = 0; i < 120; i++)); do
  f=$(rnd $((RANDOM % 7))); st=$(rnd $((RANDOM % 4))); la=$(rnd $((RANDOM % 7)))
  [[ $st =~ ^-?0*(\.0*)?$ ]] && st=0.5
  case $((RANDOM % 4)) in 0) t "$f" "$st" "$la" ;; 1) t -w "$f" "$st" "$la" ;; 2) t -s , "$f" "$st" "$la" ;; 3) t "$f" "$la" ;; esac
done
echo "seq-parity: $((n-fail))/$n identical to $("$G" --version | head -1)"; exit $(( fail>0 ? 1 : 0 ))
