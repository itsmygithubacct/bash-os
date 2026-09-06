#!/usr/bin/env bash
# tests/sort-parity.sh [BINARY] — sort against GNU coreutils' on the same
# inputs and the same argument words: -n over random integers, floats,
# negatives and non-numbers (which GNU orders as zero, without machine
# arithmetic: 12345678901234567890 and ...891 differ, "1e5" is 1, "+5" and
# "abc" are 0); -rn, -u and -s ties; -k and -t keys, numeric and text, with
# a field's leading blanks and GNU's rule that a key with letters of its own
# takes no global option; stdin, -z, several files, -c; a 50,000-line numeric
# file. In the C locale and a UTF-8 one. Output and exit status must match;
# stderr is not compared (the disorder message carries the program's name).
# Skips without GNU sort.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=$(readlink -f "${1:-$HERE/out/bash}")
command -v sort >/dev/null && sort --version 2>/dev/null | grep -q coreutils || { echo "sort-parity: SKIP (no GNU sort)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; cd "$d"
n=0; fail=0
vis(){ if [[ -n "${ZT:-}" ]]; then tr '\0' '|'; else cat; fi; }   # -z output: NULs made visible for the shell
cmp_out(){ # cmp_out LABEL LOCALE ARGS... (stdin from $STDIN if set): stdout and exit status
  local label=$1 loc=$2; shift 2; n=$((n+1)); local a b
  if [[ -n "${STDIN:-}" ]]; then a=$( { LC_ALL=$loc sort "$@" 2>/dev/null < "$STDIN"; echo "rc=$?"; } | vis); b=$( { LC_ALL=$loc "$BX" -c 'PATH=; sort "$@"' _ "$@" 2>/dev/null < "$STDIN"; echo "rc=$?"; } | vis)
  else a=$( { LC_ALL=$loc sort "$@" 2>/dev/null; echo "rc=$?"; } | vis); b=$( { LC_ALL=$loc "$BX" -c 'PATH=; sort "$@"' _ "$@" 2>/dev/null; echo "rc=$?"; } | vis); fi
  [[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF sort [$loc] $label: $*"; diff <(echo "$a") <(echo "$b") | head -4 | sed 's/^/    /'; }
}
# --- inputs, from a fixed seed
python3 - <<'PYX'
import random
r = random.Random(20260906)
# 50,000 integers in +-10^9, some repeated, some with leading zeros or blanks
ints = [r.randint(-10**9, 10**9) for _ in range(49000)]
ints += r.sample(ints, 900)
lines = [str(v) for v in ints] + [f"{'-' if v < 0 else ''}000{abs(v)}" for v in r.sample(ints, 50)] + [f"  {v}" for v in r.sample(ints, 25)] + [f"\t{v}" for v in r.sample(ints, 25)]
r.shuffle(lines); open("ints", "w").write("\n".join(lines) + "\n")
# floats: varying precision, trailing zeros, a bare point, -0
fl = [f"{r.uniform(-1e6, 1e6):.{r.randint(0, 7)}f}" for _ in range(5000)]
fl += ["-0", "0", "0.0", "-0.0", ".5", "-.5", "5.", "-5.", "1.50", "1.5", "1.05", "0.500", "00.5", "-00.50", "5.0.1", "5.0"]
r.shuffle(fl); open("floats", "w").write("\n".join(fl) + "\n")
# the cases a strtod would get wrong
open("junk", "w").write("\n".join(["abc", "", "  12", "-", "+7", "1e5", "0x10", "inf", "nan", "1,000", "12abc", "3.4.5", "--5", "- 5", ".", "-.",
    "12 34", "-0", "0", "0.0", "00012", "12", "-0.5", ".5", "0.5", "5.", "5", "1.50", "1.5", "1.05", "-5", "-10", "-5.0", "-5.1",
    "12345678901234567890", "12345678901234567891", "-12345678901234567890", "-12345678901234567891", "\t9", "9\tx", "1.5x",
    "0.1e3", "-abc", "-.0", "1.", "1.0000001", "1.00000001", "99999999999999999999.5", "99999999999999999999.05",
    "  -3", "\v5", "\f5", "\r5", "５", "٣", "1.", "1", "01", "-01", "-1", "1e", "e1", "0.", "-0."]) + "\n")
# whitespace fields: word number word, leading blanks on some lines, short and empty lines
w = ["x", "y", "z", "w", "v", "X", "Y", "b", "B", "a-b", "a_b", "a b"]
fl2 = [f"{r.choice(w)} {r.randint(-50, 50)} {r.choice(w)}" for _ in range(300)]
fl2 += [f"  {r.choice(w)} {r.randint(-50, 50)} q" for _ in range(30)] + [f"\t{r.choice(w)}\t{r.randint(-50, 50)}" for _ in range(30)]
fl2 += ["w", "", "v -7", "x 3 p", "x 3 q", "  z 2 s", "y 10 r", "1 2 b", "1 10 a", "1 3 c"]
r.shuffle(fl2); open("fields", "w").write("\n".join(fl2) + "\n")
# colon fields: empty and missing fields, blanks inside a field
cl = [f"{r.choice(w)}:{r.randint(-50, 50)}:{r.choice(w)}" for _ in range(300)]
cl += ["b:3:x", "a:10:y", "c:2:z", "a:10:w", ":5:", "d", "e::", "f:-1:q", "a:  5:x", "a:5:y", "::", "a:", "a", ""]
r.shuffle(cl); open("colon", "w").write("\n".join(cl) + "\n")
open("nonl", "w").write("3\n1\n2")
open("znums", "wb").write(b"\0".join(s.encode() for s in ["b 2", "\n3", "a\n1", "10", "-4", "x"]) + b"\0")
open("sorted", "w").write("\n".join(str(v) for v in sorted(ints)) + "\n")
open("m1", "w").write("1\n3\n5\n"); open("m2", "w").write("2\n4\n6\n")
PYX
for loc in C C.UTF-8; do
  # numeric keys on the whole line
  for f in ints floats junk; do
    for args in "-n" "-rn" "-n -u" "-n -s" "-rn -s" "-n -u -s" "-n -r -u" "-nu" "-nr"; do cmp_out "$f" $loc $args "$f"; done
    for args in "" "-r" "-u" "-s" "-r -u" "-r -s"; do cmp_out "$f" $loc $args "$f"; done
  done
  # whitespace-separated fields: numeric and text keys, blanks, GNU's option inheritance
  for args in "-k2n" "-k2nr" "-k2,2n" "-k2n -u" "-k2n -s" "-k1,1 -k2n" "-k3 -k2n" "-k2n -k1,1" "-r -k2n" "-k2n -r" "-n -k2" "-n -k2r" \
              "-k2" "-k2,2" "-k1,1" "-k1,1b" "-k1b,1" "-b -k2" "-k2b" "-k2.2,2n" "-k2,2.0n" "-k3,2" "-k1.2,1" "-k2 -s" "-k2 -u" "-k3,3 -k1,1r" "-f -k1,1" "-k1,1f -k2n"; do
    cmp_out "fields" $loc $args fields
  done
  # -t fields
  for args in "-t: -k2n" "-t: -k2nr" "-t: -k2,2n" "-t: -k2n -u" "-t: -k2n -s" "-t: -k2 -k3" "-t: -k3 -k2n" "-t: -k2,2" "-t: -k1,1 -k2n" "-t: -k2nr -k1" \
              "-t: -k2" "-t: -k3,2" "-t: -k2.2,2n" "-t: -k2,2.1" "-t: -r -k2n" "-t: -n -k2" "-t: -n -k2r" "-t: -k2,2b" "-t: -k2b,2" "-t : -k 2 -n"; do
    cmp_out "colon" $loc $args colon
  done
  # stdin, no final newline, several files, -z, -o, -m, -c
  STDIN=ints cmp_out "stdin" $loc -n; STDIN=nonl cmp_out "stdin no newline" $loc -n; STDIN=
  cmp_out "no newline" $loc -n nonl
  cmp_out "three files" $loc -n ints floats junk
  cmp_out "three files -u" $loc -n -u junk floats junk
  ZT=1; cmp_out "-z" $loc -z -n znums; cmp_out "-z text" $loc -z znums; cmp_out "-z -u" $loc -z -n -u znums; ZT=
  cmp_out "-m" $loc -m -n m1 m2; cmp_out "-m text" $loc -m m1 m2
  cmp_out "-c sorted" $loc -c -n sorted; cmp_out "-c unsorted" $loc -c -n ints; cmp_out "-c -u" $loc -c -u -n sorted; cmp_out "-c -k" $loc -c -k1,1n fields; cmp_out "-C" $loc -C -n ints
  n=$((n+1)); a=$(LC_ALL=$loc sort -n -o out.gnu ints; cat out.gnu); b=$(LC_ALL=$loc "$BX" -c 'PATH=; sort -n -o out.bos ints; cat out.bos'); [[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF sort [$loc] -o FILE"; }
done
echo "sort-parity: $((n-fail))/$n identical to GNU coreutils"; exit $(( fail>0 ? 1 : 0 ))
