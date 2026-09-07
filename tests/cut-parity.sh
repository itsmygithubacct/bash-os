#!/usr/bin/env bash
# tests/cut-parity.sh [BINARY] — this repo's cut against GNU coreutils' cut on
# the same inputs: every option and range form, the range-list errors, lines
# without a delimiter, empty lines and an empty file, a missing final newline,
# NUL bytes, CRLF, -z, a delimiter on either side of the 64 KB block edge, a
# line longer than the block, several files, a missing file, stdin, options
# after the operands, long options and their prefixes. Output bytes and exit
# status must match; for an error, the message after the "cut: " prefix.
# Skips without a GNU cut on the host.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=$(readlink -f "${1:-$HERE/out/bash}")
G=$(command -v cut); [[ -n "$G" ]] && "$G" --version 2>/dev/null | grep -q coreutils || { echo "cut-parity: SKIP (no GNU cut)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; cd "$d"
export LC_ALL=C          # GNU quotes with '' here; in a UTF-8 locale it would use curly quotes
n=0; fail=0
# cmp_out LABEL ARGS... — stdout bytes and status must match, and the first
# stderr line after its program-name prefix. Stdin from $STDIN when set.
cmp_out(){
  local label=$1 ra rb ea eb; shift; n=$((n+1))
  "$G" "$@" < "${STDIN:-/dev/null}" > a.out 2> a.err; ra=$?
  "$BX" -c 'PATH=; cut "$@"' _ "$@" < "${STDIN:-/dev/null}" > b.out 2> b.err; rb=$?
  ea=$(sed -n '1{s/^.*cut: //;p}' a.err); eb=$(sed -n '1{s/^.*cut: //;p}' b.err)
  if [[ $ra != "$rb" ]] || ! cmp -s a.out b.out || [[ "$ea" != "$eb" ]]; then
    fail=$((fail+1)); echo "  DIFF $label: cut $*"
    [[ $ra != "$rb" ]] && echo "    status $ra vs $rb"
    cmp -s a.out b.out || cmp a.out b.out 2>&1 | head -1 | sed 's/^/    /'
    [[ "$ea" != "$eb" ]] && echo "    stderr: '$ea' vs '$eb'"
  fi
}
# --- inputs
printf 'a b c\n1 2 3\nx y\n' > sp                       # space-delimited
printf 'a\tb\tc\nd\te\n' > tab                          # TAB-delimited (the default)
printf 'a,b,,d\n,lead\ntrail,\n' > comma                # empty fields
printf 'one two  three\nnodelim\n\n x\ny \n' > mix      # a double space, no delimiter, empty, leading, trailing
: > empty
printf 'a b c' > nonl                                   # no final newline
printf 'a b\r\nc d\r\n' > crlf
printf 'a\0b c\0d\ne f\n' > nul                         # NUL inside a line
printf 'a b\0c d\0e f' > zlines                         # -z input, no final NUL
printf '\xce\xb1\xce\xb2 \xce\xb3\xce\xb4\n' > utf8     # -c is bytes in GNU cut
python3 - <<'PYX'
import random
r = random.Random(20260906)
open("random", "wb").write(bytes(r.randrange(256) for _ in range(200 * 1024)))
# a delimiter at the last byte of the first block, one just after it, then a
# line longer than a block, then a short line
open("edge", "wb").write(b"a" * 65535 + b" b " + b"c" * 70000 + b"\n" + b"x" * 70000 + b" y\n" + b"p q\n")
open("big", "w").write("".join(f"line {i} some words here\n" for i in range(20000)))
PYX
# --- bytes: every form of a list, complement, output delimiter
for f in sp mix empty nonl crlf nul utf8 random edge big; do
  for args in -b1 -b1-3 -b2- -b-2 -b1,3 -b1-2,3 -b3-,1 -b2-4,3-5 -c2 -c1-2 -b99 -nb1-2 \
              "-b1,3 --output-delimiter=:" "-b1-2,3 --output-delimiter=:" "-b2 --complement" \
              "-b2 --complement --output-delimiter=::" "-b1- --complement" "-b1,3 --output-delimiter=" \
              "-b65535-65537" "-b65536-" "-b1-65536,70000-"; do
    cmp_out "$f" $args "$f"
  done
done
# --- fields: a space delimiter, then the default TAB and a comma
for f in sp mix empty nonl crlf nul utf8 random edge big; do
  for args in -f1 -f2 -f2- -f-2 -f1,3 -f3 -f5 "-f1 -s" "-f2 -s" "-f5 -s" "-f1 --complement" \
              "-f2 --complement -s" "-f1- --complement" "-f1- --complement -s" "-f1,3 --output-delimiter=XY" \
              "-f1,2 --output-delimiter=" "-f1-2,3 --output-delimiter=:" "-f2-,1" -nf2; do
    cmp_out "$f" -d ' ' $args "$f"
  done
done
for args in -f1 -f2 -f2- "-f1,3 --output-delimiter=-" "-f2 -s"; do cmp_out tab $args tab; done
for args in -f1 -f3 -f2- -f-2 "-f3 -s" "-f1 --complement"; do cmp_out comma -d, $args comma; done
cmp_out "NUL delimiter" -d '' -f1 nul
cmp_out "NUL delimiter -s" -d '' -f2 -s nul
cmp_out "-d twice, last wins" -d, -d ' ' -f2 sp
# --- the delimiter is the line delimiter: the whole input is one record
printf 'a\nb\nc\n' > lines; printf 'a\nb\nc' > lines_nonl; printf '\n\n' > blank2; printf 'a\n' > one; printf 'a' > bare
for f in lines lines_nonl blank2 one bare empty; do
  for args in -f1 -f2 -f4 -f1- "-f1 -s" "-f2 -s" "-f2 --complement" "-f1- --complement" "-f1,3 --output-delimiter=:"; do
    cmp_out "$f, -d newline" -d $'\n' $args "$f"
  done
done
cmp_out "two files, -d newline" -d $'\n' -f2 lines lines_nonl
cmp_out "-z -d ''" -z -d '' -f2 zlines
cmp_out "-z -d '' -s" -z -d '' -f1- -s zlines
# --- -z
for args in "-b1" "-b2-" "-f2" "-f2 -s" "-f1 --complement"; do cmp_out zlines -z -d ' ' $args zlines; done
cmp_out zlines --zero-terminated -b1 zlines
for text in ',' 'a,' ',b,' 'a,b,' ',,'; do
  printf '%s' "$text" > zfinal
  for fields in 1 2 3 1,2 1,3 2,3; do
    cmp_out "unterminated -z record" -z -d, -f"$fields" zfinal
    cmp_out "unterminated -z record, -s" -z -d, -f"$fields" -s zfinal
  done
done
# --- several files, a missing one, a directory, stdin
cmp_out "three files" -d ' ' -f1 sp nonl mix
cmp_out "missing file" -d ' ' -f1 sp nope mix
cmp_out "a directory" -b1 sp . mix
STDIN=sp cmp_out "stdin" -d ' ' -f2
STDIN=sp cmp_out "stdin as -" -d ' ' -f2 -
STDIN=sp cmp_out "stdin twice" -b1 - -
STDIN=nonl cmp_out "stdin, no final newline" -b1-3
# --- options after operands, --, long options and prefixes
cmp_out "options after the file" sp -d ' ' -f2
cmp_out "-- ends options" -b1 -- sp
cmp_out "--bytes=" --bytes=1 sp
cmp_out "--characters" --characters 2 sp
cmp_out "--fields= --delimiter=" --fields=1 --delimiter=' ' sp
cmp_out "--only-delimited" --only-delimited -d ' ' -f1 mix
cmp_out "--complement" --complement -b2 sp
cmp_out "--output-delimiter STRING" --output-delimiter : -b1,3 sp
cmp_out "prefixes" --del ' ' --fi 2 --only sp
cmp_out "--comp" --comp -b2 sp
cmp_out "ambiguous prefix" --c 2 sp
cmp_out "unknown long option" --frob -b1 sp
cmp_out "unknown short option" -q sp
cmp_out "-b without a list" sp -b
cmp_out "--bytes without a list" sp --bytes
cmp_out "--complement=x" --complement=x -b1 sp
# --- list syntax that is accepted
for args in "1 3" "1-3 5" 01 18446744073709551614 1-18446744073709551614 18446744073709551614-; do cmp_out "list '$args'" -b "$args" sp; done
cmp_out "list with a tab" -b $'1\t3' sp
# --- list errors and option conflicts: the message and the status
for args in 0 - 3-2 1-2-3 1--3 1-3- +1 1.5 1-a a "" "1,,3" " 1" "1 " "1, 3" 0- -0 99999999999999999999 18446744073709551615 1-99999999999999999999; do
  cmp_out "bad -b '$args'" -b "$args" sp
  cmp_out "bad -f '$args'" -f "$args" sp
done
cmp_out "two lists" -b1 -f2 sp
cmp_out "two lists, same type" -b1 -c2 sp
cmp_out "-d with -b" -d ' ' -b1 sp
cmp_out "-s with -b" -s -b1 sp
cmp_out "-d two characters" -d ab -f1 sp
cmp_out "no list" sp
cmp_out "no list, only -s" -s sp
# --- several errors at once: GNU reports the option checks before it parses the list
cmp_out "bad list and -d with -b" -b a -d ' ' sp
cmp_out "bad list and a long -d" -f 3-1 -d ab sp
cmp_out "bad list and -s with -b" -b 0 -s sp
cmp_out "two lists, the second bad" -f1 -b 0 sp
cmp_out "empty output delimiter" -b1,3 --output-delimiter= sp
# --- the -a ARRAY extension: the elements are the output lines
n=$((n+1)); a=$("$G" -d ' ' -f2 --complement mix); b=$("$BX" -c 'PATH=; cut -d " " -f2 --complement -a A mix && printf "%s\n" "${A[@]}"')
[[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF -a ARRAY"; diff <(echo "$a") <(echo "$b") | head -4 | sed 's/^/    /'; }
n=$((n+1)); a=$("$G" -d ' ' -f1 -s mix | wc -l); b=$("$BX" -c 'PATH=; cut -d " " -f1 -s -a A mix; echo ${#A[@]}')
[[ "$a" == "$b" ]] || { fail=$((fail+1)); echo "  DIFF -a ARRAY with -s: $a lines vs $b elements"; }
# A named input opened at descriptor zero still belongs to this invocation.
if [[ -d /proc/self/fd ]]; then
  n=$((n+1))
  "$BX" -c 'PATH=; exec 0<&-; cut -b1 sp >/dev/null; [[ ! -e /proc/$$/fd/0 ]]' || {
    fail=$((fail+1)); echo "  DIFF named input leaks descriptor zero"
  }
fi
echo "cut-parity: $((n-fail))/$n identical to $("$G" --version | head -1)"; exit $(( fail>0 ? 1 : 0 ))
