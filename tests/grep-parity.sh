#!/usr/bin/env bash
# tests/grep-parity.sh [BINARY] — grep against GNU grep on the same inputs and
# command lines: both dialects and -F, every flag, the -w retry rules, -x,
# context and -m, empty patterns, binary files and encoding errors, -z, case
# folding in UTF-8, block edges (a match straddling the 96 KB block boundary,
# a line longer than a block, a NUL after the first block), recursion, and
# what is left on stdin. stdout and the exit status must be identical; stderr
# must be identical once the program-name prefix is dropped. Skips without
# GNU grep.
#   GREP_IMPL=CMD runs the bash-os side through CMD instead of the builtin
#   (tests/run.sh points it at the ASan+UBSan harness, tests/grep-host.c).
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=$(readlink -f "${1:-$HERE/out/bash}")
GNUPATH=$(getconf PATH 2>/dev/null || echo /usr/bin:/bin)
PATH=$GNUPATH grep --version 2>/dev/null | grep -q 'GNU grep' || { echo "grep-parity: SKIP (no GNU grep)"; exit 0; }
LOC=C.UTF-8; locale -a 2>/dev/null | grep -qiE '^C\.utf-?8$' || LOC=en_US.UTF-8
d=$(mktemp -d); result_dir=$(mktemp -d); trap 'rm -rf "$d" "$result_dir"' EXIT; cd "$d"
n=0; fail=0; tmp_ge=$result_dir/.ge; tmp_be=$result_dir/.be

# --- inputs
printf 'foo\nbar\nbaz\nfoo bar\nfoobar\naaa\na-a-a\nx-a-a\n\nab cd\na bbc\n' > t.txt
printf 'a\0b\0c\0' > z.bin
printf 'text\0binary\nfoo\n' > bin.dat
printf 'no newline at end' > nonl.txt
: > empty.txt
printf 'a\nb\0c\nd\0' > zrec.bin
printf 'ſ\nK\nİ\nı\ns\nk\ni\n' > fold.txt
printf 'ab\0cd\n' > nulline
printf 'tab\there\r\nplain\nfoo\tbar\nÜber café\nnaïve foo\n' > misc.txt
mkdir -p dir sub/deep; echo foo > dir/f; echo foo > sub/deep/g
python3 - <<'PYX'
import random
r = random.Random(7)
lines = []
for i in range(20000):
    w = " ".join(r.choice(["alpha","beta","gamma","delta","tick","tock"]) for _ in range(r.randint(2,9)))
    if i % 997 == 0: w += " MARK"
    if i in (5000, 5001, 5002): w = "ctx" + str(i)
    lines.append(f"{i} {w}")
open("big.txt","w").write("\n".join(lines) + "\n")
# a line longer than the 96 KB block, the needle near its end
open("longline.txt","w").write("start\n" + "x" * 300000 + "needle" + "y" * 100 + "\nend needle\n")
# the needle straddling the first block boundary, and "nee" ending a line at the second
b = bytearray(b"a" * 98301); b[98301-3:98301] = b"nee"; b += b"dle here\n"; b += b"b" * 98000 + b"\n" + b"z" * (196608 - len(b) - 4) + b"nee" + b"\n"
open("straddle.txt","wb").write(bytes(b))
# a NUL after the first block, with matches before and after it
open("latenul.txt","wb").write(b"foo early\n" + b"filler line\n" * 12000 + b"foo before\0nul\n" + b"foo after\n")
PYX

# --- one case: a shell command line using grep, run by the system bash with
# GNU grep, and by bash-os with its builtin (or by GREP_IMPL)
run_case(){ # LOCALE COMMAND
  local loc=$1 c=$2 go=$result_dir/.go bo=$result_dir/.bo ge be gr br; n=$((n+1))
  LC_ALL=$loc PATH=$GNUPATH bash -c "$c" </dev/null >"$go" 2>"$tmp_ge"; gr=$?
  ge=$(sed -E 's#^[^ ]*/grep: #grep: #' "$tmp_ge")   # /usr/bin/grep: -> grep:
  if [[ -n "${GREP_IMPL:-}" ]]; then
    LC_ALL=$loc ASAN_OPTIONS=exitcode=99 UBSAN_OPTIONS=halt_on_error=1:exitcode=99 PATH=$GNUPATH bash -c "grep() { $GREP_IMPL \"\$@\"; }; $c" </dev/null >"$bo" 2>"$tmp_be"; br=$?
  else
    LC_ALL=$loc PATH= "$BX" -c "$c" </dev/null >"$bo" 2>"$tmp_be"; br=$?
  fi
  # the shell prefixes a builtin's message with "SHELL: line N: NAME: "
  be=$(sed -E 's#^[^ ]*: line [0-9]+: ##; s#^(bash)?grep: #grep: #' "$tmp_be")
  [[ "$gr" == "$br" && "$ge" == "$be" ]] && cmp -s "$go" "$bo" && return
  fail=$((fail+1)); echo "  DIFF [$loc] $c"
  echo "    status $gr vs $br; stderr GNU=[$ge] builtin=[$be]"
  cmp -s "$go" "$bo" || cmp "$go" "$bo" | head -1
}
run_list(){ local loc=$1 c; while IFS= read -r c; do [[ -z $c || $c == \#* ]] && continue; run_case "$loc" "$c"; done; }

run_list $LOC <<'CASES' 2>/dev/null
# dialects: BRE by default, as GNU (\| \+ \? \{ \} operators; + ? { } | literal)
grep 'foo\|baz' t.txt
grep 'fo+' t.txt
grep 'fo\+' t.txt
grep 'a\{3\}' t.txt
grep 'a{3}' t.txt
grep -E 'a{3}' t.txt
grep 'foo\(bar\)\?' t.txt
grep -o 'foo\(bar\)\?' t.txt
grep 'foo(bar)' t.txt
grep -E 'foo(bar)' t.txt
grep '\(' t.txt
grep '(' t.txt
grep -E '(' t.txt
grep -E ')' t.txt
grep ')' t.txt
grep -F '(' t.txt
grep '[' t.txt
grep -E 'a|' t.txt
grep -E '|a' t.txt
grep -E -o 'a|' t.txt
grep -c -E 'a|' t.txt
grep -E '()' t.txt
grep -E 'a**' t.txt
grep '*a' t.txt
grep -E '*a' t.txt
grep -E '+a' t.txt
grep -E 'a|*b' t.txt
grep -E '^*' misc.txt
grep -c '^*' misc.txt
grep -c -E '^{2}' big.txt
grep -c -E '{2}' misc.txt
grep -c -E '(*a)' misc.txt
grep -c -E 'a(+b)' misc.txt
grep -E 'a{1' t.txt
grep -E 'a{1,2' t.txt
grep 'a\{1' t.txt
grep 'a\{1,2}' misc.txt
grep '^{' t.txt
grep 'a{' t.txt
grep -E 'a{' t.txt
grep -E '{' t.txt
grep -E 'a{1' t.txt
grep -c -E 'a{2' misc.txt
grep -c -E 'a{x}' misc.txt
grep -c -E '()' misc.txt
grep -c -E '(|a)' misc.txt
grep -c -E 'a||b' misc.txt
grep -c -E '(a|)' misc.txt
# backreferences, groups, anchors
grep '\(foo\)\1' t.txt
grep -E '(o)\1' t.txt
grep -E '(a)(-)\2' t.txt
grep -c '\(a\)-\1' t.txt
grep -E -c '(a)-\1' t.txt
grep -e '\(a\)-\1' -e foo -c t.txt
grep -c '\(tick\).*\1' big.txt
grep -o '\(tick\).*\1' big.txt | head -2
grep -E '(foo|bar)$' t.txt
grep -e '^foo' -e '^bar' -n t.txt
grep -e 'foo$' -e 'ar$' -n t.txt
grep -c '^' t.txt
grep -c '$' t.txt
grep -c '^$' t.txt
grep -v -c '^$' t.txt
grep -o '^.' t.txt
grep -o '.$' t.txt
grep -E -o '^.|.$' t.txt
grep -E -c '^' misc.txt
grep -E -c '$' misc.txt
grep -E -c 'a$b' misc.txt
grep -c 'a$b' misc.txt
grep -c 'a^b' misc.txt
grep -E -c 'a^b' misc.txt
grep -c '^^' misc.txt
grep -c '$$' misc.txt
grep -c '^plain$' misc.txt
grep -c 'here$' misc.txt
grep -c $'here\r$' misc.txt
grep -c -e '^tab' -e 'foo$' misc.txt
grep -E -c '^tab|foo$' misc.txt
grep -c 'x*' t.txt
grep 'a*' t.txt
grep -o 'a*' t.txt
grep -o 'o*' t.txt
grep -E -o 'o+' t.txt
grep -o '\(ba\)\?[rz]' t.txt
grep -E 'x*' t.txt
grep -c -E '^$' t.txt
grep -c -v -E '^$' t.txt
# word and line matching, GNU's retry rules
grep -w 'a-a' t.txt
grep -wo 'a-a' t.txt
grep -w -e '-a' t.txt
grep -wo 'a[ b]*' t.txt
grep -w '' t.txt
grep -w 'a*' t.txt
grep -wo 'a*' t.txt
grep -x 'a*' t.txt
grep -xc '' t.txt
grep -wc '' t.txt
grep -x '' t.txt
grep -x '' t.txt | od -c | head -1
grep -n -x '' t.txt
grep -o '' t.txt
grep -E -w 'a|ab' t.txt
grep -E -wo 'a|ab' t.txt
grep -E -wo 'ab|a' t.txt
grep -E -w 'a-a|-a' t.txt
grep -w 'foo' t.txt
grep -wc 'a' t.txt
grep -wo 'a' t.txt
grep -w -c -e 'a' -e 'a' t.txt
grep -x -F -e a -e ab t.txt
grep -E -x -e a -e ab t.txt
grep -F -x -e 'ab cd' t.txt
grep -F -w -e 'a-a' -e 'a-a-a' t.txt
grep -Fwo -e 'a-a' -e 'a-a-a' t.txt
grep -F -w -e 'a-a' -e 'x-a' t.txt
grep -F -w -e a -e aa -o t.txt
grep -F -w -e a-a-a -e a-a -o t.txt
grep -F -o -e a -e aa t.txt
grep -F -x -e foo -e aaa t.txt
grep -F -x -c '' t.txt
grep -x -c -F '' t.txt
grep -F '' t.txt
grep -F -x '' t.txt
grep -F -w '' t.txt
grep -F -v -w '' t.txt
grep -c -x -e foo -e '' t.txt
printf 'foobar foo\n' | grep -wo 'foo'
printf 'foobar foo\n' | grep -wob 'foo'
printf 'é a\n' | grep -w a
printf 'éa\n' | grep -w a
printf 'a_b a\n' | grep -wo a
grep -c -w -E 'x*' big.txt
grep -w -c 'tick' big.txt
grep -w -o 'tick' big.txt | head -3
grep -w -c '^0' big.txt
grep -c -w -E 't[io]ck' big.txt
grep -c -x -E '[0-9]+ ctx[0-9]+' big.txt
grep -n -x -E '[0-9]+ ctx[0-9]+' big.txt
grep -x '0 alpha' big.txt
grep -x -n '^1 .*' big.txt
grep -c -w 'here' misc.txt
grep -x 'plain' misc.txt
grep -x -c 'plain' misc.txt
grep -x -e plain -e 'foo	bar' misc.txt
grep -F -x -e plain -e 'foo	bar' misc.txt
grep -w 'ber' misc.txt
grep -w 'caf' misc.txt
grep -w -o 'café' misc.txt
grep '\<a' t.txt
grep -o '\<a' t.txt
grep -o '\ba\b' t.txt
grep -o 'a\>' t.txt
grep -o '\<.' t.txt
grep -o '.\>' t.txt
grep -o '\ba' t.txt
grep -o 'a\>' t.txt
grep -o '\Ba' t.txt
grep -c '\<foo' misc.txt
grep -c 'foo\>' misc.txt
grep -c '\bfoo\b' misc.txt
grep -c -E '\Bo' misc.txt
grep -c -E '\<beta\>' big.txt
grep -c -E '\bbeta\b' big.txt
grep -c -E 'beta\B' big.txt
# counting, listing, quiet, status
grep -c 'foo' t.txt
grep -c '' t.txt
grep -c '' empty.txt
grep -v x empty.txt
grep -c a empty.txt
grep -v -c a empty.txt
grep -L a empty.txt t.txt
grep -H foo t.txt
grep -l foo t.txt empty.txt
grep -L foo t.txt empty.txt
grep -L foo empty.txt
grep -L foo t.txt
grep -l foo empty.txt
grep -c foo t.txt empty.txt
grep -h foo t.txt t.txt
grep 'foo' nonl.txt t.txt
grep -c -H foo t.txt
grep -q foo missing t.txt
grep -q foo t.txt missing
grep -qs foo missing t.txt
grep -q foo missing
grep foo missing t.txt
grep -c foo missing t.txt
grep -s foo missing
grep foo missing
grep -h foo missing t.txt
grep foo dir
grep -s foo dir
grep -c '' /dev/null
grep -L '' /dev/null
grep -y FOO t.txt
grep -y foo t.txt
grep --no-such t.txt
grep -e foo -- -x t.txt
grep -- -x t.txt
grep -e -x t.txt
grep --count foo t.txt
grep --files-with-matches foo t.txt
grep --line-number --with-filename foo t.txt
grep --max-count=1 foo t.txt
grep --max-count 1 foo t.txt
grep --regexp=foo --regexp=bar -c t.txt
grep --file=/dev/null -c t.txt
grep --context=1 baz t.txt
grep --after-context=1 --before-context=0 baz t.txt
grep --fixed-strings --ignore-case FOO t.txt
grep --null-data -c a z.bin
grep --colour foo t.txt
grep --color foo t.txt
grep --binary-files=without-match foo bin.dat
# patterns: several, empty, from files, newlines
grep -e foo -e bar -n t.txt
grep -c -e the -e and -e zzz t.txt
grep -E -c 'foo|ba' t.txt
grep -o -E 'foo|foobar' t.txt
grep -o -E 'foobar|foo' t.txt
grep -E 'foo|ba' -c t.txt
grep 'foo\|ba' -c t.txt
grep -E 'a-a|x' t.txt
grep 'ba[rz]' t.txt
grep -e '' -e foo t.txt
grep -c -e foo -e '' t.txt
grep -f /dev/null t.txt
grep -v -f /dev/null t.txt
grep -e foo -f /dev/null t.txt
grep -v -c '' t.txt
grep -v -c -e '' t.txt
grep -v -c -e '' -e x t.txt
grep -c -v -f /dev/null t.txt
grep -c -f /dev/null t.txt
grep -x -v '' t.txt
grep -w -v '' t.txt
grep -L -v '' t.txt
grep -v '' t.txt
grep -F -c -e 'a' -e 'a' t.txt
grep -e $'foo\nbar' t.txt
grep -c -e $'foo\n' t.txt
grep -c $'foo\n' t.txt
printf 'foo\nbar\n' | grep -f - t.txt
grep -c -e alpha -e beta -e gamma big.txt
grep -c -E 'alpha|beta|gamma' big.txt
grep -c -E 'MARK|ctx5000' big.txt
grep -n -E 'MARK|ctx5000' big.txt | tail -3
grep -c -E -e 'alpha' -e '[0-9]{5} beta' big.txt
grep -c -e 'alpha' -e '[0-9]\{5\} beta' big.txt
# only-matching, offsets, numbers, prefixes, NUL after names
grep -i -o 'foo' t.txt
grep -n -b 'a' t.txt
grep -ob 'a' t.txt
grep -bv foo nonl.txt
grep -b -o 'o' nonl.txt
grep -nb '' nonl.txt
grep -c 'end$' nonl.txt
grep -o 'end$' nonl.txt
grep -v -n 'x' nonl.txt
grep -bo 'a' z.bin
grep '' nonl.txt
grep -c 'o' nonl.txt
grep -x 'no newline at end' nonl.txt
grep -b '' nonl.txt
grep -bo 'end' nonl.txt
grep -n '' empty.txt
grep -L '' empty.txt
grep -l '' empty.txt
grep -v -c '' empty.txt
grep -H foo - < t.txt
grep -c foo - t.txt < t.txt
grep -Z -c foo t.txt t.txt | od -c | head -2
grep -Z -n foo t.txt t.txt | od -c | head -2
grep -lZ foo t.txt t.txt | od -c | head -1
grep -ob 'foo' misc.txt
grep -n '' misc.txt | od -c | head -3
grep -v -n -e foo -e plain misc.txt
grep -v -o a t.txt
grep -v -c -o a t.txt
# context, -m, separators
grep -o -A1 foo t.txt
grep -m1 -A2 foo t.txt
grep -m1 -A2 ba t.txt
grep -B1 -A1 'baz' t.txt
grep -C1 -n 'a' t.txt
grep -m 2 -c a t.txt
grep -A1 -B1 -n -c foo t.txt
grep -m1 foo t.txt t.txt
grep -m1 -c foo t.txt
grep -m1 -v foo t.txt
grep -q -m1 foo t.txt
grep -m0 a t.txt
grep -m0 -L a t.txt
grep -m 1 -c '' t.txt
grep -m 2 -n -v foo t.txt
grep -m 2 -o -n a t.txt
grep -m 1 -A 1 -B 1 -n baz t.txt
grep -c -m1 -A1 foo t.txt
grep -A1 -c foo t.txt
grep -2 -n baz t.txt
grep -A0 -n foo t.txt
grep -B0 -n foo t.txt
grep -C0 -c foo t.txt
grep -n -A1 foo t.txt empty.txt t.txt
printf 'a\nb\nc\n' | grep -n -B5 c
printf 'a\nb\nc\nd\ne\nf\n' | grep -n -A1 -B1 -e b -e e
printf 'a\nb\nc\nd\ne\nf\n' | grep -n -A1 -B1 -e b -e d
printf 'a\nb\nc\nd\ne\nf\n' | grep -n -C1 -v -e b -e e
printf 'a\nb\nc\nd\ne\nf\n' | grep -c -C1 -e b -e e
printf 'a\nb\nc\nd\ne\nf\n' | grep -n -A1 -m1 -e b -e c
printf 'a\nb\nc\nd\ne\nf\n' | grep -n -A2 -m1 -v -e a -e b
printf 'a\nb\nc\nd\ne\nf\n' | grep -n -B1 -A1 -o -e b -e e
printf 'a\nb\nc\nd\ne\nf\n' | grep -o -B1 -A1 -e b -e e
grep -n -B2 -A2 ctx5001 big.txt
grep -n -C1 -e ctx5000 -e ctx5002 big.txt
grep -n -A1 -B1 MARK big.txt | tail -6
grep -m 3 -n MARK big.txt
grep -m 3 -c MARK big.txt
grep -m 3 -A1 -n MARK big.txt
grep -m 1 -v -n alpha big.txt
grep -m 2 -n -E 'delta.*delta' big.txt
# binary files and encoding errors
grep foo bin.dat
grep -c foo bin.dat
grep -a foo bin.dat
grep -I foo bin.dat
grep -I -c foo bin.dat
grep -I -L foo bin.dat
grep -c '' z.bin
grep b z.bin
grep -c b z.bin
grep -a b z.bin
grep -ao b z.bin
grep 'a.b' bin.dat
grep -n b z.bin
grep -l b z.bin
grep -o b z.bin
printf 'caf\xe9 foo\n' | grep foo
printf 'caf\xe9 foo\n' | grep -c foo
printf 'caf\xe9 foo\n' | grep -o foo
printf 'caf\xe9 foo\n' | grep -a foo | od -c | head -1
printf 'x\nfoo\n\0\nfoo\n' | grep foo
printf 'x\nfoo\n\0\nfoo\n' | grep -c foo
printf 'x\nfoo\n\0\nfoo\n' | grep -c ''
printf 'ab\0cd\n' | grep -c d
printf 'ab\0cd\n' | grep -o d
printf 'ab\0cd\n' | grep -a -c 'b[^x]c'
grep -a -c 'cd' nulline
grep -a -o 'b[^x]c' nulline | od -c | head -1
grep foo latenul.txt
grep -c foo latenul.txt
grep -n foo latenul.txt
grep -o foo latenul.txt
grep -a -c foo latenul.txt
grep -l foo latenul.txt
grep -n -B1 'foo after' latenul.txt
grep -c '' latenul.txt
grep -c -E 'foo (before|after)' latenul.txt
grep -E 'foo (before|after)' latenul.txt
grep -n -E 'foo (before|after)' latenul.txt
# NUL-separated records
grep -z '^b' zrec.bin
grep -z 'a.b' zrec.bin
grep -z -c '' zrec.bin
grep -z b z.bin
printf 'a\nb\nc\nd\ne\nf\n' | grep -z -c .
printf 'a\0b\0' | grep -z -n b | od -c | head -2
printf 'a\0b\0' | grep -z -Z -n b | od -c | head -2
printf 'a\0b\0' | grep -z -A1 -n a | od -c | head -2
printf 'a\0b\0c\0d\0' | grep -z -A1 -n -e a -e d | od -c | head -3
printf 'a\nb' | grep -z -c .
printf 'a\nb\0c\nd\0' | grep -z -c -E '[^x]$'
printf 'a\nb\0c\nd\0' | grep -z -c -E 'a.b'
printf 'a\nb\0c\nd\0' | grep -z -o -E 'a.b' | od -c | head -1
printf 'a\nb\0c\nd\0' | grep -z -c '^c'
printf 'a\nb\0c\nd\0' | grep -z -c 'b$'
printf 'a\nb\0c\nd\0' | grep -z -c -E 'b[[:space:]]c'
# patterns that could match the newline (block search must not be used)
printf 'ab\ncd\n' | grep -c -E 'b[[:space:]]c'
printf 'ab\ncd\n' | grep -c -E 'b\sc'
printf 'ab\ncd\n' | grep -c -E 'b[^x]c'
printf 'ab\ncd\n' | grep -c -E 'b.c'
printf 'ab\ncd\n' | grep -c -E 'b\Wc'
printf 'ab\ncd\n' | grep -c -E 'b[[.newline.]]c'
grep -c -E 'a[[:space:]]b' big.txt
grep -c -E 'alpha\sbeta' big.txt
grep -c -E 'alpha\Wbeta' big.txt
grep -c -E 'alpha[ ]beta' big.txt
grep -c -E 'alpha[[:blank:]]beta' big.txt
grep -c -E 'alpha[ -/]beta' big.txt
grep -c -E 'alpha[^x]beta' big.txt
# case folding
grep -i s fold.txt
grep -i k fold.txt
grep -i i fold.txt
grep -i 'ſ' fold.txt
grep -i 'BA[RZ]' t.txt
grep -F -i -o FOO t.txt
printf 'aXb\n' | grep -o -i 'x'
printf 'ſ\n' | grep -i -c s
printf 'ſ\n' | grep -E -i -c s
printf 'K\n' | grep -i -c k
printf 'K\n' | grep -i -c 'k|x'
printf 'K\n' | grep -E -i -c 'k|x'
printf 'İ\n' | grep -i -c i
printf 'É\n' | grep -i -c 'é'
printf 'É\n' | grep -F -i -c 'é'
printf 'ABC\n' | grep -i -o 'b'
printf 'ABC\n' | grep -F -i -o 'b'
grep -i 'FOO BAR' t.txt
grep -F -i 'FOO BAR' t.txt
grep -F -i -e 'FOO BAR' -e 'XYZ' t.txt
grep -i -e 'FOO BAR' -e 'XYZ' t.txt
grep -i -c 'a-a' t.txt
grep -ic 'A-A' t.txt
grep -iw 'A-A' t.txt
grep -ix 'FOOBAR' t.txt
grep -ic 's' t.txt
grep -io 'AB' t.txt
grep -c -i 'ALPHA' big.txt
grep -c -i -w 'TICK' big.txt
grep -c -i -E 'ALPHA|BETA' big.txt
grep -c -i 'gamma' big.txt
grep -c -i -w 'GAMMA' big.txt
grep -n -i '^1999[0-9] GAMMA' big.txt
grep -c -i 'ck$' big.txt
grep -o -i 'ÜBER' misc.txt
grep -c -i 'über' misc.txt
grep -c 'ü' misc.txt
grep -F -c 'ü' misc.txt
grep -F -i -c 'Ü' misc.txt
grep -c 'ü\|é' misc.txt
# block edges: 96 KB boundary, a line longer than a block, lazy line numbers
grep -c MARK big.txt
grep -n MARK big.txt
grep -b MARK big.txt
grep -c -v tick big.txt
grep -c '^1999' big.txt
grep -n '^1999' big.txt
grep '^19999 ' big.txt
grep -o '^1999.' big.txt
grep -c 'MARK$' big.txt
grep -n -o 'MARK$' big.txt
grep -c '^0 ' big.txt
grep -c -E '[0-9]{4} ' big.txt
grep -c -E '^[0-9]+ (alpha|beta)' big.txt
grep -n -E '^1999[0-9] gamma' big.txt
grep -c 'tick.*tock' big.txt
grep -o -E 'ti[ck]+' big.txt | head -3
grep -c -v -E '[a-z]+ [a-z]+' big.txt
grep -c -E '(alpha|beta)+ gamma' big.txt
grep -o -E '(alpha|beta)+ gamma' big.txt | head -2
grep -c -E 'alpha$' big.txt
grep -c -E '^[0-9]+ alpha' big.txt
grep -c -E '' big.txt
grep -c -E 'x*' big.txt
grep -c needle longline.txt
grep -n -o needle longline.txt
grep -b -o needle longline.txt
grep -c '^start' longline.txt
grep -c 'end needle$' longline.txt
grep -c -v x longline.txt
grep -n -B1 'end needle' longline.txt | cut -c1-20
grep -c -E 'x{300000}needle' longline.txt
grep -n -E 'e{2}dle' longline.txt | cut -c1-12
grep -o -E 'x{3}needle' longline.txt
grep -c needle straddle.txt
grep -b -o needle straddle.txt
grep -c 'nee$' straddle.txt
grep -b -o 'nee$' straddle.txt
grep -c 'b*$' straddle.txt
grep -n -c '' straddle.txt
grep -c -E 'e{3}' straddle.txt
grep -b -o -E 'ne+dle' straddle.txt
grep -b -o -E 'nee$' straddle.txt
grep -c -E '^b+$' straddle.txt
grep -c -E 'a{98298}nee' straddle.txt
# bracket expressions, classes, escapes
grep -c $'\r' misc.txt
grep -c $'\t' misc.txt
grep -o 'foo.bar' misc.txt | od -c | head -1
grep 'caf.' misc.txt
grep -o 'caf.' misc.txt
grep -o '\w*' misc.txt | head -4
grep -o -E '[[:alpha:]]+' misc.txt | tail -3
grep -c 'a.b' misc.txt
grep -c -E 'a\w' misc.txt
grep -o '[[:upper:]]' misc.txt
grep -c '.' misc.txt
grep -c '^.$' misc.txt
grep -o '^.' misc.txt
grep -o '.$' misc.txt | od -c | head -2
grep -E -c 'o{2}' misc.txt
grep -E -c 'o{2,}' misc.txt
grep -E -c 'o{,2}' misc.txt
grep -c 'o\{2\}' misc.txt
grep -E -c '(fo)+' misc.txt
grep -E -o '(fo)+' misc.txt
grep -E -c '(fo)?o' misc.txt
grep -E -c 'x*foo' misc.txt
grep -E -o 'x*foo' misc.txt
grep -E -o 'fo*' misc.txt
grep -E -c '(^|[^a-z])foo' misc.txt
grep -E -c 'foo([^a-z]|$)' misc.txt
grep -c 'foo.*bar' misc.txt
grep -c 'bar.*foo' misc.txt
grep -o 'a[^a]*a' misc.txt
grep -c '[[:space:]]' misc.txt
grep -c '[^[:space:]]$' misc.txt
grep -c '[]]' misc.txt
grep -c '[^]]' misc.txt
grep -c '[a-]' misc.txt
grep -c '[[.hyphen.]]' misc.txt
grep -c '[[=a=]]' misc.txt
grep -c '\.' misc.txt
grep -c '\*' misc.txt
grep -c '\\' misc.txt
grep -c '\-' misc.txt
grep -c '\/' misc.txt
grep -c 'a\{1,\}' misc.txt
grep -c 'a\{,2\}' misc.txt
grep -c '\(a\)\(b\)' misc.txt
grep -c '\(ab\)*' misc.txt
grep -o '\(ab\)*' misc.txt
grep -c '\(*\)' misc.txt
grep -c 'x\+' misc.txt
grep -c 'x\?foo' misc.txt
grep -o 'x\?foo' misc.txt
grep -E -c 'x+' misc.txt
grep -E -o 'fo|foo' misc.txt
grep -E -o 'foo|fo' misc.txt
grep '[[:digit:]]' t.txt
grep '[]a]' t.txt
grep '[^]a]' t.txt
grep -c '[[:space:]]' t.txt
grep -c '\s' t.txt
grep -c '\w' t.txt
grep -E -o '\w+' t.txt
grep -c -E '[0-9]+' big.txt
grep -c -E 'w[a-z]+ch' big.txt
# recursion and file selection
grep --include='*.txt' -r foo .
grep -r foo dir
grep -c foo dir/f
grep -rc foo dir
grep -rl foo dir t.txt
grep -rh foo dir
grep -rH foo dir/f
grep -r foo dir/f
cd dir && grep -r foo
grep -r foo . | LC_ALL=C sort
grep -rn foo . dir | LC_ALL=C sort
grep --include='*.txt' -rl foo . | LC_ALL=C sort
grep --exclude='t.txt' -rl foo . | LC_ALL=C sort
grep --exclude-dir=dir -rl foo . | LC_ALL=C sort
grep -R foo dir
grep -r foo | LC_ALL=C sort
# what is left on stdin
{ grep -m1 foo; echo ---; cat; } < t.txt
{ grep -q foo; echo ---; cat; } < t.txt
{ grep -l foo; echo ---; cat; } < t.txt
{ grep -c foo; echo ---; cat; } < t.txt
{ grep -m1 -A1 foo; echo ---; cat; } < t.txt
CASES

# --- the C locale: bytes are characters, nothing folds beyond ASCII
run_list C <<'CASES' 2>/dev/null
printf 'éa\n' | grep -w a
printf 'caf\xe9 foo\n' | grep foo
printf 'caf\xe9 foo\n' | grep -c foo
printf 'É\n' | grep -F -i -c 'é'
printf 'ABC\n' | grep -F -i -o 'b'
printf 'ſ\n' | grep -i -c s
grep -c -i 'ALPHA' big.txt
grep -c 'caf.' misc.txt
grep -o 'caf.' misc.txt | od -c | head -1
grep -c -w 'caf' misc.txt
grep -o '[[:upper:]]' misc.txt
grep -c MARK big.txt
grep -c needle straddle.txt
grep foo latenul.txt
grep -c foo latenul.txt
grep -i -c 'FOO BAR' t.txt
grep -w -c 'a' t.txt
grep -x 'no newline at end' nonl.txt
CASES

if [[ -w /dev/full ]]; then
  run_case C 'grep foo t.txt > /dev/full'
  run_case C 'grep -c foo t.txt > /dev/full'
  run_case C 'grep -q foo t.txt > /dev/full'
fi
echo "grep-parity: $((n-fail))/$n identical to GNU grep ($(PATH=$GNUPATH grep --version | head -1 | grep -oE '[0-9.]+$'))"
exit $(( fail>0 ? 1 : 0 ))
