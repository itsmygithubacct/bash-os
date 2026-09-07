#!/usr/bin/env bash
# tests/text-tools-parity.sh [BINARY] — the text and formatting tools imported
# from the upstream collection, byte-compared against the host's coreutils and
# util-linux on the same inputs. A tool with no host counterpart is exercised
# for a round trip instead. Skips a comparison when the host tool is absent.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; cd "$d"
pass=0; fail=0; skip=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }; no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
printf 'a\tb\tc\nxx\tyy\tzz\n\tlead\n' > tabs.txt
printf 'one two three\nfour five six\nseven eight nine\n' > words.txt
printf '1 alpha\n2 beta\n3 gamma\n' > j1.txt; printf '1 A\n2 B\n4 D\n' > j2.txt
printf 'l1\nl2\nl3\nl4\nl5\nl6\n' > lines.txt
printf 'no newline at end' > nonl.txt; : > empty.txt
head -c 512 /dev/urandom > bin.dat; printf 'text\0with\0nuls\nand a long printable run here\n' > mixed.dat

# cmp2 LABEL COMMAND — run under both userlands, compare stdout+stderr+status
cmp2(){ local label=$1 cmd=$2 tool=${2%% *}
  if ! command -v "$tool" >/dev/null; then skip=$((skip+1)); return; fi
  local a b ra rb
  a=$(eval "$cmd" 2>&1); ra=$?
  b=$("$BX" -c "PATH=; $cmd" 2>&1); rb=$?
  if [[ "$a" == "$b" && "$ra" == "$rb" ]]; then ok "$label"
  else no "$label (status $ra vs $rb)"; diff <(echo "$a") <(echo "$b") | head -4 | sed 's/^/      /'; fi
}
echo "== byte-compared with the host's tools =="
cmp2 "expand"            "expand tabs.txt"
cmp2 "expand -t 4"       "expand -t 4 tabs.txt"
cmp2 "unexpand -a"       "unexpand -a tabs.txt"
cmp2 "tac"               "tac lines.txt"
cmp2 "tac (no final NL)" "tac nonl.txt"
cmp2 "tac empty"         "tac empty.txt"
cmp2 "join"              "join j1.txt j2.txt"
cmp2 "join -a1"          "join -a 1 j1.txt j2.txt"
cmp2 "pr -t"             "pr -t words.txt"
cmp2 "expr arithmetic"   "expr 6 \* 7 + 1"
cmp2 "expr length"       "expr length abcdef"
cmp2 "expr substr"       "expr substr abcdef 2 3"
cmp2 "expr match"        "expr abcdef : 'abc'"
cmp2 "hexdump -C"        "hexdump -C bin.dat"
cmp2 "hexdump -C mixed"  "hexdump -C mixed.dat"
cmp2 "column -t"         "column -t words.txt"
cmp2 "colrm 4"           "colrm 4 < words.txt"
cmp2 "colrm 2 4"         "colrm 2 4 < words.txt"
cmp2 "strings"           "strings bin.dat"
cmp2 "strings -n 4"      "strings -n 4 mixed.dat"
cmp2 "split -l 2"        "split -l 2 lines.txt sp_ && cat sp_* && rm -f sp_*"
cmp2 "csplit"            "csplit -f cs -k lines.txt 3 >/dev/null && cat cs00 cs01 && rm -f cs0*"

echo "== round trips and self-checks (no host counterpart) =="
"$BX" -c 'PATH=; uuencode -m words.txt words.txt' > enc.b64 2>/dev/null \
  && "$BX" -c 'PATH=; uudecode -o rt.txt < enc.b64' 2>/dev/null && cmp -s words.txt rt.txt \
  && ok "uuencode -m | uudecode round trip" || no "uuencode/uudecode round trip"
"$BX" -c 'PATH=; uuencode words.txt words.txt' > enc.uu 2>/dev/null \
  && "$BX" -c 'PATH=; uudecode -o rt2.txt < enc.uu' 2>/dev/null && cmp -s words.txt rt2.txt \
  && ok "classic uuencode round trip" || no "classic uuencode round trip"
"$BX" -c 'PATH=; ar rc lib.a words.txt lines.txt' 2>/dev/null && "$BX" -c 'PATH=; ar t lib.a' 2>/dev/null | tr '\n' ' ' | grep -q 'words.txt lines.txt' \
  && ok "ar create and list" || no "ar create/list"
if command -v ar >/dev/null; then ar t lib.a >/dev/null 2>&1 && ok "the host's ar reads our archive" || no "host ar cannot read ours"; else skip=$((skip+1)); fi
# `a` appends after the current line; addressing line 1 of an empty buffer is
# an error in ed(1) itself, so the script starts with a bare `a`
"$BX" -c 'PATH=; printf "a\nhello\n.\nw out.ed\nq\n" | ed -s out.ed' >/dev/null 2>&1
[[ "$(cat out.ed 2>/dev/null)" == hello ]] && ok "ed appends and writes" || no "ed: [$(cat out.ed 2>/dev/null)]"
# tput carries a curated capability table (xterm, screen, tmux, linux, vt100,
# dumb) plus a side-file path for anything else; an unlisted TERM is a clean
# error, not a crash
[[ "$(TERM=xterm "$BX" -c 'PATH=; tput cols')" == 80 ]] && ok "tput cols for a known TERM" || no "tput cols"
TERM=xterm "$BX" -c 'PATH=; tput bold' >/dev/null 2>&1 && ok "tput bold" || no "tput bold"
out=$(TERM=no-such-terminal-xyz "$BX" -c 'PATH=; tput cols' 2>&1); [[ $? == 3 && "$out" == *"unknown terminal"* ]] \
  && ok "an unlisted TERM is a clean error (exit 3)" || no "unknown TERM: $out"
"$BX" -c 'PATH=; tinfo --help' >/dev/null 2>&1 && ok "tinfo runs" || no "tinfo"
"$BX" -c 'PATH=; printf "a\bb\n" | col' >/dev/null 2>&1 && ok "col runs" || no "col"

echo; echo "text-tools-parity: $pass passed, $fail failed, $skip skipped (no host tool)"
exit $(( fail>0 ? 1 : 0 ))
