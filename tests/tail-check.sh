#!/usr/bin/env bash
# tests/tail-check.sh [BINARY] — tail builtin: repeated stdin, errors, GNU last-line
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-tail}")
[[ -x $BX ]] || { echo "tail-check: missing binary $BX"; exit 1; }
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }

d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
printf 'alpha\nbeta\n' > "$d/input"

# Command substitution strips trailing newlines; append a sentinel inside
# the same substitution so they survive.
# Three fresh redirections of the same file. Empty PATH.
got=$("$BX" -c 'PATH=; tail -n 1 < "$1"; tail -n 1 < "$1"; tail -n 1 < "$1"' _ "$d/input"; printf x)
if [[ $got == $'beta\nbeta\nbeta\nx' ]]; then
  ok "three fresh tail -n 1 redirections print beta three times"
else
  no "repeat-input got $(printf %s "$got" | od -An -tx1 | tr -s ' ') want beta x3"
fi

# Named file is unaffected (control).
got=$("$BX" -c 'PATH=; tail -n 1 "$1"' _ "$d/input"; printf x)
if [[ $got == $'beta\nx' ]]; then
  ok "tail -n 1 named file"
else
  no "named file $(printf %s "$got" | od -An -tx1 | tr -s ' ')"
fi

got=$("$BX" -c 'PATH=; printf "a\nb\nc\n" | tail -n 1'; printf x)
if [[ $got == $'c\nx' ]]; then
  ok "tail -n 1 on a pipe"
else
  no "pipe $(printf %s "$got" | od -An -tx1 | tr -s ' ')"
fi

# Partial-read then tail, matching GNU.
if command -v /usr/bin/tail >/dev/null; then
  printf 'one\ntwo\nthree\nfour\n' > "$d/four"
  gnu=$( { read -r x; /usr/bin/tail -n 100000; } < "$d/four" )
  bos=$("$BX" -c 'PATH=; { read -r x; tail -n 100000; }' < "$d/four")
  if [[ $bos == "$gnu" ]]; then
    ok "tail after a partial shell read matches GNU"
  else
    no "partial-read bos=$(printf %s "$bos" | od -An -tx1) gnu=$(printf %s "$gnu" | od -An -tx1)"
  fi
fi

# Output failure must not hang reading forever. /dev/zero never ends;
# /dev/full fails the first write. Bound the wait so a hang is a FAIL.
if [[ -e /dev/zero && -e /dev/full ]]; then
  /usr/bin/timeout 2 "$BX" -c 'PATH=; tail -c +1' < /dev/zero > /dev/full 2>"$d/err"
  rc=$?
  if [[ $rc == 124 ]]; then
    no "write-error hung until timeout (still reading after stdout failed)"
  elif [[ $rc != 0 ]]; then
    ok "write-error stops (rc=$rc)"
  else
    no "write-error returned 0"
  fi
fi

# A huge line count must not crash on a failed ring allocation.
/usr/bin/timeout 2 "$BX" -c 'PATH=; tail -n 1073741824' < "$d/input" >"$d/huge-out" 2>"$d/huge-err"
rc=$?
if [[ $rc == 124 ]]; then
  no "huge -n hung or never returned"
elif [[ $rc -ge 128 ]]; then
  no "huge -n died with signal $((rc-128))"
else
  ok "huge -n did not crash (rc=$rc)"
fi

echo "tail-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
