#!/usr/bin/env bash
# tests/repeat-input-check.sh [BINARY] — a builtin must read a redirected stdin
# correctly on every invocation, not just the first.
#
# A builtin runs in the shell process, so the stdin FILE outlives the call. A
# reader that leaves the EOF flag set makes the next `CMD < FILE' read nothing
# and still exit 0 — silent data loss. Pipelines fork, so the bug only appears
# when the builtin runs directly in the shell, which is the normal case with an
# empty PATH. Every filter below is driven twice from two different files.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }

cd "$d"
# Two inputs of identical shape and size, distinguishable byte for byte.
awk 'BEGIN{for(i=0;i<500;i++)printf "AAAA-line-%04d\n", i}' > A
awk 'BEGIN{for(i=0;i<500;i++)printf "BBBB-line-%04d\n", i}' > B

# Repeated invocation: N passes over the same file in one shell must emit the
# one-pass output N times. Runs with an empty PATH, no fork, stdout to a file.
batch(){ # batch INPUT PASSES CMD...
  local input=$1 n=$2; shift 2
  "$BX" --noprofile --norc -c '
    PATH=; input=$1; count=$2; shift 2
    for ((i=0;i<count;i++)); do "$@" < "$input" || exit; done' \
    _ "$input" "$n" "$@" 2>/dev/null | wc -c
}

# Distinct inputs: the second invocation must reflect the second file, not a
# stale buffer and not an empty read.
second(){ # second CMD... -> bytes produced by the second invocation
  "$BX" --noprofile --norc -c '
    PATH=; shift 0
    "$@" < A > /dev/null
    "$@" < B > out.second' _ "$@" 2>/dev/null
  wc -c < out.second
}

check(){ # check LABEL INPUT CMD...
  local label=$1 input=$2; shift 2
  local one three
  one=$(batch "$input" 1 "$@")
  three=$(batch "$input" 3 "$@")
  if [[ $one -eq 0 ]]; then
    no "$label: one pass produced no output (fixture or arguments wrong)"
    return
  fi
  if [[ $three -eq $((one * 3)) ]]; then
    ok "$label: three passes emit 3x one pass ($three bytes)"
  else
    no "$label: three passes emitted $three bytes, expected $((one * 3))"
  fi
}

check_second(){ # check_second LABEL CMD...
  local label=$1; shift
  local a b
  a=$("$BX" --noprofile --norc -c 'PATH=; "$@" < A > out.first' _ "$@" 2>/dev/null; wc -c < out.first)
  b=$(second "$@")
  if [[ $a -eq 0 ]]; then
    no "$label: first invocation produced no output"
  elif [[ $b -eq $a ]]; then
    ok "$label: second invocation on a different file emits $b bytes"
  else
    no "$label: second invocation emitted $b bytes, first emitted $a"
  fi
}

# The four loadables that read the persistent stdin FILE directly. Each was
# confirmed to emit nothing (more, less), an empty body (uuencode) or a single
# byte (xargs) on a second invocation before the clearerr fix.
for spec in "more::more" "less::less" "xargs:-n 2 /bin/echo:xargs"; do
  IFS=: read -r cmd extra label <<<"$spec"
  # shellcheck disable=SC2086
  check "$label" A $cmd $extra
  # shellcheck disable=SC2086
  check_second "$label" $cmd $extra
done
check uuencode A uuencode payload
check_second uuencode uuencode payload

# obj and bsdgames read the persistent stdin stream too; found by the metric
# coverage sweep, 2026-09-12. obj's --batch-check and bsdgames' headless filters
# both silently processed nothing on a second call.
if "$BX" --noprofile --norc -c 'PATH=; type -t obj' 2>/dev/null | grep -q builtin; then
  # hash --stdin-paths drives the same getline(stdin) loop as --batch-check but
  # needs no repository, so the check works anywhere.
  printf 'hello\n' > h.txt
  printf 'h.txt\n' > objpaths
  a=$("$BX" --noprofile --norc -c 'PATH=; obj hash --stdin-paths < objpaths > o1 2>/dev/null'; wc -c < o1)
  b=$("$BX" --noprofile --norc -c 'PATH=; obj hash --stdin-paths < objpaths > /dev/null 2>&1
                                    obj hash --stdin-paths < objpaths > o2 2>/dev/null'; wc -c < o2)
  if [[ $a -eq 0 ]]; then
    no "obj hash --stdin-paths produced nothing on the first call; check the fixture"
  elif [[ $b -eq $a ]]; then
    ok "obj hash --stdin-paths second invocation emits $b bytes"
  else
    no "obj hash --stdin-paths: first $a bytes, second $b bytes"
  fi
fi
if "$BX" --noprofile --norc -c 'PATH=; type -t bsdgames' 2>/dev/null | grep -q builtin; then
  printf 'sos\n' > morsein
  a=$("$BX" --noprofile --norc -c 'PATH=; bsdgames morse < morsein > m1 2>/dev/null'; wc -c < m1)
  b=$("$BX" --noprofile --norc -c 'PATH=; bsdgames morse < morsein > /dev/null 2>&1
                                    bsdgames morse < morsein > m2 2>/dev/null'; wc -c < m2)
  [[ $a -gt 0 && $b -eq $a ]] && ok "bsdgames morse second invocation emits $b bytes" \
    || no "bsdgames morse: first $a bytes, second $b bytes"
fi

# Controls: these already reset their stream, and must stay correct.
for c in cat tac rev "nl -ba" "fold -w 40" "sort" "wc -l" "strings -n 4"; do
  # shellcheck disable=SC2086
  check "control $c" A $c
done

# The second invocation must carry the second file's bytes, not the first's.
got=$("$BX" --noprofile --norc -c 'PATH=; cat < A > /dev/null; cat < B' _ 2>/dev/null | head -n 1)
[[ $got == BBBB-line-0000 ]] && ok "second invocation reads the second file" \
  || no "second invocation produced '$got'"

echo "repeat-input: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
