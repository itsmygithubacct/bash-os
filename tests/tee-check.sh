#!/usr/bin/env bash
# tests/tee-check.sh [BINARY] — stock tee: closed stdin and failed destinations
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-tee}")
[[ -x /usr/bin/tee ]] || { echo "tee-check: SKIP (no /usr/bin/tee)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }

t=$("$BX" -c 'PATH=; type -t tee' 2>/dev/null) || t=
[[ $t == builtin ]] && ok "tee is a builtin with empty PATH" || no "type -t tee -> '$t'"

"$BX" -c 'PATH=; tee --help' >"$d/help" 2>&1; rc=$?
[[ -s $d/help ]] && grep -q 'standard input' "$d/help" \
  && ok "--help prints usage (rc=$rc)" || no "--help rc=$rc out=$(head -c 80 "$d/help")"

"$BX" -c 'PATH=; tee <&- > /dev/null' >"$d/out" 2>"$d/err"; rc=$?
[[ $rc != 0 ]] && ok "closed stdin returns $rc" || no "closed stdin rc=$rc (want non-zero) err=$(cat "$d/err")"

/usr/bin/tee <&- > /dev/null 2>"$d/gnu.err"; grc=$?
[[ $grc != 0 ]] && ok "GNU tee closed stdin returns $grc" || no "GNU tee closed stdin rc=$grc err=$(cat "$d/gnu.err")"

# All outputs failed: must return promptly, not hang until timeout 124.
t0=$(date +%s.%N)
timeout 2 "$BX" -c 'PATH=; tee /dev/full >/dev/full' < /dev/zero >"$d/all.out" 2>"$d/all.err"
rc=$?
t1=$(date +%s.%N)
elapsed=$(python3 -c "print(round(float('$t1')-float('$t0'),3))")
nerr=$(wc -l < "$d/all.err")
if [[ $rc != 0 && $rc != 124 && $nerr -le 20 ]]; then
  ok "all dests failed returns $rc in ${elapsed}s ($nerr diagnostics)"
else
  no "all dests failed rc=$rc elapsed=${elapsed}s lines=$nerr (want non-zero, not 124)"
fi

# One dest failed, one healthy: payload is kept; status non-zero.
printf 'payload\n' > "$d/want"
printf 'payload\n' | "$BX" -c "PATH=; tee /dev/full '$d/dest'" >"$d/mixed.out" 2>"$d/mixed.err"
rc=$?
if [[ $rc != 0 ]] && cmp -s "$d/dest" "$d/want"; then
  ok "failed dest skips; healthy dest keeps payload"
else
  no "mixed rc=$rc dest=$(od -c "$d/dest" 2>/dev/null | head -1)"
fi
printf 'payload\n' | /usr/bin/tee /dev/full "$d/gnu-dest" >/dev/null 2>"$d/gnu-mixed.err"
if cmp -s "$d/gnu-dest" "$d/want"; then
  ok "GNU mixed dest keeps payload"
else
  no "GNU mixed dest mismatch"
fi

echo "tee-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
