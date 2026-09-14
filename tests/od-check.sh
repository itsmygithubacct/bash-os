#!/usr/bin/env bash
# tests/od-check.sh [BINARY] — od builtin: repeated redirected stdin
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-p1readers}")
[[ -x $BX ]] || { echo "od-check: missing binary $BX"; exit 1; }
command -v /usr/bin/od >/dev/null || { echo "od-check: SKIP (no host od)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t od 2>/dev/null) || t=
[[ $t == builtin ]] && ok "od is a builtin with empty PATH" || no "type -t od -> '$t'"

printf 'alpha\nbeta\n' > "$d/input"
/usr/bin/od -An -tx1 < "$d/input" > "$d/once"
{ /usr/bin/od -An -tx1 < "$d/input"; /usr/bin/od -An -tx1 < "$d/input"; /usr/bin/od -An -tx1 < "$d/input"; } > "$d/gnu"
cat "$d/once" "$d/once" "$d/once" > "$d/want"
cmp -s "$d/gnu" "$d/want" && ok "GNU od -An -tx1 emits three copies" \
  || no "GNU od -An -tx1 did not emit three copies"
"$BX" -c 'PATH=; od -An -tx1 < "$1"; od -An -tx1 < "$1"; od -An -tx1 < "$1"' _ "$d/input" > "$d/got"
cmp -s "$d/got" "$d/gnu" && ok "three fresh od -An -tx1 redirections match GNU" \
  || no "repeat-input got $(od -An -tx1 "$d/got" | tr -s ' ') want $(od -An -tx1 "$d/gnu" | tr -s ' ')"

# A failed write is reported, as GNU od does, and does not leak into the next call.
if [[ -w /dev/full ]]; then
  "$BX" -c 'PATH=; od -An -tx1 "$1" > /dev/full; echo "status=$?" >&2; od -An -tx1 "$1" > "$2"' \
    _ "$d/input" "$d/after" 2> "$d/err"; rc=$?
  grep -q 'write error' "$d/err" && grep -q 'status=1' "$d/err" \
    && ok "od > /dev/full reports a write error and fails" || no "od > /dev/full: $(tr '\n' ' ' < "$d/err")"
  [[ $rc == 0 ]] && cmp -s "$d/after" "$d/once" && ok "the next od call writes normally" \
    || no "od after a failed write: exit $rc"
fi

echo "od-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
