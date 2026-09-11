#!/usr/bin/env bash
# tests/tee-check.sh [BINARY] — stock tee builtin: closed-stdin read error
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

"$BX" -c 'PATH=; tee <&- > /dev/null' >"$d/out" 2>"$d/err"; rc=$?
[[ $rc != 0 ]] && ok "closed stdin returns $rc" || no "closed stdin rc=$rc (want non-zero) err=$(cat "$d/err")"

/usr/bin/tee <&- > /dev/null 2>"$d/gnu.err"; grc=$?
[[ $grc != 0 ]] && ok "GNU tee closed stdin returns $grc" || no "GNU tee closed stdin rc=$grc err=$(cat "$d/gnu.err")"

echo "tee-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
