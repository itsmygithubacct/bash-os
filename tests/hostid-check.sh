#!/usr/bin/env bash
# tests/hostid-check.sh [BINARY] — hostid builtin against hostid(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
command -v hostid >/dev/null || { echo "hostid-check: SKIP (no host hostid)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

want=$(/usr/bin/hostid)
got=$(B hostid) && [[ $got == "$want" ]] && ok "matches hostid(1): $got" || no "builtin '$got' gnu '$want'"

printf '0123abcd\n' > "$d/id"
got=$(BASHHOSTID_MACHINE_ID_PATH=$d/id "$BX" -c 'PATH=; hostid')
[[ $got == 0123abcd ]] && ok "override file of eight hex digits" || no "override '$got'"

printf 'xyz\n' > "$d/bad"
got=$(BASHHOSTID_MACHINE_ID_PATH=$d/bad "$BX" -c 'PATH=; hostid')
[[ $got == "$want" ]] && ok "invalid override falls back to gethostid" || no "bad override '$got'"

B hostid extra >/dev/null 2>"$d/err"; rc=$?
[[ $rc != 0 && -s $d/err ]] && ok "extra operand fails with a diagnostic" || no "extra operand rc=$rc err=$(cat "$d/err")"

if [[ -r /etc/machine-id ]]; then
  mid=$(head -c 8 /etc/machine-id | tr 'A-F' 'a-f')
  got=$(B hostid)
  if [[ $mid == "$want" ]]; then
    ok "machine-id prefix coincides with gethostid; default still matches hostid(1)"
  elif [[ $got != "$mid" ]]; then
    ok "default is gethostid, not the machine-id prefix"
  else
    no "default still prints machine-id prefix $mid"
  fi
fi

echo "hostid-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
