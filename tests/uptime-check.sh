#!/usr/bin/env bash
# tests/uptime-check.sh [BINARY] — uptime builtin against a proc fixture
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t uptime 2>/dev/null) || t=
[[ $t == builtin ]] && ok "uptime is a builtin with empty PATH" || no "type -t uptime -> '$t'"

mkdir "$d/proc"
# Distinctive btime: 1700000000 is 2023-11-14 22:13:20 UTC, not this host's boot.
printf '90061.00 10.00\n' > "$d/proc/uptime"
printf 'cpu 0\nbtime 1700000000\n' > "$d/proc/stat"
printf '0.01 0.02 0.03 1/2 3\n' > "$d/proc/loadavg"
want_s=$(date -d @1700000000 '+%Y-%m-%d %H:%M:%S')

got=$(BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; uptime -s')
[[ $got == "$want_s" ]] && ok "uptime -s matches fixture btime $want_s" \
  || no "uptime -s '$got' want '$want_s'"

live=$(B uptime -s 2>/dev/null) || live=
[[ -n $live && $got != "$live" ]] \
  && ok "fixture -s is not the live boot time $live" \
  || no "could not discriminate fixture -s from live '$live'"

gotp=$(BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; uptime -p')
[[ $gotp == 'up 1 day, 1 hour, 1 minute' ]] \
  && ok "uptime -p pretty from fixture 90061s" \
  || no "uptime -p '$gotp'"

BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; uptime' >"$d/def" 2>"$d/def.err"; rc=$?
[[ $rc == 0 && -s $d/def ]] && grep -q 'load average:' "$d/def" \
  && ok "default uptime exits 0 with load average" \
  || no "default rc=$rc out=$(cat "$d/def") err=$(cat "$d/def.err")"

B uptime --help >"$d/help" 2>&1; rc=$?
[[ $rc == 0 && -s $d/help ]] && ok "--help exits 0 with usage" \
  || no "--help rc=$rc out=$(cat "$d/help")"

B uptime -V >"$d/ver" 2>"$d/ver.err"; rc=$?
[[ $rc == 0 && -s $d/ver ]] && ok "-V exits 0 with version text" \
  || no "-V rc=$rc out=$(cat "$d/ver") err=$(cat "$d/ver.err")"

B uptime extra >/dev/null 2>"$d/err"; rc=$?
[[ $rc != 0 && -s $d/err ]] && ok "extra operand fails with a diagnostic" \
  || no "extra operand rc=$rc err=$(cat "$d/err")"

mkdir "$d/empty"
BASHOS_PROC_ROOT=$d/empty "$BX" -c 'PATH=; uptime' >/dev/null 2>"$d/miss"; rc=$?
[[ $rc != 0 ]] && grep -q uptime "$d/miss" \
  && ok "missing proc/uptime fails with a diagnostic" \
  || no "missing uptime rc=$rc err=$(cat "$d/miss")"

if [[ -x /usr/bin/uptime ]]; then
  g=$(/usr/bin/uptime -s)
  b=$(B uptime -s)
  [[ $b == "$g" ]] && ok "live uptime -s matches uptime(1): $g" \
    || no "live builtin '$b' gnu '$g'"
else
  echo "  SKIP  GNU uptime -s comparison (no /usr/bin/uptime)"
fi

echo "uptime-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
