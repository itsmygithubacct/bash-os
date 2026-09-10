#!/usr/bin/env bash
# tests/timeout-check.sh [BINARY] — timeout builtin: statuses, duration 0, SIGCHLD
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-timeout}")
[[ -x $BX ]] || { echo "timeout-check: missing binary $BX"; exit 1; }
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }

# Empty PATH: timeout is the injected builtin. true/false/eval are Bash's.
# sleep is not in a timeout-only binary, so timed children use /bin/sleep.
status(){
  local want=$1 rc=0
  shift
  "$@" >/dev/null 2>&1 || rc=$?
  [[ $rc == "$want" ]]
}

if status 0 "$BX" -c 'PATH=; timeout 1 true'; then
  ok "timeout 1 true -> 0"
else
  no "timeout 1 true"
fi

if status 1 "$BX" -c 'PATH=; timeout 1 false'; then
  ok "timeout 1 false -> 1"
else
  no "timeout 1 false"
fi

if status 124 "$BX" -c 'PATH=; timeout .05 /bin/sleep 2'; then
  ok "timeout .05 sleep 2 -> 124"
else
  no "timeout .05 /bin/sleep 2"
fi

if status 7 "$BX" -c 'PATH=; timeout 1 eval "exit 7"'; then
  ok "timeout 1 eval exit 7 -> 7"
else
  no "timeout 1 eval exit 7"
fi

if status 9 "$BX" -c 'PATH=; timeout 0 eval "exit 9"'; then
  ok "timeout 0 runs the command (exit 9)"
else
  no "timeout 0 eval exit 9"
fi

if status 0 "$BX" -c 'PATH=; timeout 0 /bin/true'; then
  ok "timeout 0 true -> 0"
else
  no "timeout 0 /bin/true"
fi

# A duration-0 sleep must finish, not return 124.
zero=$("$BX" -c '
PATH=
t0=$EPOCHREALTIME
timeout 0 /bin/sleep 0.15
rc=$?
t1=$EPOCHREALTIME
printf "rc=%s t0=%s t1=%s\n" "$rc" "$t0" "$t1"
')
echo "  note  duration-0 probe: $zero"
zero_rc=$(printf '%s\n' "$zero" | sed -n 's/^rc=\([^ ]*\).*/\1/p')
zero_t0=$(printf '%s\n' "$zero" | sed -n 's/.* t0=\([^ ]*\).*/\1/p')
zero_t1=$(printf '%s\n' "$zero" | sed -n 's/.* t1=\([^ ]*\).*/\1/p')
if [[ $zero_rc == 0 ]] && python3 -c "import sys; sys.exit(0 if float('$zero_t1')-float('$zero_t0') >= 0.10 else 1)"; then
  ok "timeout 0 sleep waited for the child"
else
  no "timeout 0 /bin/sleep 0.15 ($zero)"
fi

# Background job exits while timeout waits. SIGCHLD must remain pending so
# Bash reaps it (jobs list / no zombie). timeout must still wait for its child.
# A CHLD trap firing alone is not enough: the timeout child can set the trap
# while the background sleep stays a zombie (pre-change behaviour).
chld_out=$("$BX" -c '
PATH=
chld=0
trap "chld=1" CHLD
t0=$EPOCHREALTIME
/bin/sleep 0.05 &
bg=$!
timeout 1 /bin/sleep 0.2
trc=$?
t1=$EPOCHREALTIME
if kill -0 "$bg" 2>/dev/null; then alive=1; else alive=0; fi
if [[ -r /proc/$bg/stat ]]; then
  read -r _ comm state rest < /proc/$bg/stat
else
  comm=missing
  state=gone
fi
jobs_out=$(jobs -l 2>/dev/null || true)
printf "trc=%s chld=%s alive=%s state=%s t0=%s t1=%s jobs=%s\n" \
  "$trc" "$chld" "$alive" "$state" "$t0" "$t1" "$jobs_out"
')
echo "  note  SIGCHLD probe: $chld_out"
trc=$(printf '%s\n' "$chld_out" | sed -n 's/^trc=\([^ ]*\).*/\1/p')
chld=$(printf '%s\n' "$chld_out" | sed -n 's/.* chld=\([^ ]*\).*/\1/p')
alive=$(printf '%s\n' "$chld_out" | sed -n 's/.* alive=\([^ ]*\).*/\1/p')
state=$(printf '%s\n' "$chld_out" | sed -n 's/.* state=\([^ ]*\).*/\1/p')
t0=$(printf '%s\n' "$chld_out" | sed -n 's/.* t0=\([^ ]*\).*/\1/p')
t1=$(printf '%s\n' "$chld_out" | sed -n 's/.* t1=\([^ ]*\).*/\1/p')
jobs=$(printf '%s\n' "$chld_out" | sed -n 's/.* jobs=//p')
waited=1
python3 -c "import sys; sys.exit(0 if float('$t1')-float('$t0') >= 0.15 else 1)" 2>/dev/null && waited=0
# Process gone and not still Running. A Done notification may remain in jobs.
reaped=1
if [[ $alive == 0 && $state == gone && $jobs != *Running* ]]; then
  reaped=0
fi
if [[ $trc == 0 && $waited == 0 && $reaped == 0 ]]; then
  ok "bg job reaped (trap=$chld); timeout waited for its child"
else
  no "SIGCHLD swallowed or timeout did not wait (trc=$trc chld=$chld alive=$alive state=$state jobs=$jobs waited=$waited)"
fi

echo "timeout-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
