#!/usr/bin/env bash
# bench/run.sh — the same POSIX scripts under three userlands, timed:
#   bashos   bash-os, PATH empty: every command is a builtin of the shell
#   busybox  busybox sh with its applets on PATH (the classic embedded userland)
#   gnu      bash with the system's coreutils, grep, sed … as external commands
#
# Usage: bench/run.sh [--runs N] [--static] [--busybox BIN] [--only PATTERN] [--quick]
#   --runs N       timed runs per cell, median reported (default 5)
#   --static       bench out/bash-static instead of out/bash
#   --busybox BIN  a busybox binary (default: the one on PATH)
#   --only PAT     workloads whose file name matches PAT
#   --quick        one run, small data (a smoke test)
# Needs: a built bash-os, a busybox, python3 (to generate data). Nothing else.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
RUNS=5; BOS=out/bash; BB=$(command -v busybox || true); ONLY=""; QUICK=0
while [[ $# -gt 0 ]]; do case "$1" in
  --runs) RUNS=$2; shift 2 ;; --static) BOS=out/bash-static; shift ;; --busybox) BB=$2; shift 2 ;;
  --only) ONLY=$2; shift 2 ;; --quick) QUICK=1; RUNS=1; shift ;; *) echo "bench: unknown arg $1" >&2; exit 2 ;;
esac; done
[[ -x $BOS ]] || { echo "bench: build first: ./build.sh${BOS/out\/bash-static/ --static}" >&2; exit 1; }
[[ -n $BB && -x $BB ]] || { echo "bench: no busybox (install one or pass --busybox BIN)" >&2; exit 1; }
GNUSH=$(command -v bash); GNUPATH=$(getconf PATH 2>/dev/null || echo /usr/bin:/bin)

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir -p "$W/bb" "$W/data" "$W/out"
"$BB" --install -s "$W/bb" 2>/dev/null || for a in $("$BB" --list); do ln -s "$BB" "$W/bb/$a"; done
[[ -e $W/bb/sh ]] || ln -s "$BB" "$W/bb/sh"
QUICK=$QUICK python3 - "$W/data" <<'PY'
import os, random, sys
d = sys.argv[1]; r = random.Random(20260906); q = os.environ.get("QUICK") == "1"
words = ["the","of","and","to","in","a","is","that","for","it","as","was","with","be","by","on","not","he","i","this",
         "are","or","his","from","at","which","but","have","an","had","they","you","were","their","one","all","we","can","her","has"]
lines = []; size = 0
while size < (60_000 if q else 423_000):
    l = " ".join(r.choice(words) + ("" if r.random() < .9 else str(r.randint(0, 99))) for _ in range(r.randint(3, 12))); lines.append(l); size += len(l) + 1
open(f"{d}/words.txt", "w").write("\n".join(lines) + "\n")
open(f"{d}/log.txt", "w").write("".join(f"2026-09-06T10:{i%60:02d}:{i%60:02d} host svc[{1000+i}]: event {i} status={'ok' if i%7 else 'fail'}\n" for i in range(1500 if not q else 300)))
os.makedirs(f"{d}/files", exist_ok=True)
for i in range(1000 if not q else 100): open(f"{d}/files/f{i:04d}.txt", "w").write(f"file {i}\n" * (i % 5 + 1))
PY
N=1000; [[ $QUICK == 1 ]] && N=100

# --- the three userlands: name, shell, PATH
declare -A SH=([bashos]="$HERE/$BOS" [busybox]="$W/bb/sh" [gnu]="$GNUSH")
declare -A P=([bashos]="" [busybox]="$W/bb" [gnu]="$GNUPATH")
CFGS=(bashos busybox gnu)

# --- one timed run: real/user/sys seconds and the processes created meanwhile
# (kernel last-pid delta: system-wide, so run on a quiet machine; a small
# constant of the harness's own processes is included in every cell)
t_run() { # cfg workload -> "real user sys pids"
  local cfg=$1 wl=$2 p0 p1 tf="$W/tf"
  p0=$(cat /proc/sys/kernel/ns_last_pid)
  TIMEFORMAT='%3R %3U %3S'
  { time PATH="${P[$cfg]}" "${SH[$cfg]}" "$wl" "$W/data" "${SH[$cfg]}" "$N" > "$W/out/$cfg.txt" 2> "$W/out/$cfg.err"; } 2> "$tf"
  local rc=$?
  p1=$(cat /proc/sys/kernel/ns_last_pid)
  echo "$(cat "$tf") $(( p1 - p0 ))"
  return "$rc"
}
median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print (NR%2) ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2}'; }

echo "# bash-os bench — $(date -u +%F) — $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//'), $(uname -m), kernel $(uname -r)"
echo "# bashos: $BOS ($("$HERE/$BOS" -c 'echo $BASH_VERSION'))  busybox: $("$BB" 2>&1 | head -1 | cut -d' ' -f1-2)  gnu: bash $($GNUSH -c 'echo $BASH_VERSION'), coreutils $(ls --version | head -1 | grep -oE '[0-9.]+$')"
echo "# $RUNS timed run(s) per cell after a warm-up; median wall ms; procs = processes created during the run (system-wide pid delta)"
echo
printf '| %-26s | %9s | %9s | %9s | %8s | %8s | %-18s |\n' "workload" "bashos ms" "busybox ms" "gnu ms" "bb/bos" "gnu/bos" "procs bos/bb/gnu"
printf '|%s|%s|%s|%s|%s|%s|%s|\n' "$(printf '%.0s-' {1..28})" "$(printf '%.0s-' {1..11})" "$(printf '%.0s-' {1..11})" "$(printf '%.0s-' {1..11})" "$(printf '%.0s-' {1..10})" "$(printf '%.0s-' {1..10})" "$(printf '%.0s-' {1..20})"
declare -A MS PR
mismatch=""; failed=0
for wl in bench/workloads/*.sh; do
  name=$(basename "$wl" .sh); [[ -n $ONLY && $name != *$ONLY* ]] && continue
  skip=""
  for cfg in "${CFGS[@]}"; do
    MS[$cfg]="n/a"; PR[$cfg]="-"
    if grep -q '\${ wc' "$wl" && ! "${SH[$cfg]}" -c 'x=${ echo hi; }' >/dev/null 2>&1; then skip+="$cfg "; continue; fi
    t_run "$cfg" "$wl" >/dev/null || failed=1
    if [[ -s "$W/out/$cfg.err" ]]; then echo "# $name/$cfg stderr: $(head -c 200 "$W/out/$cfg.err" | tr '\n' ' ')"; fi
    reals=(); pids=()
    for ((r = 0; r < RUNS; r++)); do
      timing=$(t_run "$cfg" "$wl") || failed=1
      read -r re us sy pd <<< "$timing"
      reals+=("$re"); pids+=("$pd")
    done
    MS[$cfg]=$(median "${reals[@]}" | awk '{printf "%.0f", $1*1000}'); PR[$cfg]=$(median "${pids[@]}" | awk '{printf "%d", $1}')
  done
  flag=""
  for cfg in busybox gnu; do [[ " $skip " == *" $cfg "* ]] && continue; cmp -s "$W/out/bashos.txt" "$W/out/$cfg.txt" || flag="*"; done
  [[ -n $flag ]] && mismatch+="$name "
  printf '| %-26s | %9s | %9s | %9s | %8s | %8s | %-18s |\n' "$name$flag" "${MS[bashos]}" "${MS[busybox]}" "${MS[gnu]}" \
    "$(awk -v a="${MS[busybox]}" -v b="${MS[bashos]}" 'BEGIN{printf (a+0>0&&b+0>0)?"%.2fx":"-", a/b}')" "$(awk -v a="${MS[gnu]}" -v b="${MS[bashos]}" 'BEGIN{printf (a+0>0&&b+0>0)?"%.2fx":"-", a/b}')" \
    "${PR[bashos]}/${PR[busybox]}/${PR[gnu]}"
done
[[ -n $mismatch ]] && echo "# * outputs differed between userlands for: $mismatch(see the workload; a format or option difference, not a timing one)"

# --- footprint: bytes on disk for the shell plus every command the workloads use
CMDS="basename dirname wc grep sort uniq head tail tr cut sed mkdir touch cp mv ls find du rm stat ps df date uname hostname cat seq true"
gnu_bytes=$( { readlink -f "$GNUSH"; for c in $CMDS; do PATH=$GNUPATH type -P "$c" 2>/dev/null | xargs -r readlink -f; done; } | sort -u | xargs -r stat -c %s | awk '{s+=$1} END{print s+0}')
echo; echo "| footprint (shell + the commands above, on disk) | bytes |"; echo "|---|---|"
printf '| bashos: %s (%s) | %s |\n' "$BOS" "$(file "$HERE/$BOS" | grep -oE 'statically linked|dynamically linked')" "$(stat -c %s "$HERE/$BOS")"
printf '| busybox: %s (%s) | %s |\n' "$BB" "$(file "$BB" | grep -oE 'statically linked|dynamically linked')" "$(stat -c %s "$BB")"
printf '| gnu: bash + %s separate binaries | %s |\n' "$(echo $CMDS | wc -w)" "$gnu_bytes"
[[ -z $mismatch && $failed == 0 ]]
