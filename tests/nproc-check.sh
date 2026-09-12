#!/usr/bin/env bash
# tests/nproc-check.sh [BINARY] — `coreutils nproc` against GNU nproc(1)
#
# GNU's default counts the processors this process may RUN on (the affinity
# mask), not the online ones: under `taskset -c N` it prints 1 while
# _SC_NPROCESSORS_ONLN still reports every CPU. Only --all ignores affinity.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" --noprofile --norc -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t coreutils 2>/dev/null) || t=
[[ $t == builtin ]] && ok "coreutils is a builtin with empty PATH" || no "type -t coreutils -> '$t'"

GNU=/usr/bin/nproc
if [[ ! -x $GNU ]]; then
  echo "nproc-check: GNU nproc not installed; nothing to compare against"
  exit 0
fi

# Unpinned: builtin, GNU and --all should all agree on this host.
b=$(B coreutils nproc); g=$($GNU)
[[ $b == "$g" ]] && ok "unpinned matches GNU ($b)" || no "unpinned builtin '$b' gnu '$g'"

b=$(B coreutils nproc --all); g=$($GNU --all)
[[ $b == "$g" ]] && ok "--all matches GNU ($b)" || no "--all builtin '$b' gnu '$g'"

# The regression: pinned to one CPU, the default must follow the mask.
if command -v taskset >/dev/null 2>&1 && [[ $($GNU --all) -gt 1 ]]; then
  # Pin to CPUs drawn from this process's own mask, so the test works even
  # when the caller already pinned it.
  mask=$(taskset -cp $$ 2>/dev/null | sed 's/.*: *//')
  # The mask prints as a list of CPUs and ranges ("0-11", "0,2,5-7"); expand it
  # so a range still yields two distinct CPUs for the two-CPU case below.
  cpus=$(tr ',' '\n' <<<"$mask" | while read -r part; do
           case $part in
             *-*) seq "${part%%-*}" "${part##*-}" ;;
             ?*)  echo "$part" ;;
           esac
         done)
  cpu=$(head -1 <<<"$cpus"); cpu=${cpu:-0}
  b=$(taskset -c "$cpu" "$BX" --noprofile --norc -c 'PATH=; coreutils nproc')
  g=$(taskset -c "$cpu" $GNU)
  [[ $b == "$g" ]] && ok "pinned to one CPU matches GNU ($b)" \
    || no "pinned builtin '$b' gnu '$g' (default must count the affinity mask)"
  # --all deliberately ignores the mask, in both implementations.
  b=$(taskset -c "$cpu" "$BX" --noprofile --norc -c 'PATH=; coreutils nproc --all')
  g=$(taskset -c "$cpu" $GNU --all)
  [[ $b == "$g" ]] && ok "pinned --all still reports every CPU ($b)" \
    || no "pinned --all builtin '$b' gnu '$g'"

  # Two CPUs, to show it counts the mask rather than clamping to 1.
  second=$(sed -n 2p <<<"$cpus")
  if [[ -n ${second:-} && $second != "$cpu" ]]; then
    b=$(taskset -c "$cpu,$second" "$BX" --noprofile --norc -c 'PATH=; coreutils nproc')
    g=$(taskset -c "$cpu,$second" $GNU)
    [[ $b == "$g" ]] && ok "pinned to two CPUs matches GNU ($b)" \
      || no "two-CPU builtin '$b' gnu '$g'"
  fi
else
  echo "  SKIP  taskset unavailable or single-CPU host: affinity cases not run"
fi

# --ignore=N subtracts, floored at 1.
b=$(B coreutils nproc --ignore=1); g=$($GNU --ignore=1)
[[ $b == "$g" ]] && ok "--ignore=1 matches GNU ($b)" || no "--ignore=1 builtin '$b' gnu '$g'"
b=$(B coreutils nproc --ignore=100000); g=$($GNU --ignore=100000)
[[ $b == "$g" ]] && ok "--ignore over the count floors at GNU's value ($b)" \
  || no "--ignore=100000 builtin '$b' gnu '$g'"

# Repeated invocation in one shell: the builtin does not fork, so a cached
# count would show up here.
got=$("$BX" --noprofile --norc -c 'PATH=; for i in 1 2 3; do coreutils nproc; done' | sort -u | wc -l)
[[ $got == 1 ]] && ok "three invocations in one shell agree" || no "three invocations gave $got distinct values"

echo "nproc-check: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
