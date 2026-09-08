#!/usr/bin/env bash
# tests/util-linux-smoke.sh [BINARY] — the util-linux family imported from the
# upstream collection: every one is a builtin with help text, and the ones that
# can act without privilege or destroying anything are exercised, against the
# host's util-linux where it is installed. Nothing here writes to a block
# device, a swap area or a filesystem signature.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX=$(readlink -f "${1:-$HERE/out/bash}")
TOOLS="flock setsid ionice blockdev ipcmk ipcctl chattr lsattr mkswap swapon swapoff wipefs
       fincore fsfreeze losetup dmsetup getfacl setfacl fstrim prlimit hwclock renice taskset
       chrt uclampset"
pass=0; fail=0; ok(){ echo "  PASS  $*"; pass=$((pass+1)); }; no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; printf 'data\n' > "$d/f"

echo "== all present as builtins, with help text =="
nb=0; nh=0
for t in $TOOLS; do
  [[ "$("$BX" -c "type -t $t" 2>/dev/null)" == builtin ]] || { echo "    not a builtin: $t"; nb=$((nb+1)); }
  "$BX" -c "help $t" >/dev/null 2>&1 || { echo "    no help: $t"; nh=$((nh+1)); }
done
[[ $nb == 0 ]] && ok "$(echo $TOOLS | wc -w) tools are builtins" || no "$nb are not builtins"
[[ $nh == 0 ]] && ok "all have help text" || no "$nh lack help text"

echo "== they run: locking, sessions, scheduling, queries =="
[[ "$(B flock -x "$d/f" -c 'echo held')" == held ]] && ok "flock FILE -c CMD" || no "flock -c"
[[ "$("$BX" -c "PATH=; exec 9>$d/lk; flock -x 9 && echo fd-held")" == fd-held ]] && ok "flock on an open fd (the builtin-only idiom)" || no "flock fd"
[[ "$(B setsid true; echo $?)" == 0 ]] && ok "setsid" || no "setsid"
B taskset -p $$ 2>/dev/null | grep -q 'current affinity mask' && ok "taskset -p" || no "taskset -p"
B chrt -p $$ 2>/dev/null | grep -q 'scheduling policy' && ok "chrt -p" || no "chrt -p"
B uclampset -p $$ 2>/dev/null | grep -q 'util_clamp' && ok "uclampset -p" || no "uclampset -p"
B prlimit --pid $$ 2>/dev/null | grep -q . && ok "prlimit --pid" || no "prlimit"
B renice 1 $$ >/dev/null 2>&1 && ok "renice" || no "renice"
B fincore "$d/f" 2>/dev/null | grep -qi 'file' && ok "fincore" || no "fincore"
B lsattr "$d/f" 2>/dev/null | grep -q "$d/f" && ok "lsattr" || no "lsattr"
B getfacl "$d/f" 2>/dev/null | grep -q '^# owner:' && ok "getfacl" || no "getfacl"
B losetup 2>/dev/null | grep -qi 'NAME' && ok "losetup (list)" || no "losetup list"
B swapon 2>/dev/null | grep -qi 'filename' && ok "swapon (list)" || no "swapon list"
B dmsetup version 2>/dev/null | grep -qi 'version' && ok "dmsetup version" || no "dmsetup version"
for t in blockdev wipefs fsfreeze fstrim hwclock ipcctl; do
  B $t --help >/dev/null 2>&1 && ok "$t --help" || no "$t --help"
done
for t in mkswap chattr; do
  B $t >/dev/null 2>&1 && no "$t with no argument should fail" || ok "$t with no argument fails cleanly"
done

echo "== parity with the host's util-linux, where installed =="
n=0
for probe in "ionice -p $$" "taskset -p $$" "chrt -p $$"; do
  set -- $probe; command -v "$1" >/dev/null || continue
  # the pid differs between the two runs, so compare with it removed
  a=$(eval "$probe" 2>&1 | sed -E 's/[0-9]+/N/g'); b=$(B $probe 2>&1 | sed -E 's/[0-9]+/N/g')
  # Older util-linux omits SCHED_OTHER's runtime even when sched_getattr
  # supplies it. Keep comparing that field when the host reports it.
  if [[ $1 == chrt && $a != *'current runtime parameter:'* ]]; then
    b=$(printf '%s\n' "$b" | sed "/^pid N's current runtime parameter: N$/d")
  fi
  n=$((n+1)); [[ "$a" == "$b" ]] && ok "$1 output matches util-linux" || { no "$1 differs"; echo "      host: $a"; echo "      ours: $b"; }
done
[[ $n == 0 ]] && echo "  (no host util-linux to compare against)"

echo; echo "util-linux-smoke: $pass passed, $fail failed"; exit $(( fail>0 ? 1 : 0 ))
