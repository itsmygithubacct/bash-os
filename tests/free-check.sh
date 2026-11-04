#!/usr/bin/env bash
# tests/free-check.sh [BINARY] — free builtin against a meminfo fixture and free(1) headers
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t free 2>/dev/null) || t=
[[ $t == builtin ]] && ok "free is a builtin with empty PATH" || no "type -t free -> '$t'"

mkdir "$d/proc"
# Kernel order: Cached before SwapCached. Distinct MemTotal cannot be a live counter
# on this host (live totals are tens of millions of kB).
cat > "$d/proc/meminfo" <<'EOF'
MemTotal:       424242 kB
MemFree:         10000 kB
MemAvailable:    80000 kB
Buffers:          1111 kB
Cached:           2222 kB
SwapCached:      99999 kB
SwapTotal:       50000 kB
SwapFree:        40000 kB
Shmem:            3333 kB
SReclaimable:     4444 kB
EOF

out=$(BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; free -k')
hdr=$(printf '%s\n' "$out" | sed -n '1p')
mem=$(printf '%s\n' "$out" | sed -n '2p')
swp=$(printf '%s\n' "$out" | sed -n '3p')
read -r -a hf <<< "$hdr"
read -r _ mtot mused mfree mshared mbuff mavail <<< "$mem"
read -r _ stot sused sfree <<< "$swp"

[[ ${hf[0]} == total && ${hf[1]} == used && ${hf[2]} == free \
   && ${hf[3]} == shared && ${hf[4]} == buff/cache && ${hf[5]} == available ]] \
  && ok "default -k header columns" || no "header fields: ${hf[*]}"

[[ $mtot == 424242 ]] && ok "fixture MemTotal 424242" || no "Mem total '$mtot'"
[[ $mfree == 10000 ]] && ok "fixture MemFree 10000" || no "Mem free '$mfree'"
[[ $mavail == 80000 ]] && ok "fixture MemAvailable 80000" || no "Mem available '$mavail'"
[[ $mused == 344242 ]] && ok "used is total-available 344242" || no "Mem used '$mused'"
[[ $mshared == 3333 ]] && ok "fixture Shmem 3333" || no "Mem shared '$mshared'"
# GNU: Buffers+Cached+SReclaimable = 1111+2222+4444 = 7777. Old builtin
# subtracted Shmem (3333) and printed 4444.
[[ $mbuff == 7777 && $mbuff != 4444 ]] \
  && ok "buff/cache is GNU Buffers+Cached+SReclaimable, not Shmem-subtracted" \
  || no "buff/cache '$mbuff' (want 7777, not 4444)"
line=$(BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; free -k -L')
read -r _ _ _ cachuse _ _ _ memfree <<< "$line"
[[ $cachuse == 7777 ]] && ok "-L CachUse follows buff/cache" || no "-L CachUse '$cachuse' line '$line'"
[[ $stot == 50000 && $sused == 10000 && $sfree == 40000 ]] \
  && ok "fixture Swap columns" || no "Swap '$swp'"

deflt=$(BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; free')
[[ $deflt == "$out" ]] && ok "default unit is -k" || no "default differs from -k"

live=$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null || echo '')
if [[ -n $live && $live != 424242 ]]; then
  ok "fixture total is not the live MemTotal $live"
else
  no "could not discriminate fixture from live MemTotal '$live'"
fi

# Missing and zero availability use procps' free-memory fallback, even when
# buffers and cache are nonzero.  Put SwapCached first to catch substring keys.
cat > "$d/proc/meminfo" <<'EOF'
MemTotal: 100000 kB
MemFree: 10000 kB
Buffers: 1111 kB
SwapCached: 99999 kB
Cached: 2222 kB
SReclaimable: 4444 kB
SwapTotal: 50000 kB
SwapFree: 40000 kB
EOF
legacy=$(BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; free -k')
read -r _ _ legacy_used _ _ legacy_cache legacy_available <<< "$(printf '%s\n' "$legacy" | sed -n '2p')"
[[ $legacy_used == 90000 && $legacy_available == 10000 && $legacy_cache == 7777 ]] \
  && ok "missing MemAvailable and exact Cached key" || no "legacy fields: $legacy"
printf 'MemAvailable: 0 kB\n' >> "$d/proc/meminfo"
zero=$(BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; free -k')
[[ $zero == "$legacy" ]] && ok "zero MemAvailable uses fallback" || no "zero availability: $zero"
human=$(BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; free -h')
read -r _ human_total _ _ _ _ _ <<< "$(printf '%s\n' "$human" | sed -n '2p')"
[[ $human_total == 97Mi ]] && ok "human units use procps compact binary format" || no "human total '$human_total'"
BASHOS_PROC_ROOT=$d/proc "$BX" -c 'PATH=; free -c 2 -s 0.1' > "$d/repeat" 2> "$d/repeat.err"; rc=$?
[[ $rc == 0 && $(grep -c '^Mem:' "$d/repeat") == 2 ]] \
  && ok "fractional interval repeats twice" || no "fractional interval rc=$rc stderr=$(cat "$d/repeat.err")"

B free --help >"$d/help" 2>&1; rc=$?
[[ $rc == 0 && -s $d/help ]] && ok "--help exits 0 with usage" || no "--help rc=$rc out=$(cat "$d/help")"

B free -V >"$d/ver" 2>"$d/ver.err"; rc=$?
[[ $rc == 0 && -s $d/ver ]] && ok "-V exits 0 with version text" || no "-V rc=$rc out=$(cat "$d/ver") err=$(cat "$d/ver.err")"

B free extra >/dev/null 2>"$d/err"; rc=$?
[[ $rc != 0 && -s $d/err ]] && ok "extra operand fails with a diagnostic" || no "extra operand rc=$rc err=$(cat "$d/err")"

mkdir "$d/empty"
BASHOS_PROC_ROOT=$d/empty "$BX" -c 'PATH=; free -k' >/dev/null 2>"$d/miss"; rc=$?
[[ $rc != 0 ]] && grep -q meminfo "$d/miss" \
  && ok "missing meminfo fails with a diagnostic" \
  || no "missing meminfo rc=$rc err=$(cat "$d/miss")"

if [[ -x /usr/bin/free ]]; then
  bhdr=$(B free -k | sed -n '1p')
  ghdr=$(/usr/bin/free -k | sed -n '1p')
  [[ $bhdr == "$ghdr" ]] && ok "GNU free -k header line" || no "builtin hdr '$bhdr' gnu '$ghdr'"
  read -r -a gf <<< "$ghdr"
  [[ ${gf[0]} == total && ${gf[4]} == buff/cache && ${gf[5]} == available ]] \
    && ok "GNU free -k field names" || no "GNU fields: ${gf[*]}"
  blab=$(B free -k | awk 'NR>1{print $1}' | paste -sd' ' -)
  glab=$(/usr/bin/free -k | awk 'NR>1{print $1}' | paste -sd' ' -)
  [[ $blab == "$glab" && $blab == "Mem: Swap:" ]] \
    && ok "GNU free -k row labels" || no "builtin labels '$blab' gnu '$glab'"
else
  echo "  SKIP  GNU free -k header comparison (no /usr/bin/free)"
fi

echo "free-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
