#!/usr/bin/env bash
# tests/col-newline-check.sh [BINARY] — col output termination against util-linux col(1)
#
# util-linux col terminates its output: an input whose last line has no newline
# still gets one. Empty input produces nothing. The builtin used to pass the
# input's final bytes through unchanged, which made it one byte short on any
# unterminated input -- the difference that kept col's large text fixture out of
# the benchmark. It has nothing to do with the locale.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
GNU=/usr/bin/col

t=$("$BX" --noprofile --norc -c 'PATH=; type -t col' 2>/dev/null) || t=
[[ $t == builtin ]] && ok "col is a builtin with empty PATH" || no "type -t col -> '$t'"

cd "$d"
printf 'alpha\nbeta\n'          > terminated
printf 'alpha\nbeta'            > unterminated
: > emptyfile
printf 'a\bb\nc'                > overstrike
printf '\n'                     > justnewline
awk 'BEGIN{for(i=0;i<5000;i++)printf "word-%04d line\n", i}' > big
printf %s "$(cat big)"          > bigunterminated   # same, minus the final newline

if [[ ! -x $GNU ]]; then
  echo "col-newline-check: util-linux col not installed; nothing to compare against"
  exit 0
fi

cmp_case(){ # cmp_case LABEL FIXTURE [FLAGS...]
  local label=$1 fixture=$2; shift 2
  local b g
  b=$("$BX" --noprofile --norc -c 'PATH=; col "$@" < "$0"' "$fixture" "$@" | od -An -c | tr -s ' ')
  g=$(LC_ALL=C $GNU "$@" < "$fixture" | od -An -c | tr -s ' ')
  [[ $b == "$g" ]] && ok "$label matches util-linux" \
    || no "$label: builtin [$b] util-linux [$g]"
}

for flags in "" "-b"; do
  suffix=${flags:+ $flags}
  # shellcheck disable=SC2086
  cmp_case "terminated input$suffix"    terminated    $flags
  # shellcheck disable=SC2086
  cmp_case "unterminated input$suffix"  unterminated  $flags
  # shellcheck disable=SC2086
  cmp_case "empty input$suffix"         emptyfile     $flags
  # shellcheck disable=SC2086
  cmp_case "a single newline$suffix"    justnewline   $flags
  # shellcheck disable=SC2086
  cmp_case "overstrike, unterminated$suffix" overstrike $flags
done

# The fixture shape that the benchmark uses: a large body whose last line is
# unterminated because the generator truncated it to a byte count.
b=$("$BX" --noprofile --norc -c 'PATH=; col -b < bigunterminated' | wc -c)
g=$(LC_ALL=C $GNU -b < bigunterminated | wc -c)
[[ $b == "$g" ]] && ok "large unterminated fixture matches byte count ($b)" \
  || no "large fixture: builtin $b bytes, util-linux $g bytes"

# File operands are a bash-os extension: util-linux col reads only stdin and
# rejects an operand ("col: bad usage"). So there is no reference for this path,
# and the check is internal consistency -- two unterminated operands must gain
# exactly one newline in total, not one per operand.
two=$("$BX" --noprofile --norc -c 'PATH=; col -b unterminated unterminated' | wc -c)
one=$("$BX" --noprofile --norc -c 'PATH=; col -b unterminated' | wc -c)
raw=$(wc -c < unterminated)
# one pass = raw + 1 newline; two operands = 2*raw + 1 newline.
[[ $two -eq $((2 * raw + 1)) && $one -eq $((raw + 1)) ]] \
  && ok "two operands gain one newline in total ($two bytes for 2x$raw)" \
  || no "two operands: got $two bytes, expected $((2 * raw + 1)) (one pass $one, raw $raw)"
if LC_ALL=C $GNU -b unterminated >/dev/null 2>&1; then
  no "util-linux col accepted a file operand; the extension note above is stale"
else
  ok "util-linux col rejects a file operand, so that path has no reference"
fi

# Repeated invocation in one shell, the no-fork path.
b=$("$BX" --noprofile --norc -c 'PATH=; for i in 1 2 3; do col -b < unterminated; done' | wc -c)
one=$("$BX" --noprofile --norc -c 'PATH=; col -b < unterminated' | wc -c)
[[ $b -eq $((one * 3)) ]] && ok "three invocations emit 3x one pass ($b bytes)" \
  || no "three invocations emitted $b, expected $((one * 3))"

echo "col-newline-check: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
