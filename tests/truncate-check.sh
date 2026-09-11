#!/usr/bin/env bash
# tests/truncate-check.sh [BINARY] — truncate overflow must not empty the file
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-truncate}")
[[ -x $BX ]] || { echo "truncate-check: missing binary $BX"; exit 1; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t truncate 2>/dev/null) || t=
[[ $t == builtin ]] && ok "truncate is a builtin with empty PATH" || no "type -t truncate -> '$t'"

# Published P1: overflow must fail and leave the three bytes alone.
printf abc > "$d/file"
B truncate -s +9223372036854775807 "$d/file" >/dev/null 2>"$d/ov.err"; rc=$?
got=$(cat "$d/file")
[[ $rc != 0 && $got == abc ]] && grep -qi overflow "$d/ov.err" \
  && ok "overflow +LLONG_MAX fails; file still abc" \
  || no "overflow rc=$rc bytes='$got' err=$(cat "$d/ov.err")"

if [[ -x /usr/bin/truncate ]]; then
  printf abc > "$d/gfile"
  /usr/bin/truncate -s +9223372036854775807 "$d/gfile" >/dev/null 2>"$d/gnu.err"; grc=$?
  ggot=$(cat "$d/gfile")
  [[ $grc != 0 && $ggot == abc ]] && grep -qi overflow "$d/gnu.err" \
    && ok "GNU overflow also fails and preserves abc" \
    || no "GNU overflow rc=$grc bytes='$ggot' err=$(cat "$d/gnu.err")"
  [[ $got == "$ggot" && $rc != 0 && $grc != 0 ]] \
    && ok "builtin overflow outcome matches GNU (fail, abc)" \
    || no "builtin bytes='$got' rc=$rc gnu bytes='$ggot' rc=$grc"
fi

# Shrink/grow GNU accepts.
printf abc > "$d/s"
B truncate -s 1 "$d/s" >/dev/null 2>"$d/e"; rc=$?
[[ $rc == 0 && $(cat "$d/s") == a ]] && ok "shrink -s 1 leaves a" || no "shrink -s 1 rc=$rc bytes='$(cat "$d/s")'"

printf abc > "$d/s"
B truncate -s 6 "$d/s" >/dev/null 2>"$d/e"; rc=$?
[[ $rc == 0 && $(wc -c < "$d/s") == 6 ]] && ok "grow -s 6 is 6 bytes" || no "grow -s 6 rc=$rc len=$(wc -c < "$d/s")"

printf abc > "$d/s"
B truncate -s +2 "$d/s" >/dev/null 2>"$d/e"; rc=$?
[[ $rc == 0 && $(wc -c < "$d/s") == 5 ]] && ok "relative +2 is 5 bytes" || no " +2 rc=$rc len=$(wc -c < "$d/s")"

printf abc > "$d/s"
B truncate -s -1 "$d/s" >/dev/null 2>"$d/e"; rc=$?
[[ $rc == 0 && $(cat "$d/s") == ab ]] && ok "relative -1 leaves ab" || no " -1 rc=$rc bytes='$(cat "$d/s")'"

printf abc > "$d/s"
B truncate -s -100 "$d/s" >/dev/null 2>"$d/e"; rc=$?
[[ $rc == 0 && ! -s $d/s ]] && ok "shrink past zero becomes empty" || no " -100 rc=$rc len=$(wc -c < "$d/s")"

# Reference size.
printf abcde > "$d/ref"
printf abc > "$d/s"
B truncate -r "$d/ref" "$d/s" >/dev/null 2>"$d/e"; rc=$?
[[ $rc == 0 && $(wc -c < "$d/s") == 5 ]] && ok "-r REF copies size 5" || no "-r rc=$rc len=$(wc -c < "$d/s")"

printf abcde > "$d/ref"
printf abc > "$d/s"
B truncate -r "$d/ref" -s +1 "$d/s" >/dev/null 2>"$d/e"; rc=$?
[[ $rc == 0 && $(wc -c < "$d/s") == 6 ]] && ok "-r REF -s +1 is 6 bytes" || no "-r +1 rc=$rc len=$(wc -c < "$d/s")"

printf abcde > "$d/ref"
printf abc > "$d/s"
B truncate -r "$d/ref" -s +9223372036854775807 "$d/s" >/dev/null 2>"$d/refo.err"; rc=$?
got=$(cat "$d/s")
[[ $rc != 0 && $got == abc ]] && grep -qi overflow "$d/refo.err" \
  && ok "-r overflow fails; file still abc" \
  || no "-r overflow rc=$rc bytes='$got' err=$(cat "$d/refo.err")"

B truncate --help >"$d/help" 2>&1; rc=$?
[[ $rc == 0 && -s $d/help ]] && ok "--help exits 0 with usage" || no "--help rc=$rc out=$(cat "$d/help")"

B truncate -s 1 >/dev/null 2>"$d/miss"; rc=$?
[[ $rc != 0 && -s $d/miss ]] && ok "missing file operand fails" || no "missing file rc=$rc err=$(cat "$d/miss")"

B truncate "$d/file" >/dev/null 2>"$d/nosize"; rc=$?
[[ $rc != 0 ]] && grep -q size "$d/nosize" \
  && ok "missing --size/--reference fails" \
  || no "no size rc=$rc err=$(cat "$d/nosize")"

# I/O error: cannot open a read-only file; contents unchanged.
printf abc > "$d/ro"
chmod a-w "$d/ro"
B truncate -s 1 "$d/ro" >/dev/null 2>"$d/ro.err"; rc=$?
chmod u+w "$d/ro"
got=$(cat "$d/ro")
[[ $rc != 0 && $got == abc ]] && grep -qi 'open\|denied\|write' "$d/ro.err" \
  && ok "read-only I/O error preserves abc" \
  || no "ro rc=$rc bytes='$got' err=$(cat "$d/ro.err")"

# Recovery: overflow on one file does not prevent a later successful shrink.
printf abc > "$d/bad"
printf xyz > "$d/good"
B truncate -s +9223372036854775807 "$d/bad" >/dev/null 2>"$d/rec.err"
B truncate -s 1 "$d/good" >/dev/null 2>"$d/rec2.err"; rc=$?
[[ $(cat "$d/bad") == abc && $rc == 0 && $(cat "$d/good") == x ]] \
  && ok "after overflow, a later shrink still works" \
  || no "recovery bad='$(cat "$d/bad")' good='$(cat "$d/good")' rc=$rc"

echo "truncate-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
