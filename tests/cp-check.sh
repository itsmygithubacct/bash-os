#!/usr/bin/env bash
# tests/cp-check.sh [BINARY] — cp builtin: copy, link, metadata, failure recovery
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'chmod -R u+rwX "$d" 2>/dev/null; rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }
same(){ cmp -s "$1" "$2"; }

t=$(B type -t cp 2>/dev/null) || t=
[[ $t == builtin ]] && ok "cp is a builtin with empty PATH" || no "type -t cp -> '$t'"

# Copy
printf 'payload\n' > "$d/a"
B cp "$d/a" "$d/b"; rc=$?
[[ $rc == 0 ]] && same "$d/a" "$d/b" \
  && ok "copy writes dest and keeps source" || no "copy rc=$rc"

# Link: default clones a symlink as a symlink
printf 'via-link\n' > "$d/real"
ln -s real "$d/slink"
B cp "$d/slink" "$d/slink-copy"; rc=$?
if [[ $rc == 0 && -L $d/slink-copy && $(readlink "$d/slink-copy") == real ]]; then
  ok "copies a symlink as a symlink"
else
  no "symlink copy rc=$rc link=$(readlink "$d/slink-copy" 2>/dev/null)"
fi

# Metadata
printf 'meta\n' > "$d/msrc"
chmod 600 "$d/msrc"
B cp -p "$d/msrc" "$d/mdst"; rc=$?
smode=$(stat -c '%a' "$d/msrc")
dmode=$(stat -c '%a' "$d/mdst")
[[ $rc == 0 && $dmode == "$smode" && $dmode == 600 ]] && same "$d/msrc" "$d/mdst" \
  && ok "cp -p preserves mode $dmode" || no "cp -p rc=$rc srcmode=$smode destmode=$dmode"

# Readable -f overwrite succeeds
printf 'new\n' > "$d/src-ok"
printf 'old destination\n' > "$d/tgt-ok"
printf 'new\n' > "$d/want-new"
B cp -f "$d/src-ok" "$d/tgt-ok"; rc=$?
[[ $rc == 0 ]] && same "$d/tgt-ok" "$d/want-new" \
  && ok "readable -f overwrite succeeds" || no "-f overwrite rc=$rc"

# Failure recovery: unreadable source, -f must keep dest (the published P1)
printf 'source\n' > "$d/source"
printf 'old destination\n' > "$d/target"
printf 'old destination\n' > "$d/want-old"
chmod 000 "$d/source"
B cp -f "$d/source" "$d/target" >/dev/null 2>"$d/err"; rc=$?
chmod u+r "$d/source"
if [[ $rc != 0 && -e $d/target ]] && same "$d/target" "$d/want-old"; then
  ok "unreadable -f keeps dest"
else
  no "unreadable -f rc=$rc exists=$([[ -e $d/target ]] && echo yes || echo no) err=$(cat "$d/err")"
fi
grep -q 'Permission denied' "$d/err" && ok "unreadable -f diagnostic" || no "err=$(cat "$d/err")"

# Same fixture with GNU: dest kept
g=$(mktemp -d)
printf 'source\n' > "$g/source"
printf 'old destination\n' > "$g/target"
printf 'old destination\n' > "$g/want-old"
chmod 000 "$g/source"
/usr/bin/cp -f "$g/source" "$g/target" >/dev/null 2>"$g/err"; grc=$?
chmod u+r "$g/source"
if [[ $grc != 0 ]] && same "$g/target" "$g/want-old"; then
  ok "GNU unreadable -f keeps dest"
else
  no "GNU rc=$grc dest-exists=$([[ -e $g/target ]] && echo yes || echo no)"
fi
rm -rf "$g"

# Unreadable source without -f also leaves dest
printf 'source\n' > "$d/source2"
printf 'keep me\n' > "$d/target2"
printf 'keep me\n' > "$d/want-keep"
chmod 000 "$d/source2"
B cp "$d/source2" "$d/target2" >/dev/null 2>"$d/err2"; rc=$?
chmod u+r "$d/source2"
[[ $rc != 0 ]] && same "$d/target2" "$d/want-keep" \
  && ok "unreadable without -f keeps dest" || no "plain unreadable rc=$rc"

# Missing source, dest present
printf 'stay\n' > "$d/stay"
printf 'stay\n' > "$d/want-stay"
B cp "$d/no-such" "$d/stay" >/dev/null 2>"$d/miss"; rc=$?
[[ $rc != 0 ]] && same "$d/stay" "$d/want-stay" \
  && ok "missing source keeps dest" || no "missing source rc=$rc"

# Missing operand
B cp >/dev/null 2>"$d/op"; rc=$?
[[ $rc != 0 && -s $d/op ]] && ok "missing operand fails" || no "missing operand rc=$rc"
B cp "$d/a" >/dev/null 2>"$d/op2"; rc=$?
[[ $rc != 0 && -s $d/op2 ]] && ok "one operand fails" || no "one operand rc=$rc"

# -f replaces a dest symlink only after source is readable
printf 'fresh\n' > "$d/s3"
printf 'other\n' > "$d/other"
printf 'fresh\n' > "$d/want-fresh"
printf 'other\n' > "$d/want-other"
ln -sf other "$d/alias"
B cp -f "$d/s3" "$d/alias"; rc=$?
[[ $rc == 0 && ! -L $d/alias ]] && same "$d/alias" "$d/want-fresh" && same "$d/other" "$d/want-other" \
  && ok "-f replaces dest symlink, not its target" || no "symlink replace rc=$rc islink=$([[ -L $d/alias ]] && echo yes || echo no)"

echo "cp-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
