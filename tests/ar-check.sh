#!/usr/bin/env bash
# tests/ar-check.sh [BINARY] — truncated header, extract cleanup, archive links
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
[[ -x $BX ]] || { echo "ar-check: missing binary $BX"; exit 1; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }
# Run the builtin with cwd in the scratch dir so ar x writes stay there.
C(){
  local cmd=$1; shift
  "$BX" -c 'PATH=; cd "$1"; shift; eval "$1"' _ "$d" "$cmd"
}
GNU=/usr/bin/ar

t=$(B type -t ar 2>/dev/null) || t=
[[ $t == builtin ]] && ok "ar is a builtin with empty PATH" || no "type -t ar -> '$t'"

printf '%s' '!<arch>
X' > "$d/partial.a"
B ar t "$d/partial.a" >/dev/null 2>"$d/err"; rc=$?
if [[ $rc != 0 ]]; then
  ok "ar t partial.a fails"
else
  no "ar truncated header rc=$rc err=$(cat "$d/err")"
fi
if [[ -x $GNU ]]; then
  "$GNU" t "$d/partial.a" >/dev/null 2>"$d/gerr"; grc=$?
  [[ $grc != 0 ]] && ok "GNU ar t partial.a fails" || no "GNU rc=$grc"
fi

B ar --help >"$d/help" 2>&1; rc=$?
[[ $rc == 0 && -s $d/help ]] && ok "--help exits 0 with usage" \
  || no "--help rc=$rc out=$(cat "$d/help")"

# --- extract: member name is an existing directory ---
printf 'body\n' > "$d/mem.txt"
( cd "$d" && "$GNU" rcs dir.a mem.txt )
mv "$d/mem.txt" "$d/mem.txt.bak"
mkdir "$d/mem.txt"
C 'ar x dir.a' >/dev/null 2>"$d/xdir.err"; rc=$?
[[ $rc != 0 && -d $d/mem.txt ]] && ok "ar x onto a directory fails; directory remains" \
  || no "x-dir rc=$rc dir=$(ls -ld "$d/mem.txt" 2>&1) err=$(cat "$d/xdir.err")"
if [[ -x $GNU ]]; then
  ( cd "$d" && "$GNU" x dir.a ) >/dev/null 2>"$d/gxdir.err"; grc=$?
  [[ $grc != 0 && -d $d/mem.txt ]] && ok "GNU ar x onto a directory fails" \
    || no "GNU x-dir rc=$grc"
fi
rmdir "$d/mem.txt"
mv "$d/mem.txt.bak" "$d/mem.txt"

fdlog=$("$BX" -c '
PATH=
cd "$1"
/bin/rm -f mem.txt
/bin/mkdir mem.txt
# ls/wc are not in an ar-only binary; count /proc fds with the shell.
set -- /proc/$$/fd/*
b=$#
i=0
while [[ $i -lt 5 ]]; do
  ar x dir.a >/dev/null
  i=$((i+1))
done
set -- /proc/$$/fd/*
a=$#
printf "before=%s after=%s\n" "$b" "$a"
' _ "$d" 2>"$d/fd.err")
before=${fdlog#before=}; before=${before%% after=*}; after=${fdlog##*after=}
[[ -n $before && $before == "$after" ]] && ok "failed ar x onto a directory leaks no fds ($before)" \
  || no "fd leak '$fdlog' err=$(cat "$d/fd.err")"

# --- ar r through a symlink archive: symlink remains, target rewritten ---
printf 'one\n' > "$d/one.txt"
cp "$d/dir.a" "$d/real.a"
ln -s real.a "$d/link.a"
ino_before=$(stat -c '%i' "$d/real.a")
C 'ar r link.a one.txt' >/dev/null 2>"$d/rsym.err"; rc=$?
ino_after=$(stat -c '%i' "$d/real.a")
[[ $rc == 0 && -L $d/link.a && $(readlink "$d/link.a") == real.a && $ino_before == "$ino_after" ]] \
  && ok "ar r via symlink keeps the symlink and target inode" \
  || no "r-sym rc=$rc link=$(ls -l "$d/link.a") ino $ino_before->$ino_after err=$(cat "$d/rsym.err")"
if [[ -x $GNU ]]; then
  cp "$d/dir.a" "$d/greal.a"
  ln -s greal.a "$d/glink.a"
  gino_b=$(stat -c '%i' "$d/greal.a")
  ( cd "$d" && "$GNU" r glink.a one.txt ) >/dev/null
  gino_a=$(stat -c '%i' "$d/greal.a")
  [[ -L $d/glink.a && $gino_b == "$gino_a" ]] && ok "GNU ar r via symlink keeps link and inode" \
    || no "GNU r-sym ino $gino_b->$gino_a"
fi

# --- ar r through a hard link: same inode kept ---
cp "$d/dir.a" "$d/hard1.a"
ln "$d/hard1.a" "$d/hard2.a"
hino=$(stat -c '%i' "$d/hard1.a")
hn=$(stat -c '%h' "$d/hard1.a")
C 'ar r hard2.a one.txt' >/dev/null 2>"$d/rhard.err"; rc=$?
hino2=$(stat -c '%i' "$d/hard1.a")
hn2=$(stat -c '%h' "$d/hard1.a")
[[ $rc == 0 && $hino == "$hino2" && $hn == 2 && $hn2 == 2 ]] \
  && ok "ar r via hard link keeps nlink=2 and the same inode" \
  || no "r-hard rc=$rc ino $hino->$hino2 nlink $hn->$hn2 err=$(cat "$d/rhard.err")"
if [[ -x $GNU ]]; then
  cp "$d/dir.a" "$d/ghard1.a"
  ln "$d/ghard1.a" "$d/ghard2.a"
  ( cd "$d" && "$GNU" r ghard2.a one.txt ) >/dev/null
  [[ $(stat -c '%h' "$d/ghard1.a") == 2 && $(stat -c '%i' "$d/ghard1.a") == $(stat -c '%i' "$d/ghard2.a") ]] \
    && ok "GNU ar r via hard link keeps nlink=2" \
    || no "GNU r-hard nlink=$(stat -c '%h' "$d/ghard1.a")"
fi

# --- ar x over an existing symlink member name: follow and overwrite target ---
mkdir "$d/xsym"
printf 'payload-bytes\n' > "$d/xsym/payload"
( cd "$d/xsym" && "$GNU" rcs xsym.a payload )
rm -f "$d/xsym/payload"
printf 'OLDDEST' > "$d/xsym/target.dat"
ln -s target.dat "$d/xsym/payload"
"$BX" -c 'PATH=; cd "$1"; ar x xsym.a' _ "$d/xsym" >/dev/null 2>"$d/xsym.err"; rc=$?
[[ $rc == 0 && -L $d/xsym/payload && $(readlink "$d/xsym/payload") == target.dat \
   && $(cat "$d/xsym/target.dat") == payload-bytes ]] \
  && ok "ar x over a symlink follows and overwrites the target" \
  || no "x-sym rc=$rc link=$(ls -l "$d/xsym/payload") target=$(cat "$d/xsym/target.dat" 2>/dev/null) err=$(cat "$d/xsym.err")"
if [[ -x $GNU ]]; then
  rm -f "$d/xsym/payload"
  printf 'OLDDEST' > "$d/xsym/target.dat"
  ln -s target.dat "$d/xsym/payload"
  ( cd "$d/xsym" && "$GNU" x xsym.a )
  [[ -L $d/xsym/payload && $(cat "$d/xsym/target.dat") == payload-bytes ]] \
    && ok "GNU ar x over a symlink follows and overwrites the target" \
    || no "GNU x-sym target=$(cat "$d/xsym/target.dat" 2>/dev/null)"
fi

# --- extract write error: member larger than stdio buffer onto /dev/full ---
python3 -c 'open("'"$d"'/big","wb").write(b"B"*8192)'
( cd "$d" && "$GNU" rcs full.a big )
rm -f "$d/big"
ln -s /dev/full "$d/big"
C 'ar x full.a' >/dev/null 2>"$d/full.err"; rc=$?
# GNU unlinks the dest name after a write error (the symlink is gone).
[[ $rc != 0 && ! -e $d/big ]] && grep -qi 'space\|write\|device' "$d/full.err" \
  && ok "ar x onto /dev/full fails; dest unlinked as GNU does" \
  || no "x-full rc=$rc leftover=$(ls -l "$d/big" 2>&1) err=$(cat "$d/full.err")"
if [[ -x $GNU ]]; then
  rm -f "$d/big"
  ln -s /dev/full "$d/big"
  ( cd "$d" && "$GNU" x full.a ) >/dev/null 2>"$d/gfull.err"; grc=$?
  [[ $grc != 0 && ! -e $d/big ]] && ok "GNU ar x onto /dev/full fails and unlinks dest" \
    || no "GNU x-full rc=$grc leftover=$(ls -l "$d/big" 2>&1) err=$(cat "$d/gfull.err")"
fi

# --- short member body: GNU rejects extract; dest must not appear ---
python3 -c '
name="short/".ljust(16)
hdr=name+"0".ljust(12)+"0".ljust(6)+"0".ljust(6)+"100644  "+"100".ljust(10)+"`\n"
open("'"$d"'/short.a","wb").write(b"!<arch>\n"+hdr.encode()+b"abc")
'
rm -f "$d/short"
C 'ar x short.a' >/dev/null 2>"$d/short.err"; rc=$?
[[ $rc != 0 && ! -e $d/short ]] && ok "ar x short member body fails; no dest file" \
  || no "short-x rc=$rc exists=$(ls -l "$d/short" 2>&1) err=$(cat "$d/short.err")"
printf 'EXISTING' > "$d/short"
C 'ar x short.a' >/dev/null 2>"$d/short2.err"; rc=$?
got=$(cat "$d/short")
[[ $rc != 0 && $got == EXISTING ]] && ok "ar x short body leaves an existing dest alone" \
  || no "short-exist rc=$rc bytes='$got'"
if [[ -x $GNU ]]; then
  rm -f "$d/short"
  ( cd "$d" && "$GNU" x short.a ) >/dev/null 2>"$d/gshort.err"; grc=$?
  [[ $grc != 0 && ! -e $d/short ]] && ok "GNU ar x short member body fails; no dest" \
    || no "GNU short-x rc=$grc"
fi

echo "ar-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
