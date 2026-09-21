#!/usr/bin/env bash
# tests/chmod-check.sh [BINARY] — symbolic modes, held against chmod(1).
#
# Two things a symbolic mode says that are easy to get wrong: a clause that
# names nobody — `+x` rather than `u+x` — leaves alone whatever the file
# mode creation mask holds back, and the bits above the nine (setuid,
# setgid, sticky) belong to no class, so a mask has no say over them.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
GNU=/bin/chmod
[[ -x $GNU ]] || GNU=/usr/bin/chmod
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }

t=$("$BX" -c 'PATH=; type -t chmod' 2>/dev/null) || t=
[[ $t == builtin ]] && ok "chmod is a builtin with empty PATH" || no "type -t chmod -> '$t'"

if [[ ! -x $GNU ]]; then
  echo "  no chmod(1) to compare with; the comparison is skipped"
  echo "chmod-check: $pass passed, $fail failed"
  [[ $fail == 0 ]]
  exit
fi

for mask in 077 022 002 000; do
  for mode in +x a+x +w +rw =x u+x,+w go-r +X o=r ug=rw 755 0644 \
              +t u+s g+s +s u+x,g+s u=rws g=rxs ug+s a-s; do
    (
      umask "$mask"
      rm -f "$d/theirs" "$d/ours"
      : > "$d/theirs"; : > "$d/ours"
      "$GNU" "$mode" "$d/theirs" 2>/dev/null
      "$BX" -c 'PATH=; chmod "$1" "$2"' _ "$mode" "$d/ours" 2>/dev/null
      theirs=$(stat -c %a "$d/theirs"); ours=$(stat -c %a "$d/ours")
      [[ $theirs == "$ours" ]] || printf 'umask %s chmod %s: chmod(1) %s, builtin %s\n' \
        "$mask" "$mode" "$theirs" "$ours" >> "$d/differences"
    )
  done
done

if [[ -s $d/differences ]]; then
  cat "$d/differences"
  no "$(wc -l < "$d/differences") mode(s) differ from chmod(1)"
else
  ok "36 modes across four masks match chmod(1)"
fi

# A directory keeps X meaning "searchable", which is the other half of +X.
umask 022
rm -rf "$d/theirs.d" "$d/ours.d"; mkdir "$d/theirs.d" "$d/ours.d"
"$GNU" +X "$d/theirs.d"
"$BX" -c 'PATH=; chmod +X "$1"' _ "$d/ours.d"
[[ $(stat -c %a "$d/theirs.d") == $(stat -c %a "$d/ours.d") ]] \
  && ok "+X on a directory" \
  || no "+X on a directory: chmod(1) $(stat -c %a "$d/theirs.d"), builtin $(stat -c %a "$d/ours.d")"

echo "chmod-check: $pass passed, $fail failed"
[[ $fail == 0 ]]
