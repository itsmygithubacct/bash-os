#!/usr/bin/env bash
# Mail read back: each patch applied and committed with the author and
# date it carried, and what happens when one of them will not go on — the
# state left behind, and going on, past it, or back. The repositories live
# under HOME, which the harness does not compare.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit format-patch am log status reset
# requires-feature: diff-patch diff-stat
set -e

cd "$HOME"
git init -q -b main from
cd from
printf 'one\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'
printf 'two\n' >> f.txt
git commit -q -am 'add two

with a body of its own'
printf 'three\n' >> f.txt
git commit -q -am 'add three'
git format-patch --stdout HEAD~2 > "$HOME/mail.mbox"
cd ..

git init -q -b main to
cd to
printf 'one\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'

echo '=== applied, one after the other ==='
git am "$HOME/mail.mbox"
git log --format='%an <%ae> %ad %s' --date=raw
git status --short

echo '=== and when one will not go on ==='
printf 'CHANGED\n' > f.txt
git commit -q -am 'a commit of its own'
git am "$HOME/mail.mbox" || echo "said no: $?"
git status --short
git am "$HOME/mail.mbox" || echo "and again: $?"

echo '=== past it ==='
git am --skip || echo "skip said: $?"
git log --format='%s' | head -4
git status --short

echo '=== or back ==='
git am "$HOME/mail.mbox" || echo "said no: $?"
git am --abort
git log --format='%s' | head -3
git status --short

echo '=== or settled by hand and gone on with ==='
git am "$HOME/mail.mbox" || echo "said no: $?"
printf 'one\ntwo\n' > f.txt
git add f.txt
git am --continue
git log --format='%an %s' | head -4
git status --short
