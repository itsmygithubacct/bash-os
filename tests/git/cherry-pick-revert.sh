#!/usr/bin/env bash
# Taking one commit onto another branch, and taking one back out. Both are
# three-way merges with a particular base, so both can conflict, and both
# can be continued or abandoned. Run through tests/git-parity.py, never on
# its own.
# requires: init add commit switch cherry-pick revert status log reset
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
printf 'one\ntwo\nthree\n' > a.txt
git add a.txt
git commit -q -m 'the common commit'

git switch -q -c topic
printf 'one\ntwo\nTHREE\n' > a.txt
printf 'extra\n' > b.txt
git add .
git commit -q -m 'topic changes the third line'
git switch -q main

echo '=== cherry-pick ==='
git cherry-pick topic
git log --oneline
git log -1 --format='%s%n%an %ae%n%cn %ce%n%P'
cat a.txt
git status --short

echo '=== revert what was just picked ==='
git revert --no-edit HEAD
git log --oneline
git log -1 --format='%s%n%b'
cat a.txt
test ! -e b.txt && echo 'the file the pick added is gone again'

echo '=== a cherry-pick that conflicts ==='
git switch -q -c other main
printf 'one\ntwo\nDIFFERENT\n' > a.txt
git add a.txt
git commit -q -m 'other changes the third line'
git cherry-pick topic || echo "conflict: $?"
cat a.txt
git status --short
git status
git ls-files -s

echo '=== settling it ==='
printf 'one\ntwo\nsettled\n' > a.txt
git add a.txt
git status --short
git cherry-pick --continue
git log --oneline -2
git log -1 --format='%s%n%an'
git status --short

echo '=== a cherry-pick that is abandoned ==='
git switch -q -c third main
printf 'one\ntwo\nTHIRD\n' > a.txt
git add a.txt
git commit -q -m 'third changes the third line'
git cherry-pick topic || echo "conflict: $?"
git status --short
git cherry-pick --abort
git status --short
git log --oneline -1
cat a.txt

echo '=== a revert that conflicts ==='
git switch -q -c reverter main
printf 'one\ntwo\nreverter\n' > a.txt
git add a.txt
git commit -q -m 'reverter changes the third line'
git revert --no-edit main || echo "conflict: $?"
git status --short
git revert --abort
git status --short
git log --oneline -1
