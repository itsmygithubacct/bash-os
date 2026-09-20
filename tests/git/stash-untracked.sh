#!/usr/bin/env bash
# Stashing what is not tracked yet: the third commit a stash grows when -u
# is asked for, what leaves the working tree with it, and what comes back.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit stash status log ls-tree rev-parse
set -e

git init -q -b main .
printf 'one\ntwo\n' > a.txt
printf 'ignored\n' > rules
printf 'skip.log\n' > .gitignore
git add a.txt .gitignore
git commit -q -m 'the first commit'

echo '=== a tree with work in it, tracked and not ==='
printf 'one\nTWO\n' > a.txt
printf 'new file\n' > b.txt
mkdir -p nest/deeper
printf 'deeper still\n' > nest/deeper/c.txt
printf 'never mind me\n' > skip.log
git stash push -u -m 'work and new files'
git status --short
ls
test -e skip.log && echo 'the ignored file stayed'
test -e b.txt || echo 'the untracked file went'
test -d nest || echo 'and the directory it was in'

echo '=== what the stash holds ==='
git stash list
git log --format='%s' -1 refs/stash
git log --format='%s' -1 'refs/stash^2'
git log --format='%s' -1 'refs/stash^3'
git log --format='%p' -1 'refs/stash^3'
git ls-tree -r --name-only 'refs/stash^3'
git ls-tree -r --name-only refs/stash

echo '=== and what comes back ==='
git stash pop
git status --short
cat a.txt
cat b.txt
cat nest/deeper/c.txt
git stash list

echo '=== with something already standing there ==='
git add -A
git commit -q -m 'the second commit'
printf 'one\nTHREE\n' > a.txt
printf 'another\n' > d.txt
git stash push -u -q
printf 'in the way\n' > d.txt
git stash pop || echo "pop said no: $?"
cat d.txt
git stash list
git status --short

echo '=== applying it where the way is clear ==='
rm -f d.txt
git checkout -- a.txt        # the tracked half came back with the first try
git stash pop
cat d.txt
cat a.txt
git status --short
git stash list

echo '=== nothing to save ==='
git add -A
git commit -q -m 'the third commit'
git stash push -u
git stash list
