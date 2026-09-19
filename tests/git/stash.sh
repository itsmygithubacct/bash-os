#!/usr/bin/env bash
# Putting work aside and taking it back: the stack refs/stash keeps in its
# own reflog, and what apply, pop and drop do to it. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit stash status log diff switch
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
printf 'one\ntwo\n' > a.txt
printf 'keep\n' > k.txt
git add .
git commit -q -m 'the first commit'

echo '=== nothing to save ==='
git stash
git stash list

echo '=== saving work ==='
printf 'one\nTWO\n' > a.txt
printf 'staged\n' > s.txt
git add s.txt
printf 'untracked\n' > u.txt
git stash push -m 'work in progress'
git status --short
cat a.txt
test -e u.txt && echo 'the untracked file stayed'
git stash list

echo '=== what the stash holds ==='
git log --format='%s' -1 refs/stash
git log --format='%s' -1 'refs/stash^2'
git stash show
git stash show -p

echo '=== popping it back ==='
git stash pop
git status --short
cat a.txt
git stash list

echo '=== two stashes, applied and dropped ==='
git stash push -m 'the first pile'
printf 'one\nsecond pile\n' > a.txt
git stash push -m 'the second pile'
git stash list
git stash apply
git status --short
cat a.txt
git stash list
git stash drop
git stash list
git checkout -q -- a.txt
git stash pop
cat a.txt
git status --short
git stash list

echo '=== stashing, changing HEAD, and coming back ==='
git add -A
git commit -q -m 'commit what came back'
printf 'one\nfor the stash\n' > a.txt
git stash push -m 'across a commit'
printf 'new file\n' > n.txt
git add n.txt
git commit -q -m 'a commit while stashed'
git stash pop
cat a.txt
git status --short
git stash list
git log --oneline
