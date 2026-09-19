#!/usr/bin/env bash
# A merge that does not settle: conflict markers in the working tree, three
# stages in the index, what status says about it, and the two ways out —
# resolve and commit, or abort. Run through tests/git-parity.py, never on
# its own.
# requires: init add commit switch merge status ls-files log reset
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
printf 'one\ntwo\nthree\nfour\nfive\n' > shared.txt
printf 'keep\n' > keep.txt
printf 'gone later\n' > doomed.txt
git add .
git commit -q -m 'the common commit'

git switch -q -c topic
printf 'ONE\ntwo\nthree\nfour\nfive\n' > shared.txt
printf 'topic only\n' > topic.txt
git add .
git commit -q -m 'topic edits the first line'

git switch -q main
printf 'uno\ntwo\nthree\nfour\nfive\n' > shared.txt
git add shared.txt
git commit -q -m 'main edits the first line'

echo '=== the merge stops ==='
git merge topic || echo "conflict: $?"
cat shared.txt
git status --short
git status
git ls-files -s
git log --oneline -1

echo '=== aborting puts it all back ==='
git merge --abort
git status --short
cat shared.txt
git ls-files -s
git log --oneline -1

echo '=== resolving and committing ==='
git merge topic || echo "conflict: $?"
printf 'settled\ntwo\nthree\nfour\nfive\n' > shared.txt
git add shared.txt
git status --short
git status
git commit -m 'merge topic, resolved by hand'
git log --oneline
git log -1 --format='%s%n%P'
git status --short
git ls-files -s
cat shared.txt

echo '=== one side deletes what the other changes ==='
git switch -q -c deleter main
git rm -q doomed.txt
git commit -q -m 'remove doomed.txt'
git switch -q main
printf 'still wanted\n' > doomed.txt
git add doomed.txt
git commit -q -m 'change doomed.txt'
git merge deleter || echo "conflict: $?"
git status --short
git ls-files -s
cat doomed.txt
git merge --abort
git status --short

echo '=== both sides add the same path ==='
git switch -q -c adder main
printf 'from the branch\n' > added.txt
git add added.txt
git commit -q -m 'branch adds added.txt'
git switch -q main
printf 'from main\n' > added.txt
git add added.txt
git commit -q -m 'main adds added.txt'
git merge adder || echo "conflict: $?"
cat added.txt
git status --short
git ls-files -s
git merge --abort
git status --short
git log --oneline -1
