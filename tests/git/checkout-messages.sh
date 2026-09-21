#!/usr/bin/env bash
# What checkout and switch say about a move: the branch they landed on,
# where HEAD was before, the paragraph about a detached HEAD nobody asked
# for, and how the branch stands against the one it follows.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit branch checkout switch update-ref config rev-parse log
set -e

git init -q -b main .
printf 'one\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'
printf 'two\n' > f.txt
git commit -q -am 'the second commit'

echo '=== a branch made on the way ==='
git checkout -b topic
git checkout main
git checkout main

echo '=== and one nobody asked to detach ==='
git checkout HEAD~1
git checkout main
git checkout --detach HEAD~1
git checkout main

echo '=== switch says the same things ==='
git switch topic
git switch -c other
git switch main

echo '=== the branch before this one ==='
git checkout -
git checkout -
git rev-parse --abbrev-ref '@{-1}'
git log --oneline -1 '@{-1}'

echo '=== and how it stands against what it follows ==='
git update-ref refs/remotes/origin/main "$(git rev-parse HEAD)"
git config branch.main.remote origin
git config branch.main.merge refs/heads/main
git checkout topic
git checkout main
printf 'three\n' > f.txt
git commit -q -am 'the third commit'
git checkout topic
git checkout main
git update-ref refs/remotes/origin/main "$(git rev-parse HEAD~1)"
git checkout topic
git checkout main

echo '=== with -q it says nothing ==='
git checkout -q topic
git checkout -q main
git switch -q topic
git switch -q main
