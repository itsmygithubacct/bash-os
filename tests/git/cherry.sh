#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Which of one branch's commits another already has, by the name of the
# change rather than the name of the commit: a patch applied over there in a
# commit of its own is the same patch. And what a rebase does with one.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit checkout cherry-pick cherry rebase log branch
set -e

git init -q -b main .
printf 'a\nb\nc\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'
git checkout -q -b side
printf 'a\nB\nc\n' > f.txt
git commit -q -a -m 'change the middle line'
printf 'a\nB\nc\nd\n' > f.txt
git commit -q -a -m 'add a fourth line'
printf 'first line of a new file\n' > g.txt
git add g.txt
git commit -q -m 'a file of its own'
git checkout -q main
# The same change, in a commit of its own over here.
git cherry-pick -n side~2
git commit -q -m 'the middle line, changed here instead'
printf 'a line only main has\n' > h.txt
git add h.txt
git commit -q -m 'a file only main has'
git checkout -q side

echo '=== which of them are already there ==='
git cherry main
git cherry -v main
git cherry main side
git cherry -v main side
git cherry main side side~1
git cherry side main
git cherry -v side main
git cherry main main
git cherry --abbrev=8 -v main
git cherry -v HEAD main 2>&1 || true

echo '=== and what a rebase makes of it ==='
git rebase main
git log --oneline
git status --short --branch

echo '=== the same again, reapplied ==='
git checkout -q -b twice main
printf 'a\nQ\nc\n' > f.txt
git commit -q -a -m 'another middle line'
git checkout -q main
git cherry-pick -n twice
git commit -q -m 'that middle line, here instead'
git checkout -q twice
git cherry -v main
git rebase --reapply-cherry-picks main
git log --oneline
