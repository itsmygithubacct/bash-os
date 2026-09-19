#!/usr/bin/env bash
# Replaying a branch onto another: the straightforward case, a branch with
# nothing to replay, one that only needs fast-forwarding, and one that
# stops on a conflict and is continued or abandoned. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit switch rebase status log reset
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
printf 'base\n' > a.txt
git add a.txt
git commit -q -m 'the common commit'

git switch -q -c topic
printf 'topic one\n' > t1.txt
git add t1.txt
git commit -q -m 'topic one'
printf 'topic two\n' > t2.txt
git add t2.txt
git commit -q -m 'topic two'

git switch -q main
printf 'main moved\n' > m.txt
git add m.txt
git commit -q -m 'main moves on'

echo '=== rebasing topic onto main ==='
git switch -q topic
git rebase main
git log --oneline
git log --format='%s %an %ad' -3 --date=raw
git status --short
ls

echo '=== nothing to do ==='
git rebase main
git log --oneline -1

echo '=== a branch that only needs fast-forwarding ==='
git switch -q -c behind main
git switch -q main
printf 'ahead\n' > ahead.txt
git add ahead.txt
git commit -q -m 'main moves again'
git switch -q behind
git rebase main
git log --oneline -2
git status --short

echo '=== a rebase that stops ==='
git switch -q -c clash main
printf 'from clash\n' > c.txt
git add c.txt
git commit -q -m 'clash writes c'
git switch -q main
printf 'from main\n' > c.txt
git add c.txt
git commit -q -m 'main writes c'
git switch -q clash
git rebase main || echo "stopped: $?"
git status
git status --short
cat c.txt
git ls-files -s

echo '=== settling it and continuing ==='
printf 'settled\n' > c.txt
git add c.txt
git rebase --continue
git log --oneline -3
git status --short
cat c.txt

echo '=== a rebase that is abandoned ==='
git switch -q -c clash2 main
printf 'from clash2\n' > c.txt
git add c.txt
git commit -q -m 'clash2 writes c'
git switch -q main
printf 'main again\n' > c.txt
git add c.txt
git commit -q -m 'main writes c again'
git switch -q clash2
git rebase main || echo "stopped: $?"
git rebase --abort
git status --short
git log --oneline -1
cat c.txt
git rev-parse --abbrev-ref HEAD
