#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# History and the name-level diff.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit log diff rev-parse
set -e

git init -q -b main .
printf 'one\n' > a.txt
printf 'two\n' > b.txt
git add .
git commit -q -m 'first commit'

printf 'changed\n' >> a.txt
rm b.txt
printf 'new\n' > c.txt
git add -A
git commit -q -m 'second commit'

printf 'three\n' > d.txt
git add d.txt
git commit -q -m 'third commit' -m 'with a body line'

git log
git log --oneline
git log --oneline -n 2
git log --reverse --oneline
git log --format='%H %T %P'
git log --format='%h %an <%ae> %ad %s' --date=raw
git log --format='%s%n%b'
git log -n 1 --format='%cn %ce %cd' --date=raw
git log --first-parent --oneline

git diff --name-only HEAD~2 HEAD
git diff --name-status HEAD~2 HEAD
git diff --name-status HEAD~1 HEAD

printf 'worktree change\n' >> a.txt
git diff --name-status
git diff --name-only
git add a.txt
git diff --name-status --cached
git diff --name-status HEAD
git diff --name-status HEAD~1 -- a.txt
git diff --name-only HEAD~2 HEAD -- d.txt
