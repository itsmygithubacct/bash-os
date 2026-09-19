#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Branches, switching, tags, restoring and resetting — and the reflog they
# leave behind. Run through tests/git-parity.py, never on its own.
# requires: init add commit branch switch tag restore reset rm rev-parse
# requires: status log reflog cat-file
set -e

git init -q -b main .
printf 'one\n' > a.txt
git add .
git commit -q -m 'first commit'

git branch
git branch topic
git branch -v
git branch --show-current

git switch -q topic
git rev-parse --abbrev-ref HEAD
printf 'from topic\n' > t.txt
git add t.txt
git commit -q -m 'topic commit'

git switch -q main
git rev-parse --abbrev-ref HEAD
git status -s
test ! -e t.txt && echo 'the topic file is gone on main'
git log --oneline

git switch -q -c feature
git rev-parse --abbrev-ref HEAD
git branch
git switch -q main
git branch -d feature
git branch

git tag v1
git tag -a v2 -m 'annotated'
git tag -l
git rev-parse v1
git cat-file -t v2
git cat-file -p v2
git tag -d v1
git tag -l

printf 'changed\n' >> a.txt
git status -s
git restore a.txt
git status -s

printf 'staged change\n' >> a.txt
git add a.txt
git status -s
git restore --staged a.txt
git status -s
git restore a.txt
git status -s

git rm --cached a.txt
git status -s
git reset -q
git status -s

printf 'new\n' > b.txt
git add b.txt
git commit -q -m 'second commit'
git log --oneline
git reset -q --hard 'HEAD~1'
git log --oneline
git status -s
test ! -e b.txt && echo 'the hard reset removed the file'

git reflog
git reflog topic
