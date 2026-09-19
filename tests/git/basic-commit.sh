#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Phase 1 everyday commands: add, commit, status, diff, log, branch, switch,
# restore, reset and tag. Run through tests/git-parity.py, never on its own.
# requires: init add status commit log diff branch switch tag ls-files
# requires: restore reset rev-parse reflog cat-file
set -e

git init -q -b main .

printf 'one\n' > a.txt
mkdir -p dir
printf 'two\n' > dir/b.txt
git status --porcelain=v2 --branch
git add .
git status --porcelain=v2
git commit -q -m 'first commit'
git log --oneline
git log --format='%H %T %P %s %an %ad' --date=raw

printf 'three\n' >> a.txt
printf 'untracked\n' > u.txt
git status --short
git status --porcelain=v2 --untracked-files=all
git diff
git diff --stat
git diff --name-status
git add a.txt
git diff --cached --stat
git commit -q -m 'second commit'

git branch topic
git branch -v
git switch -q topic
git rev-parse --abbrev-ref HEAD
printf 'four\n' > c.txt
git add c.txt
git commit -q -m 'third commit on topic'
git switch -q main
git log --all --oneline
git ls-files -s

git tag lightweight
git tag -a annotated -m 'annotated tag'
git tag -l
git cat-file -t annotated

printf 'five\n' > a.txt
git restore a.txt
git status --short
git reset -q --hard HEAD
git status --porcelain=v2 --branch
git rev-parse HEAD 'HEAD^{tree}' main topic
git reflog show main
