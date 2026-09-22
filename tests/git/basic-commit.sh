#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Phase 1 everyday commands: add, commit, status, diff, log, branch, switch,
# restore, reset and tag. Run through tests/git-parity.py, never on its own.
# requires: init add status commit log diff branch switch tag ls-files
# requires: restore reset rev-parse reflog cat-file checkout
# requires-feature: diff-patch
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

# reset says what it left behind, and takes a path where a revision would
# go: git reset <file> is how a staged change is put back.
printf 'staged\n' > a.txt
printf 'other\n' > b.txt
git add a.txt b.txt
git reset a.txt
git status --short
git add -A
git reset
# A second, so that what status reads is the stat data the reset wrote and
# not a file written in the same tick as the index.
sleep 1
git status --short
git add -A
git reset -q
git status --short
git add -A
git reset --soft
git status --short
rm b.txt
git add -A
git reset
git reset --hard
git status --short
git reset nosuchthing || echo "said no: $?"

# A path the index holds that HEAD does not: reset takes it back out of the
# index rather than complaining, and so does restore --staged. A pathspec
# that names nothing is quietly nothing to reset, and an error to restore.
printf 'fresh\n' > fresh.txt
git add fresh.txt
git status --short
git reset fresh.txt
git status --short
git reset -- nosuchpath.txt || echo "reset said no: $?"
git add fresh.txt
git restore --staged fresh.txt
git status --short
git add fresh.txt
git restore --staged --worktree fresh.txt
git status --short
[ -e fresh.txt ] && echo 'fresh.txt is here' || echo 'fresh.txt is gone'
git restore --staged nosuchpath.txt || echo "restore said no: $?"
git checkout HEAD -- nosuchpath.txt || echo "checkout said no: $?"

# And before the first commit, where HEAD stands for the empty tree.
mkdir -p unborn
cd unborn
git init -q -b main .
printf 'z\n' > z.txt
git add z.txt
git reset
git status --short
git add z.txt
git reset z.txt
git status --short
git add z.txt
git reset --hard
git status --short
cd ..
# and away, so that what is compared is this repository alone.
rm -rf unborn
