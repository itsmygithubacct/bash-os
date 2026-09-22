#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run from a directory inside the working tree, git names a path from
# there, reads a path written from there, and limits what it lists to what
# is under it. This walks through the commands that do each.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit status ls-files ls-tree diff log grep rev-parse
# requires: rm restore reset mv clean checkout
set -e

git init -q -b main .
mkdir -p one/two
printf 'top\n' > top.txt
printf 'a\n' > one/a.txt
printf 'b\n' > one/two/b.txt
git add -A
git commit -q -m 'the first commit'
printf 'changed\n' >> one/a.txt
printf 'changed\n' >> top.txt
printf 'new\n' > one/new.txt

cd one

echo '=== what is here, and where it is ==='
git status
git status --short
git status --porcelain
git status --porcelain=v2
git status -z | tr '\0' '|'
echo
git rev-parse --show-prefix
git rev-parse --show-toplevel > /dev/null && echo 'toplevel: printed'

echo '=== what is listed is what is under here ==='
git ls-files
git ls-files --full-name
git ls-files -s
git ls-files -o
git ls-files -m
git ls-files two
git ls-files ../top.txt
git ls-tree HEAD
git ls-tree -r HEAD
git ls-tree -r --name-only HEAD
git ls-tree --full-name -r --name-only HEAD
git grep -n a
git grep -n changed
git grep -n b two
git grep -n top || echo 'nothing above here'

echo '=== a path is read from here ==='
git diff --name-only -- a.txt
git diff --stat a.txt
git diff -- ../top.txt
git diff --name-only ../top.txt
git log --oneline -- a.txt
git log --oneline ../top.txt
git diff --relative --name-only
git diff --relative
git diff --relative --stat
git diff --relative=two --name-only || echo 'nothing under two'
git diff --no-relative --name-only

echo '=== and a path given to a command that changes things ==='
git add new.txt
git status --short
git reset new.txt
git status --short
git rm --cached a.txt
git status --short
git reset -q a.txt
git mv a.txt c.txt
git status --short
git mv c.txt a.txt
git clean -n
git checkout -- a.txt
git status --short
