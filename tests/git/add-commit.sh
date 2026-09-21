#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Staging, status and committing: Phase 1's first commands.
# Run through tests/git-parity.py, never on its own.
# requires: init add status commit ls-files rev-parse cat-file
set -e

git init -q -b main .

printf 'one\n' > a.txt
mkdir -p dir
printf 'two\n' > dir/b.txt
printf 'ignored\n' > skip.log
printf '*.log\n' > .gitignore

git status --porcelain=v2 --branch
git status -s
git status --porcelain

git add .
git status --porcelain=v2
git status -s
git ls-files -s

git commit -q -m 'first commit'
git status --porcelain=v2 --branch
git rev-parse HEAD
git cat-file -p HEAD
git cat-file -p 'HEAD^{tree}'

printf 'changed\n' >> a.txt
: > new.txt
git status -s
git status --porcelain=v2 -uall
git status --porcelain --ignored

git add a.txt
git status --porcelain=v2
git commit -q -m 'second commit'
git status -s

rm dir/b.txt
git status -s
git add -A
git status --porcelain=v2
git commit -q -m 'third commit'
git status -s

git rev-parse HEAD 'HEAD~1' 'HEAD~2'
git ls-files
git ls-files -s

# A directory sorts after a sibling file whose name carries its own and
# then a byte below '/' — "t/git-http.py" comes before "t/git/x.sh" — so
# a search of the index for what a directory holds has to allow for it.
mkdir -p t/git
printf 'x\n' > t/git-http.py
printf 'y\n' > t/git/x.sh
printf 'z\n' > 't/git!bang'
git add t
git commit -q -m 'a directory between its siblings'
git status -s
git status --porcelain=v2
git ls-files t
printf 'more\n' > t/git/later.sh
git status -s
git add -A
git status --porcelain=v2
git commit -q -m 'and one more under it'
git status
