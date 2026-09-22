#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Paths that are awkward to write down: spaces, quotes, backslashes, a
# newline, letters outside ASCII, a leading dash. git quotes what it must
# and says so the same way everywhere, and core.quotePath turns the
# quoting of high bytes off.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit status diff log ls-files ls-tree rm mv checkout
set -e

git init -q -b main .
mkdir -p 'a dir'
printf 'plain\n' > plain.txt
printf 'spaces\n' > 'a file with spaces.txt'
printf 'quoted\n' > 'a "quoted" name.txt'
printf 'slashed\n' > 'back\slash.txt'
printf 'tabbed\n' > "$(printf 'a\tb.txt')"
printf 'accented\n' > 'café.txt'
printf 'nested\n' > 'a dir/deep file.txt'
printf 'dashed\n' > './-leading-dash.txt'

echo '=== what is there, before anything is added ==='
git status --short
git status --porcelain
git status --porcelain=v2
git status
git ls-files --others

echo '=== added and committed ==='
git add -A
git status --short
git ls-files
git ls-files -s
git ls-files -z | tr '\0' '\n'
git commit -q -m 'the awkward ones'
git ls-tree -r HEAD
git ls-tree -r --name-only HEAD
git log --name-only --format='%h'
git log --name-status --format='%h'
git log --raw --format='%h'

echo '=== changed and shown ==='
printf 'changed\n' >> 'a file with spaces.txt'
printf 'changed\n' >> 'café.txt'
git status --short
git diff --name-only
git diff --stat
git diff
git diff --numstat
git add -A
git diff --cached --name-only
git commit -q -m 'a change to two of them'

echo '=== and with the quoting turned off ==='
git -c core.quotePath=false status --short
git -c core.quotePath=false ls-files
git -c core.quotePath=false diff --name-only HEAD~1 HEAD
git -c core.quotePath=false log --name-only --format='%h' -1

echo '=== and the same again with NUL between them ==='
git ls-files -z | tr '\0' '|'
echo
git status -z | tr '\0' '|'
echo
git diff -z --name-only HEAD~1 HEAD | tr '\0' '|'
echo
git diff -z --name-status HEAD~1 HEAD | tr '\0' '|'
echo
git ls-tree -z -r HEAD | tr '\0' '|'
echo
git ls-tree -z -r --name-only HEAD | tr '\0' '|'
echo

echo '=== a name with a newline in it ==='
printf 'newlined\n' > "$(printf 'one\ntwo.txt')"
git status --short
git status --porcelain=v2
git add -A
git ls-files
git commit -q -m 'a name in two lines'
git log -1 --name-only --format='%h'
git diff --stat HEAD~1 HEAD
git ls-tree -r --name-only HEAD

echo '=== moved and taken away ==='
git mv 'a file with spaces.txt' 'another file with spaces.txt'
git status --short
git commit -q -m 'moved'
git log --name-status --format='%h' -1
git rm -q 'café.txt'
git status --short
git commit -q -m 'taken away'
git log --name-status --format='%h' -1
git ls-files
