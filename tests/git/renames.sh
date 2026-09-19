#!/usr/bin/env bash
# Renames: a file moved, a file moved and edited, one moved too far to
# recognise, and what --no-renames says instead. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit mv status diff log show rm
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n' > a.txt
printf 'other\n' > b.txt
git add .
git commit -q -m 'the first commit'

echo '=== a file moved, nothing else ==='
git mv a.txt renamed.txt
git status --short --no-renames
git status --short
git status
git status --porcelain=v2
git diff --cached
git diff --cached --stat
git diff --cached --summary
git diff --cached --name-status
git diff --cached --no-renames --stat

echo '=== committed, and seen in the log ==='
git commit -q -m 'move a.txt out of the way'
git show --stat
git show
git log --stat -1
git log --name-status -1

echo '=== moved and edited ==='
git mv renamed.txt moved-again.txt
printf 'one\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight\nnine\nTEN\n' > moved-again.txt
git add moved-again.txt
git status --short
git diff --cached
git diff --cached --stat
git diff --cached --summary
git commit -q -m 'move it again, with edits'
git show --stat

echo '=== moved too far to recognise ==='
git mv b.txt unrecognisable.txt
printf 'nothing whatever to do with the old contents of this file\nnot one line\n' > unrecognisable.txt
git add unrecognisable.txt
git status --short
git diff --cached --stat
git diff --cached --summary

echo '=== two files that swapped places ==='
git commit -q -m 'replace b.txt'
printf 'first file\nwith some lines\nto tell them apart\nand a fourth\n' > one.txt
printf 'second file\nwith other lines\nto tell them apart\nand a fourth\n' > two.txt
git add one.txt two.txt
git commit -q -m 'two files'
git mv one.txt three.txt
git mv two.txt four.txt
git status --short
git diff --cached --stat
git diff --cached --summary
