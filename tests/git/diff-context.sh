#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# How much of a file a diff shows. The width of the context is most of it,
# but a diff asked to show none of it first sets aside whatever long tail
# the two versions already share — which is why the same change can be
# described differently at -U0 than at -U3.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit diff log show
set -e

git init -q -b main .

# The shared tail runs to some thousands of bytes, which is what it takes.
{
    i=1
    while [ $i -le 40 ]; do printf 'header line %02d, in both versions\n' $i; i=$((i + 1)); done
    printf '\n'
    printf 'a paragraph that will be replaced\nwith something else entirely\n'
    printf '\n'
    i=1
    while [ $i -le 200 ]; do
        printf 'tail line %03d: the same forty-odd characters each time\n' $i
        i=$((i + 1))
    done
} > long.txt
git add long.txt
git commit -q -m 'the long file'

{
    i=1
    while [ $i -le 40 ]; do printf 'header line %02d, in both versions\n' $i; i=$((i + 1)); done
    printf '\n'
    printf 'a replacement paragraph\nin two lines of its own\nand a third\n'
    printf '\n'
    i=1
    while [ $i -le 200 ]; do
        printf 'tail line %03d: the same forty-odd characters each time\n' $i
        i=$((i + 1))
    done
} > long.txt

echo '=== the same change at every width ==='
git diff -U0 long.txt
git diff -U1 long.txt
git diff -U2 long.txt
git diff -U3 long.txt
git diff --unified=0 long.txt
git diff -U8 long.txt
git diff -U0 --stat long.txt
git diff -U0 --numstat long.txt
git diff -U0 --shortstat long.txt
git diff -U0 --word-diff long.txt

echo '=== and committed ==='
git add long.txt
git commit -q -m 'the long file, changed'
git log -1 -p -U0
git log -1 -p -U1
git show -U0
git diff -U0 HEAD~1 HEAD
git diff -U0 HEAD~1 HEAD -- long.txt

echo '=== a run that could sit in more than one place ==='
printf 'alpha\nbeta\ngamma\nalpha\nbeta\ngamma\nomega\n' > slide.txt
git add slide.txt
git commit -q -m 'a file that repeats itself'
printf 'alpha\nbeta\ngamma\nalpha\nbeta\ngamma\nalpha\nbeta\ngamma\nomega\n' > slide.txt
git diff -U0 slide.txt
git diff slide.txt
git diff --word-diff slide.txt

echo '=== a blank line in the middle of a hunk ==='
printf 'first\n\nsecond\n\nthird\n' > blanks.txt
git add blanks.txt
git commit -q -m 'a file with blank lines'
printf 'first changed\n\nsecond\n\nthird changed\n' > blanks.txt
git diff blanks.txt
git diff -U0 blanks.txt
git diff --word-diff blanks.txt
git diff --word-diff=porcelain blanks.txt
git diff --word-diff=porcelain -U1 blanks.txt
