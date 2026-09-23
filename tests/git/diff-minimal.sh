#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# A repeated-line comparison long enough to make Git's default search take
# a cheaper path; the exact search changes both the patch and its counts.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit diff log show
set -e

git init -q -b main .

make_lines () {
    seed=$1
    i=0
    while [ "$i" -lt 1200 ]; do
        seed=$(((seed * 1103515245 + 12345) & 2147483647))
        printf 'line-%d\n' "$((seed % 9))"
        i=$((i + 1))
    done
}

make_lines 90224 > lines.txt
git add lines.txt
git commit -q -m 'the first repeated file'
make_lines 41261 > lines.txt

echo '=== compare exact and default searches ==='
git diff -U0 --minimal lines.txt
git diff -U0 --diff-algorithm=minimal lines.txt
git diff --minimal --numstat lines.txt
git diff --minimal --stat lines.txt
git -c diff.algorithm=minimal diff --numstat lines.txt
git -c diff.algorithm=minimal diff --diff-algorithm=myers --numstat lines.txt
git diff -U0 --minimal --diff-algorithm=myers lines.txt

git add lines.txt
git commit -q -m 'the second repeated file'
echo '=== committed forms ==='
git show -U0 --minimal HEAD
git log -1 -p -U0 --diff-algorithm=minimal
