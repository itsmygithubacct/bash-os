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

# The stat is drawn to whatever width is asked for, and the names are cut
# from the left when they do not fit.
mkdir -p a/rather/deeply/nested/place
for i in 1 2 3 4 5 6 7 8 9; do
    printf 'line %d\n' "$i" >> a/rather/deeply/nested/place/long-name.txt
done
printf 'short\n' > s.txt
git add a s.txt
git commit -q -m 'files at two depths'
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    printf 'more %d\n' "$i" >> a/rather/deeply/nested/place/long-name.txt
done
printf 'changed\n' >> s.txt
git add -A
git commit -q -m 'and changes to both'
for width in '' '=80' '=60' '=40' '=25' '=16' '=200' '=40,20' '=60,20,1' \
             '=200,50,1'; do
    echo "--- --stat$width"
    git diff --stat$width HEAD~1 HEAD
done
git diff --stat-width=50 HEAD~1 HEAD
git diff --stat-name-width=15 HEAD~1 HEAD
git diff --stat-graph-width=10 HEAD~1 HEAD
git diff --stat=40 --stat-graph-width=3 HEAD~1 HEAD
git diff --stat-count=1 HEAD~1 HEAD
git log -1 --stat=60,20

# %xNN is the byte those two hex digits stand for.
git log -2 --format='%h%x09%s'
git log -1 --format='a%x41b%x2Cc'
git log -1 --format='%x25%xZZ%x4'

# The change as it would be to undo, and the paths without their letters.
git diff -R HEAD~1 HEAD
git diff --no-prefix HEAD~1 HEAD
git diff -R --no-prefix HEAD~1 HEAD
git diff -R --stat HEAD~1 HEAD
git diff -R --name-status HEAD~1 HEAD
git diff -R --numstat HEAD~1 HEAD
git show -R HEAD
