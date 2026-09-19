#!/usr/bin/env bash
# Merge bases: where two histories last agreed, including a pair of merges
# made in opposite orders, which leaves two bases and no single best one.
# The merges are built with commit-tree, so this scenario needs no merge
# command. Run through tests/git-parity.py, never on its own.
# requires: init add commit switch merge-base commit-tree rev-parse update-ref
set -e

git init -q -b main .
printf 'base\n' > a.txt
git add a.txt
git commit -q -m 'the common commit'
git switch -q -c left
printf 'l\n' > l.txt
git add l.txt
git commit -q -m 'left commit'
git switch -q main
git switch -q -c right
printf 'r\n' > r.txt
git add r.txt
git commit -q -m 'right commit'

echo '=== two branches from one commit ==='
git merge-base left right
git merge-base main left
git merge-base left left
git merge-base right main

echo '=== is-ancestor ==='
git merge-base --is-ancestor main left && echo 'main is an ancestor of left'
git merge-base --is-ancestor left right || echo "left is not an ancestor of right: $?"
git merge-base --is-ancestor left left && echo 'a commit is its own ancestor'

echo '=== independent and octopus ==='
git merge-base --independent left right main
git merge-base --independent main main
git merge-base --octopus left right main

echo '=== two merges, opposite orders, two bases ==='
tree=$(git rev-parse 'HEAD^{tree}')
left=$(git rev-parse left)
right=$(git rev-parse right)
m1=$(git commit-tree "$tree" -p "$left" -p "$right" -m 'merge one')
m2=$(git commit-tree "$tree" -p "$right" -p "$left" -m 'merge two')
git update-ref refs/heads/m1 "$m1"
git update-ref refs/heads/m2 "$m2"
git merge-base m1 m2
git merge-base --all m1 m2
git merge-base --independent m1 m2 left
git merge-base --octopus m1 m2 main
git merge-base --is-ancestor left m1 && echo 'left is an ancestor of the merge'
git rev-parse m1 m2

echo '=== a name that does not resolve ==='
git merge-base nosuchrev HEAD || echo "bad name: $?"
