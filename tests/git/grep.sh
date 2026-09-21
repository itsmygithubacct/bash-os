#!/usr/bin/env bash
# What grep finds and how it says so: in the working tree, in the index,
# and in a tree of its own, with the flags that change the shape of a
# line and the ones that change what counts as a match.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit grep
set -e

git init -q -b main .
mkdir -p sub
printf 'alpha beta\nBETA gamma\nthe end\n' > one.txt
printf 'beta again\nnothing here\n' > sub/two.txt
printf 'binary\000beta\000data\n' > bin.dat
printf 'ignored beta\n' > skip.log
printf '*.log\n' > .gitignore
git add -A
git commit -q -m 'the first commit'
printf 'beta in the working tree\n' >> one.txt
printf 'untracked beta\n' > fresh.txt

echo '=== what it finds ==='
git grep beta
git grep -n beta
git grep -i beta
git grep -l beta
git grep -c beta
git grep -h beta
git grep -w beta
git grep -v beta
git grep -ni beta
git grep -e beta -e gamma
git grep nothingatall || echo "nothing: $?"

echo '=== where it looks ==='
git grep --cached beta
git grep beta HEAD
git grep -n beta HEAD
git grep beta -- sub
git grep beta -- nosuch || echo "nothing there: $?"

echo '=== how the pattern is read ==='
git grep -E 'b(eta|inary)'
git grep -F 'alpha beta'
git grep '^beta'
git grep '^binary'
git grep 'end$'
git grep 'data$'
git grep -w the
git grep -w data
