#!/usr/bin/env bash
# The diff taken word by word rather than line by line: what was taken out
# in [-brackets-] and what was put in {+braces+}, and the same thing said
# one run to a line in the porcelain form.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit diff log show
set -e

git init -q -b main .
printf 'the quick brown fox\njumps over the lazy dog\nunchanged line\n' > f.txt
printf 'alpha beta gamma delta\n' > g.txt
git add f.txt g.txt
git commit -q -m 'the first commit'

echo '=== a word changed on each of two lines ==='
printf 'the quick red fox\nleaps over the lazy dog\nunchanged line\n' > f.txt
git diff --word-diff f.txt
git diff --word-diff=plain f.txt
git diff --word-diff=porcelain f.txt
git diff --word-diff=none f.txt

echo '=== words taken away, and words put in ==='
printf 'alpha delta\n' > g.txt
git diff --word-diff g.txt
git diff --word-diff=porcelain g.txt
printf 'alpha beta new words gamma delta\n' > g.txt
git diff --word-diff g.txt
printf 'ALPHA beta gamma DELTA\n' > g.txt
git diff --word-diff g.txt

echo '=== a line added, and one taken away ==='
printf 'alpha beta gamma delta\nand a new line\n' > g.txt
git diff --word-diff g.txt
git diff --word-diff=porcelain g.txt
printf '' > g.txt
git diff --word-diff g.txt

echo '=== only the spacing changed ==='
printf 'alpha  beta gamma delta\n' > g.txt
git diff --word-diff g.txt

echo '=== a line put in beside one that begins the same way ==='
# The words of the added line could sit a word later, beside the line below
# it; a diff word by word takes one run of changed lines at a time, so they
# cannot drift across a line nothing happened to.
printf 'git count-objects [-v]\n' > h.txt
git add h.txt
git commit -q -m 'one usage line'
printf 'git annotate [-l] <file>\ngit count-objects [-v]\n' > h.txt
git diff --word-diff h.txt
git diff --word-diff=porcelain h.txt
printf 'git count-objects [-v]\ngit annotate [-l] <file>\n' > h.txt
git diff --word-diff h.txt

echo '=== blank lines around a change ==='
printf 'first\n\nsecond\n\nthird\n' > i.txt
git add i.txt
git commit -q -m 'a file with blank lines'
printf 'first word\n\nsecond\n\nthird word\n' > i.txt
git diff --word-diff i.txt
git diff --word-diff=porcelain i.txt
printf 'first\n\n\nsecond\n\nthird\n' > i.txt
git diff --word-diff i.txt
git diff --word-diff=porcelain i.txt

echo '=== and through a commit ==='
git add -A
git commit -q -m 'the second commit'
git show --word-diff
git log -p --word-diff -1
git diff --word-diff HEAD~1 HEAD
git diff --word-diff=porcelain HEAD~1 HEAD -- f.txt
