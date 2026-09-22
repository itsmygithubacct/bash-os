#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The diff that overlooks whitespace: all of it, how much of it there is,
# what trails a line, and a carriage return before the end. A line that
# matches only because whitespace was overlooked is shown as the new side
# has it, which is the side git shows.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit diff log show blame
set -e

git init -q -b main .
printf 'int main (void)\n{\n\tint x = 1;\n\treturn x;\n}\n' > c.c
printf 'one two three\nfour five six\n' > words.txt
printf 'kept\ntrailing   \nplain\n' > trail.txt
git add c.c words.txt trail.txt
git commit -q -m 'the first commit'

echo '=== spacing changed, and nothing else ==='
printf 'int  main (void)\n{\n        int x = 1;\n    return x;\n}\n' > c.c
git diff c.c
git diff -w c.c
git diff --ignore-all-space c.c
git diff -b c.c
git diff --ignore-space-change c.c
git diff --ignore-space-at-eol c.c
git diff -w --stat c.c
git diff -w --numstat c.c
git diff -w --shortstat c.c

echo '=== spacing and a real change together ==='
printf 'int  main (int argc)\n{\n        int x = 1;\n    return x;\n}\n' > c.c
git diff -w c.c
git diff -b c.c
git diff -w -U0 c.c
git diff -w --word-diff c.c

echo '=== a word moved between the spaces ==='
printf 'one  two   three\nfour  five six\n' > words.txt
git diff -w words.txt
git diff -b words.txt
git diff --ignore-space-at-eol words.txt
printf 'onetwothree\nfour five six\n' > words.txt
git diff -w words.txt
git diff -b words.txt

echo '=== what trails a line ==='
printf 'kept\ntrailing\nplain   \n' > trail.txt
git diff trail.txt
git diff --ignore-space-at-eol trail.txt
git diff -b trail.txt
git diff -w trail.txt

echo '=== a carriage return before the end ==='
printf 'first\r\nsecond\r\nthird\n' > cr.txt
git add cr.txt
git commit -q -m 'lines that end the other way'
printf 'first\nsecond\r\nthird\n' > cr.txt
git diff cr.txt
git diff --ignore-cr-at-eol cr.txt
git diff -w cr.txt

echo '=== and through a commit, and a blame ==='
git add -A
git commit -q -m 'the second commit'
git diff -w HEAD~1 HEAD
git diff -b HEAD~2 HEAD
git show -w
git log -p -w -2
git blame c.c
git blame -w c.c
git blame -w -s c.c

echo '=== what a change brings in that it should not ==='
# --check says 2 when it finds something, so its status is caught rather
# than left to end the scenario.
said () { "$@" && echo 'status 0' || echo "status $?"; }
printf 'a clean line\n' > check.txt
git add check.txt
git commit -q -m 'a clean file'
printf 'a clean line\ntrailing space   \n \twith a space before the tab\n\ta plain tab\nlast\n\n' > check.txt
said git diff --check
said git diff --check --stat
said git diff --check -p
git add check.txt
said git diff --cached --check
git commit -q -m 'the whitespace goes in'
said git log -1 --check
said git show --check

echo '=== a marker left behind ==='
printf 'a clean line\n<<<<<<< HEAD\nmine\n=======\ntheirs\n>>>>>>> other\n' > check.txt
said git diff --check

echo '=== nothing wrong with it ==='
printf 'a clean line\nand another\n' > check.txt
said git diff --check

echo '=== and what the status says on its own ==='
said git diff --exit-code
said git diff --quiet
git add check.txt
git commit -q -m 'a clean change'
said git diff --exit-code
said git diff --quiet
printf 'a clean line\nand   another\n' > check.txt
said git diff --quiet -w
said git diff --quiet
said git diff --exit-code --check

echo '=== the four that cannot be asked for together ==='
said git diff --name-only --check
said git diff -s --name-status
said git diff --check -s
