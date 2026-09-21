#!/usr/bin/env bash
# Notes: text kept beside a commit without changing it, in a tree of its
# own under refs/notes/. What is compared is the notes themselves, the
# objects they are kept in, and how they read under the commits they are
# about.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit notes log show rev-parse ls-tree cat-file
set -e

git init -q -b main .
printf 'one\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'
printf 'two\n' > f.txt
git commit -q -am 'the second commit'

echo '=== a note on the tip ==='
git notes add -m 'a note on the tip'
git notes list
git notes show
git rev-parse refs/notes/commits
git ls-tree -r refs/notes/commits
git cat-file -p refs/notes/commits

echo '=== one is not replaced by accident ==='
git notes add -m 'again' || echo "said no: $?"
git notes show
git notes add -f -m 'replaced'
git notes show

echo '=== and it can be added to ==='
git notes append -m 'a second line'
git notes show

echo '=== a note on an older commit ==='
git notes add -m 'on the first' HEAD~1
git notes list
git notes list HEAD~1

echo '=== copied from one to another ==='
git notes copy HEAD~1 HEAD || echo "said no: $?"
git notes copy -f HEAD~1 HEAD
git notes show
git notes list

echo '=== how they read ==='
git log
git log --oneline
git log --no-notes
git show --stat
git log --format='[%h|%N]'

echo '=== a notes ref of their own ==='
git notes --ref reviews add -m 'looked at it'
git notes --ref reviews list
git log -1 --notes=reviews
git notes get-ref
git notes --ref reviews get-ref

echo '=== taken away again ==='
git notes remove HEAD~1
git notes list
git notes show HEAD~1 || echo "said no: $?"
git notes remove --ignore-missing HEAD~1
git log --format='[%h|%N]'
git fsck | sort
