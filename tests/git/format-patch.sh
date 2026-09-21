#!/usr/bin/env bash
# A commit written out as mail: the headers, the subject with its number,
# the body, the stat, the patch and the trailer — and the names the files
# are given. The version in the trailer is this build's own, so it is the
# one thing the comparison levels.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit format-patch
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
printf 'one\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'
printf 'two\n' >> f.txt
git commit -q -am 'the second commit

with a body of its own
and a second line'
printf 'three\n' >> f.txt
mkdir -p sub
printf 'deep\n' > sub/deep.txt
git add sub/deep.txt
git commit -q -am 'a third: with punctuation, and a slash/here'

level() { sed -e 's/^2\.47\.3.*$/<version>/'; }

echo '=== two patches, one after the other ==='
git format-patch --stdout HEAD~2 | level

echo '=== one on its own ==='
git format-patch --stdout -1 | level

echo '=== a range, and without the numbering ==='
git format-patch --stdout 'HEAD~2..HEAD' | level
git format-patch --stdout -N HEAD~2 | level

echo '=== written to files ==='
git format-patch HEAD~2
cat 0001-the-second-commit.patch | level
rm -f 0001-the-second-commit.patch 0002-a-third-with-punctuation-and-a-slash-here.patch

echo '=== and into a directory of their own ==='
git format-patch -o mail HEAD~2
ls mail
rm -rf mail
git status --short
