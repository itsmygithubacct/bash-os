#!/usr/bin/env bash
# What describe calls a commit: the nearest tag behind it, how far back
# that tag is, and the commit's own id — with the rules git uses to choose
# between two tags on one commit, and the words it refuses in.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit tag branch checkout merge describe name-rev rev-parse
set -e

git init -q -b main .
printf 'one\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'
git tag light-one
printf 'two\n' > f.txt
git commit -q -am 'the second commit'
GIT_COMMITTER_DATE='1750000200 +0000' git tag -a note-two -m 'the second, noted'
printf 'three\n' > f.txt
git commit -q -am 'the third commit'
printf 'four\n' > f.txt
git commit -q -am 'the fourth commit'

echo '=== the nearest tag behind ==='
git describe
git describe --long
git describe --tags
git describe --tags --long
git describe --abbrev=12
git describe --abbrev=0
git describe HEAD~2
git describe --tags HEAD~3
git describe --exact-match HEAD~2
git describe --exact-match HEAD || echo "said no: $?"
git describe --always
git describe --tags --match 'light*'
git describe --tags --match 'note*'
git describe --match 'nothing*' || echo "said no: $?"
git describe --match 'nothing*' --always
git describe nosuchrev || echo "said no: $?"
git describe HEAD HEAD~2

echo '=== which name reaches a commit, rather than which is behind it ==='
# A commit no tag is on top of cannot be described this way, which is what
# git says about the ones past the last tag.
git describe --contains HEAD || echo "said no: $?"
git describe --contains note-two
git describe --contains light-one
git describe --contains --all HEAD
git describe --all HEAD
git describe --all HEAD~2
git describe --all --long HEAD~1

echo '=== and the same question asked of name-rev ==='
git name-rev --name-only HEAD
git name-rev --name-only HEAD~2
git name-rev HEAD~1
git name-rev --tags --name-only HEAD~1
git name-rev --name-only --refs='refs/tags/note*' HEAD~2
git rev-parse HEAD | git name-rev --annotate-stdin

echo '=== two tags on one commit ==='
git tag light-two HEAD~1
GIT_COMMITTER_DATE='1750000300 +0000' git tag -a note-later HEAD~1 -m 'later'
git describe
git describe --tags
git describe --tags HEAD~1
git describe --tags --match 'light*'

echo '=== and a merge to reach past ==='
git checkout -q -b side HEAD~2
printf 'sideways\n' > g.txt
git add g.txt
git commit -q -m 'the side commit'
git tag -a note-side -m 'the side, noted'
git checkout -q main
git merge -q --no-edit side
git describe
git describe --long
git describe --candidates=1
git describe --tags

echo '=== a working tree that has moved on ==='
git describe --dirty
printf 'moved on\n' > f.txt
git describe --dirty
git describe --dirty=-changed
git describe --dirty --abbrev=0
git checkout -q -- f.txt
git describe --dirty

echo '=== a repository with no tags at all ==='
git tag -d light-one light-two note-two note-later note-side > /dev/null
git describe || echo "said no: $?"
git describe --tags || echo "said no: $?"
git describe --always
