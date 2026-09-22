#!/usr/bin/env bash
# What branch and tag list, and what narrows those listings: -v and -vv,
# the tags' own messages, and the four tests — merged, not merged,
# contains, points at. The repositories live under HOME, which the
# harness does not compare.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit clone fetch branch tag checkout merge config
set -e

cd "$HOME"
git init -q -b main far
cd far
printf 'one\n' > one.txt
git add one.txt
git commit -q -m 'the first commit'
cd ..
git clone -q far near
cd near

git tag light-one
git tag -a note-one -m 'the first, noted
with a second line
and a third'
printf 'two\n' > two.txt
git add two.txt
git commit -q -m 'the second commit'
git branch behind-here HEAD~1
git checkout -q -b elsewhere HEAD~1
printf 'away\n' > away.txt
git add away.txt
git commit -q -m 'a commit of its own'
git tag light-away
git checkout -q main

echo '=== the branches, and what they follow ==='
git branch
git branch -v
git branch -vv
git branch -a
git branch -r
git branch -a -v
git branch -r -v
git branch --show-current

echo '=== narrowed ==='
git branch --merged
git branch --no-merged
git branch --merged HEAD~1
git branch --no-merged HEAD~1
git branch --contains HEAD~1
git branch --contains elsewhere
git branch -a --contains HEAD~1
git branch --points-at HEAD
git branch --points-at HEAD~1
git branch -a -v --merged
git branch --contains nosuchrev || echo "said no: $?"
git branch --points-at nosuchrev || echo "said no: $?"

echo '=== a commit ahead of what it follows ==='
printf 'three\n' > three.txt
git add three.txt
git commit -q -m 'the third commit'
git branch -vv
git branch -v

echo '=== the tags ==='
git tag
git tag -n
git tag -n2
git tag -n3
git tag -l 'light*'
git tag --contains HEAD~2
git tag --contains elsewhere
git tag --points-at HEAD~2
git tag --merged HEAD
git tag --no-merged HEAD
git tag -n1 --merged HEAD
git tag --contains nosuchrev || echo "said no: $?"

echo '=== a listing narrowed by a pattern, and put in order ==='
git branch release-1
git branch release-2
git branch other
git tag v1.9
git tag v1.10
git tag v1.2
git branch --list 'release-*'
git branch -l 'other'
git branch --list 'no-such-*'
git branch --list 'release-1' 'other'
git branch -v --list 'release-*'
git branch -a --list '*release*'
git tag --sort=refname
git tag --sort=-refname
git tag --sort=v:refname
git tag --sort=version:refname
git tag -l 'v1.*' --sort=v:refname
git for-each-ref --sort=refname --format='%(refname)'
git for-each-ref --sort=-refname --format='%(refname)'
git for-each-ref --sort=objecttype --format='%(objecttype) %(refname)'
git for-each-ref --sort=refname refs/tags --format='%(refname:short)'
git for-each-ref --sort=v:refname refs/tags --format='%(refname:short)'
git for-each-ref --sort=-committerdate --count=3 --format='%(refname)' refs/heads
git for-each-ref --sort=creatordate --format='%(refname)' refs/tags
git for-each-ref --sort=nonesuch 2>&1 || true
