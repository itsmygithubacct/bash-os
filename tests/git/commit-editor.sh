#!/usr/bin/env bash
# Writing a commit message in an editor: what the editor is given to start
# from, what comes back, and what an empty message does. The editor here is
# a script that keeps what it was shown and writes back whatever $MESSAGE
# says, so both halves can be looked at.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit log status
set -e

git init -q -b main .
printf '%s\n' '#!/bin/sh' \
  'while IFS= read -r line; do printf "%s\n" "$line"; done < "$1" > editor-saw' \
  'printf "%s\n" "$MESSAGE" > "$1"' > editor
chmod 755 editor
export GIT_EDITOR=./editor

printf 'one\n' > a.txt
printf 'never staged\n' > u.txt
git add a.txt

echo '=== a message written in the editor ==='
MESSAGE='the first commit, from the editor' git commit
git log --format='%s' -1
cat editor-saw

echo '=== an empty message stops it ==='
printf 'one\ntwo\n' > a.txt
git add a.txt
MESSAGE='' git commit || echo "commit said no: $?"
git log --format='%s' -1
git status --short

echo '=== and a message again ==='
MESSAGE='the second commit' git commit -q
git log --format='%s' -1
cat editor-saw

echo '=== amending starts from the old message ==='
MESSAGE='the second commit, reworded' git commit -q --amend
git log --format='%s' -1
cat editor-saw

echo '=== -m and -e together ==='
printf 'one\ntwo\nthree\n' > a.txt
git add a.txt
MESSAGE='what the editor says' git commit -q -e -m 'what the flag says'
git log --format='%s' -1
cat editor-saw

echo '=== an editor that does nothing at all ==='
printf 'one\ntwo\nthree\nfour\n' > a.txt
git add a.txt
GIT_EDITOR=: git commit || echo "commit said no: $?"
git status --short

echo '=== and the flag on its own is still enough ==='
git commit -q -m 'the last commit'
git log --format='%s'

echo '=== a tag message is written the same way ==='
MESSAGE='the tag, from the editor' git tag -a v1
git cat-file tag v1 | tail -2
cat editor-saw
MESSAGE='' git tag -a v2 || echo "tag said no: $?"
git tag
