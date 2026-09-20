#!/usr/bin/env bash
# What a fetch can be asked for: the configured refspec, one given on the
# command line, the tags, and pruning what the far end no longer has —
# with FETCH_HEAD left behind for a merge to read. The repositories live
# under HOME, which the harness does not compare. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit branch tag fetch clone remote for-each-ref
# requires: rev-parse log config
set -e

cd "$HOME"
git init -q -b main far
cd far
printf 'one\n' > a.txt
git add a.txt
git commit -q -m 'the first commit'
git branch other
git tag v1
cd ..
git clone -q far near
root=$PWD

echo '=== the far end moves on ==='
cd far
printf 'two\n' >> a.txt
git commit -q -am 'the second commit'
git branch third
git tag v2
cd ../near
git fetch 2>&1 | sed "s|$root|ROOT|"
git for-each-ref --format='%(refname)' refs/remotes/

echo '=== what a merge would read ==='
sed "s|$root|ROOT|" .git/FETCH_HEAD

echo '=== the tags, when asked for ==='
git fetch --tags 2>&1 | sed "s|$root|ROOT|"
git for-each-ref --format='%(refname)' refs/tags/

echo '=== a refspec of its own ==='
git fetch ../far refs/heads/other:refs/remotes/named/other 2>&1 | sed "s|$root|ROOT|"
git for-each-ref --format='%(refname)' refs/remotes/named/

echo '=== and pruning what is no longer there ==='
cd ../far
git branch -D third
cd ../near
git fetch --prune 2>&1 | sed "s|$root|ROOT|"
git for-each-ref --format='%(refname)' refs/remotes/

echo '=== a second fetch has nothing to say ==='
git fetch 2>&1 | sed "s|$root|ROOT|"
echo "status: $?"
