#!/usr/bin/env bash
# What `git archive` writes: a ustar tar of a commit's tree, dated by the
# commit, owned by root, with the commit's id in a header the archive
# carries. Compared byte for byte, by way of its digest.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit tag archive rev-parse
set -e

git init -q -b main .
mkdir -p d/e
printf 'one\n' > f.txt
printf 'two\n' > d/g.txt
printf '#!/bin/sh\necho hello\n' > d/run.sh
chmod +x d/run.sh
printf 'deeper\n' > d/e/h.txt
ln -s f.txt link.txt
git add -A
git commit -q -m 'the first commit'
git tag -a v1 -m 'a tag'

echo '=== a commit, whole ==='
git archive HEAD | cksum
git archive HEAD | wc -c

echo '=== the same by its tag, and by a name of its own ==='
git archive v1 | cksum
git archive "$(git rev-parse HEAD)" | cksum

echo '=== with a prefix, with and without the slash ==='
git archive --prefix=pre/ HEAD | cksum
git archive --prefix=x HEAD | cksum

echo '=== only some of it ==='
git archive HEAD d | cksum
git archive HEAD -- d/e | cksum
git archive HEAD f.txt | cksum

echo '=== into a file ==='
git archive -o out.tar HEAD
cksum < out.tar
rm -f out.tar

echo '=== a name that will not fit in a header ==='
deep=$(printf 'dir/%.0s' $(seq 1 30))
mkdir -p "$deep"
printf 'far away\n' > "${deep}far.txt"
long=$(printf 'z%.0s' $(seq 1 120))
printf 'wide\n' > "$long"
git add -A
git commit -q -m 'the second commit'
git archive HEAD | cksum
git archive HEAD | wc -c

echo '=== what it will not do ==='
git archive nosuchthing > /dev/null || echo "said no: $?"
