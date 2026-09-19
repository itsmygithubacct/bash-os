#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Objects and refs without a commit: what Phase 0's first commands cover.
# Run through tests/git-parity.py, never on its own.
# requires: init hash-object cat-file rev-parse update-ref symbolic-ref
# requires: show-ref for-each-ref
set -e

git init -q -b main .
git rev-parse --is-inside-work-tree
git rev-parse --is-bare-repository
git rev-parse --git-dir
git symbolic-ref HEAD

printf 'hello\n' > hello.txt
blob=$(git hash-object -w hello.txt)
echo "blob $blob"
git cat-file -t "$blob"
git cat-file -s "$blob"
git cat-file blob "$blob"
git cat-file -p "$blob"
git cat-file -e "$blob" && echo 'cat-file -e: present'
git rev-parse --short "$blob"
git rev-parse --verify "$blob"

printf 'second\n' | git hash-object -w --stdin
printf 'third\n' > third.txt
git hash-object third.txt
test ! -e .git/objects/"$(git hash-object third.txt | cut -c1-2)" && echo 'hash-object without -w wrote nothing'

# A tag may point at any object, so refs can be exercised without a commit.
git update-ref refs/tags/blob-tag "$blob"
git rev-parse refs/tags/blob-tag
git rev-parse blob-tag
git rev-parse --symbolic-full-name blob-tag
git show-ref
git show-ref --tags
git show-ref --verify refs/tags/blob-tag
git for-each-ref
git for-each-ref --format='%(refname) %(objecttype) %(objectname)'
git for-each-ref --format='%(refname:short) %(objectsize)' refs/tags

# An update with the wrong old value is refused, and changes nothing.
second=$(printf 'second\n' | git hash-object -w --stdin)
git update-ref refs/tags/blob-tag "$second" "$blob"
git rev-parse refs/tags/blob-tag
if git update-ref refs/tags/blob-tag "$blob" "$second$second" 2>/dev/null; then
  echo 'update-ref accepted a bad old value'
fi
git rev-parse refs/tags/blob-tag

git update-ref -d refs/tags/blob-tag
git show-ref || echo 'no refs left'
git symbolic-ref HEAD
