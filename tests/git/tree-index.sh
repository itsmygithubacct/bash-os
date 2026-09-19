#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The index, trees, commits and revision syntax: Phase 0's plumbing.
# Run through tests/git-parity.py, never on its own.
# requires: init hash-object update-index ls-files write-tree ls-tree
# requires: commit-tree update-ref rev-parse cat-file rev-list read-tree var
set -e

git init -q -b main .

printf 'hello\n' > hello.txt
mkdir -p sub
printf 'nested\n' > sub/file.txt
printf 'sorts near sub\n' > sub.txt
blob=$(git hash-object -w hello.txt)
nested=$(git hash-object -w sub/file.txt)
near=$(git hash-object -w sub.txt)

git update-index --add --cacheinfo "100644,$blob,hello.txt"
git update-index --add --cacheinfo "100644,$nested,sub/file.txt"
git update-index --add --cacheinfo "100644,$near,sub.txt"
git ls-files
git ls-files -s

tree=$(git write-tree)
echo "tree $tree"
git ls-tree "$tree"
git ls-tree -r "$tree"
git ls-tree -r -t "$tree"
git ls-tree --name-only "$tree"
git cat-file -p "$tree"
git cat-file -t "$tree"

commit=$(git commit-tree "$tree" -m 'first commit')
git update-ref refs/heads/main "$commit"
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
git rev-parse --short HEAD
git cat-file -p HEAD
git cat-file commit HEAD

printf 'changed\n' > hello.txt
changed=$(git hash-object -w hello.txt)
git update-index --add --cacheinfo "100644,$changed,hello.txt"
tree2=$(git write-tree)
# A later date, so the two commits order the same way for everyone.
second=$(GIT_COMMITTER_DATE='1750000200 +0000' GIT_AUTHOR_DATE='1750000200 +0000' \
         git commit-tree "$tree2" -p "$commit" -m 'second commit')
git update-ref refs/heads/main "$second" "$commit"

git rev-parse HEAD 'HEAD^' 'HEAD~1' 'HEAD^{commit}' 'HEAD^{tree}' 'HEAD^0'
git rev-list --count HEAD
git rev-list HEAD
git rev-list -n 1 HEAD
git rev-parse 'main@{0}'
git rev-parse 'main@{1}'
git rev-parse --verify HEAD

git read-tree "$tree"
git ls-files -s
git read-tree HEAD
git ls-files -s

git var GIT_AUTHOR_IDENT
git var GIT_COMMITTER_IDENT
