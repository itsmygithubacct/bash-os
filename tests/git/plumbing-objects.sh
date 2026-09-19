#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Phase 0 plumbing: objects, the index, trees, refs and ignore rules.
# Every command here must give bash-os's git and real git the same output and
# the same repository. Run through tests/git-parity.py, never on its own.
set -e

git init -q -b main .

printf 'hello\n' > hello.txt
blob=$(git hash-object -w hello.txt)
echo "blob $blob"
git cat-file -t "$blob"
git cat-file -s "$blob"
git cat-file -p "$blob"
git cat-file -e "$blob" && echo "cat-file -e: present"
printf '%s\n' "$blob" | git cat-file --batch-check
git rev-parse --short "$blob"

printf 'second\n' > second.txt
second=$(git hash-object -w --stdin < second.txt)
git update-index --add --cacheinfo "100644,$blob,hello.txt"
git update-index --add --cacheinfo "100644,$second,dir/second.txt"
git ls-files -s

tree=$(git write-tree)
echo "tree $tree"
git ls-tree "$tree"
git ls-tree -r "$tree"
git cat-file -p "$tree"

commit=$(git commit-tree "$tree" -m 'plumbing commit')
git update-ref refs/heads/main "$commit" ''
git symbolic-ref HEAD
git rev-parse HEAD
git rev-parse HEAD^{tree}
git cat-file -p HEAD
git for-each-ref --format='%(refname) %(objecttype) %(objectname)'
git show-ref --head

second_commit=$(git commit-tree "$tree" -p "$commit" -m 'second plumbing commit')
git update-ref refs/heads/main "$second_commit" "$commit"
git rev-parse HEAD HEAD~1 HEAD^ 'HEAD@{0}'
git rev-list --count HEAD

git tag -m 'annotated from plumbing' v0 HEAD
git cat-file -t refs/tags/v0
git for-each-ref --format='%(refname) %(objecttype)' refs/tags

printf 'ignored\n' > ignore-me.log
printf '*.log\n' > .gitignore
git check-ignore -v ignore-me.log
git status --porcelain

git config user.name 'Config Reader'
git config --get user.name
git config --list --local
git var GIT_AUTHOR_IDENT
