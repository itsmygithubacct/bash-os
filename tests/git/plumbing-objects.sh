#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Phase 0 plumbing: objects, the index, trees, refs and ignore rules.
# Every command here must give bash-os's git and real git the same output and
# the same repository. Run through tests/git-parity.py, never on its own.
# requires: init hash-object cat-file update-index ls-files write-tree ls-tree
# requires: commit-tree update-ref symbolic-ref rev-parse rev-list show-ref
# requires: for-each-ref tag check-ignore status config var
# requires: whatchanged annotate blame diff log
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

# What the store holds, counted: loose objects and what they take up, and
# the same after they have been packed away.
git count-objects
git count-objects -v
git count-objects -H
git count-objects -v -H

# What each file was and what it became, which is the raw form of a diff.
git diff --raw HEAD~1 HEAD
git log --raw -2 --format='%h'
git whatchanged --oneline -2
git annotate hello.txt
git blame -c hello.txt

# Every object the store holds, in id order, without being asked for one at
# a time.
git cat-file --batch-all-objects --batch-check
git cat-file --batch-all-objects --batch-check --unordered
git cat-file --batch-all-objects --batch
