#!/usr/bin/env bash
# What fsck says about a repository: the objects nothing reaches, the links
# it cannot follow, and an object that is not what its name says. git lists
# those in the order of its own object table, which is not reproduced here,
# so every listing is sorted before it is compared.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit tag rm hash-object commit-tree fsck rev-parse
set -e

said () { if "$@" > /dev/null 2>&1; then echo 'said: 0'; else echo "said: $?"; fi; }

git init -q -b main .
printf 'one\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'
printf 'two\n' > f.txt
git commit -q -am 'the second commit'
git tag -a v1 -m 'the first tag'

echo '=== a repository with nothing wrong with it ==='
git fsck
said git fsck
git fsck --connectivity-only
said git fsck --connectivity-only

echo '=== objects nothing points at ==='
printf 'loose one\n' | git hash-object -w --stdin
printf 'loose two\n' | git hash-object -w --stdin
git commit-tree -m 'a commit nothing points at' "$(git rev-parse HEAD^{tree})"
git fsck 2>&1 | sort
said git fsck
git fsck --no-dangling 2>&1 | sort
git fsck --unreachable 2>&1 | sort
git fsck --unreachable --no-reflogs 2>&1 | sort

echo '=== what is staged is held ==='
printf 'staged\n' > s.txt
git add s.txt
git fsck 2>&1 | sort
git rm -q --cached s.txt
rm -f s.txt
git fsck 2>&1 | sort

echo '=== roots and tags ==='
git fsck --root 2>&1 | sort
git fsck --tags 2>&1 | sort

echo '=== walking out from what is named instead ==='
git fsck HEAD 2>&1 | sort
git fsck "$(git rev-parse HEAD)" 2>&1 | sort
git fsck nosuchthing 2>&1 | sort
said git fsck nosuchthing

echo '=== a link it cannot follow ==='
mkdir broken
(
  cd broken
  git init -q -b main .
  printf 'held\n' > held.txt
  git add held.txt
  git commit -q -m 'the only commit'
  blob=$(git rev-parse HEAD:held.txt)
  rm -f ".git/objects/${blob%"${blob#??}"}/${blob#??}"
  git fsck 2>&1 | sort
  said git fsck
  git fsck --connectivity-only 2>&1 | sort
)

echo '=== an object that is not what its name says ==='
mkdir swapped
(
  cd swapped
  git init -q -b main .
  printf 'first\n' > a.txt
  printf 'second\n' > b.txt
  git add a.txt b.txt
  git commit -q -m 'two files'
  a=$(git rev-parse HEAD:a.txt)
  b=$(git rev-parse HEAD:b.txt)
  # One object's bytes under another's name: the name no longer says what
  # the file holds, which is the thing fsck is for.
  rm -f ".git/objects/${a%"${a#??}"}/${a#??}"
  cp ".git/objects/${b%"${b#??}"}/${b#??}" ".git/objects/${a%"${a#??}"}/${a#??}"
  git fsck 2>&1 | sort
  said git fsck
)

rm -rf broken swapped
