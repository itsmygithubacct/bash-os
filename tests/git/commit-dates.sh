#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The date an author or committer line carries when the environment names
# one: every form git takes, and its refusal of the forms it does not.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit log cat-file tag
set -e

git init -q -b main .
printf 'a line\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'

said () { "$@" && echo 'status 0' || echo "status $?"; }
at () {
    GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" \
        git commit -q --allow-empty -m "named $1"
    git log -1 --format='%ad|%cd' --date=raw
}

echo '=== the forms git takes ==='
at '1750000000 +0000'
at '@1750000000'
at '@1750000000 +0200'
at '2026-01-02T03:04:05+00:00'
at '2026-01-02T03:04:05Z'
at '2026-01-02 03:04:05 +0000'
at '2026-01-02 03:04:05 -0730'
at '2026-01-02 03:04'
at '2026.01.02 03:04:05'
at '2026/01/02 03:04:05'
at '2 Jan 2026 03:04:05 +0100'
at 'Fri, 2 Jan 2026 03:04:05 +0100'
at '2026-01-02T03:04:05+05:30'

echo '=== and the ones it does not ==='
said env GIT_AUTHOR_DATE=2026-01-02 git commit -q --allow-empty -m 'a day alone'
said env GIT_AUTHOR_DATE=nonsense git commit -q --allow-empty -m 'not a date'
said env GIT_AUTHOR_DATE='2 days ago' git commit -q --allow-empty -m 'relative'
said env GIT_COMMITTER_DATE=nonsense git commit -q --allow-empty -m 'the other one'
said env GIT_AUTHOR_DATE='2026-13-02 03:04:05' git commit -q --allow-empty -m 'no such month'

echo '=== what the log says of them all ==='
git log --format='%h %ad %cd' --date=iso
git log -1 --format='%at %ct'

echo '=== a tag carries one too ==='
GIT_COMMITTER_DATE='2026-01-02T03:04:05+00:00' git tag -m 'dated' dated
git cat-file tag dated | sed -n '4p'
said env GIT_COMMITTER_DATE=nonsense git tag -m 'no good' nogood
