#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Patch names read from a diff stream: one patch, several commits, reordered
# files, whitespace kept or removed, and a binary change.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit diff log show format-patch patch-id
set -e

git init -q -b main .
printf 'one\ntwo\nthree\n' > a.txt
printf 'alpha\nbeta\ngamma\n' > b.txt
git add a.txt b.txt
git commit -q -m 'two files'
printf 'one\nTWO\nthree\n' > a.txt
printf 'alpha\nBETA\ngamma\n' > b.txt
git add a.txt b.txt
git commit -q -m 'change both files'

echo '=== one patch and a stream of commits ==='
git show --pretty=format: HEAD | git patch-id
git diff HEAD~1 HEAD | git patch-id --unstable
git log -2 -p | git patch-id
git format-patch --stdout -2 | git patch-id --stable

echo '=== file order matters only to the old form ==='
git diff HEAD~1 HEAD -- a.txt > a.patch
git diff HEAD~1 HEAD -- b.txt > b.patch
cat a.patch b.patch | git patch-id --unstable
cat b.patch a.patch | git patch-id --unstable
cat a.patch b.patch | git patch-id --stable
cat b.patch a.patch | git patch-id --stable

echo '=== configuration and whitespace kept verbatim ==='
cat a.patch b.patch | git -c patchid.stable=true patch-id
cat a.patch b.patch | git -c patchid.verbatim=true patch-id
cat a.patch b.patch | git patch-id --verbatim
printf 'not a patch\n' | git patch-id
printf '' | git -c patchid.stable=bogus patch-id 2>&1 || true
printf '' | git -c patchid.verbatim=bogus patch-id --stable 2>&1 || true

echo '=== binary ids stand in for binary contents ==='
printf 'binary\000first\n' > 0.bin
git add 0.bin
git commit -q -m 'a binary file'
printf 'binary\000second\n' > 0.bin
printf 'one\nTWO again\nthree\n' > a.txt
git diff | git patch-id
git diff | git patch-id --stable

rm -f a.patch b.patch
