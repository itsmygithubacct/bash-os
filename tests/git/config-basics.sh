#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Reading and writing configuration, and `git -c`.
# Run through tests/git-parity.py, never on its own.
# requires: init config
set -e

git init -q -b main .

git config user.name 'Config Reader'
git config user.email 'config@bash-os.test'
git config --get user.name
git config user.email

git config --add remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'
git config --add remote.origin.fetch '+refs/tags/*:refs/tags/*'
git config --get-all remote.origin.fetch
git config --get remote.origin.fetch

git config core.bigFileThreshold '  spaced value  '
git config --get core.bigfilethreshold
git config 'branch.main.description' 'a line with # a comment character'
git config --get branch.main.description

git config --list

git config --unset user.email
git config --list
if git config --get user.email; then echo 'user.email is still set'; else echo "--get on a missing key exits $?"; fi

git -c user.name=Override config --get user.name
git config --get user.name

# The file is git's own format, so git reads back what was written.
cat .git/config
