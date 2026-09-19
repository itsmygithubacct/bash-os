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

# Syntax written by hand: continuations, escapes, and a subsection.
cat >> .git/config <<'HAND'
[section]
	continued = one \
two
	quoted = "has \"quotes\" and a \ttab"
	implicit
	spaced = value # with a comment
[section "Sub Section"]
	key = subsection value
HAND
git config --get section.continued
git config --get section.quoted
git config --get section.implicit
git config --get section.spaced
git config --get 'section.Sub Section.key'
git config --list

# include.path pulls in another file at that point.
# A relative include is resolved against the file that names it, so this
# one lives beside .git/config.
printf '[included]\n\tkey = from the include\n' > .git/extra.cfg
git config include.path extra.cfg
git config --get included.key
git config --list

# The file is git's own format, so git reads back what was written.
cat .git/config
