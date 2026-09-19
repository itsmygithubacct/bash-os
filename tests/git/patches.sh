#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Patches: hunks with context and function names, added, deleted and renamed
# modes, the stat forms, and what show prints. Run through tests/git-parity.py,
# never on its own.
# requires: init add commit diff log show status tag rm
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
printf 'int main(void)\n{\n\tint x = 1;\n\tint y = 2;\n\tint z = 3;\n\treturn x + y + z;\n}\n\nstatic void helper(void)\n{\n\tputs("one");\n\tputs("two");\n\tputs("three");\n\tputs("four");\n\tputs("five");\n}\n' > code.c
printf 'alpha\nbravo\ncharlie\n' > words.txt
git add .
git commit -m 'first commit'

# Two changes far enough apart to be two hunks, each with a function name.
printf 'int main(void)\n{\n\tint x = 1;\n\tint y = 22;\n\tint z = 3;\n\treturn x + y + z;\n}\n\nstatic void helper(void)\n{\n\tputs("one");\n\tputs("two");\n\tputs("THREE");\n\tputs("four");\n\tputs("five");\n}\n' > code.c
echo '=== diff ==='
git diff
echo '=== diff --stat ==='
git diff --stat
git diff --numstat
git diff --shortstat
echo '=== diff -U1 and -U0 ==='
git diff -U1
git diff -U0
echo '=== diff --name-only, --name-status, -s ==='
git diff --name-only
git diff --name-status
git diff -s
echo '=== staged and unstaged ==='
git add code.c
printf 'alpha\nbravo\ncharlie\ndelta\n' > words.txt
git diff
git diff --cached
git diff HEAD
echo '=== status long ==='
git status
git add words.txt
git status
git commit -m 'second commit'

# A file that does not end in a newline, one added, one deleted.
printf 'no newline at the end' > ragged.txt
git add ragged.txt
git commit -m 'ragged'
printf 'no newline at the end, changed' > ragged.txt
git diff
git add ragged.txt
git commit -m 'ragged again'
git rm -q words.txt
git commit -m 'remove words'
git show --stat
echo '=== a mode change alone ==='
chmod 755 code.c
git diff
git diff --stat
git diff --summary
git add code.c
git commit -m 'make it executable'

echo '=== show ==='
git show
git show --oneline -s
git show HEAD:ragged.txt
git show 'HEAD:'
git tag -a v1 -m 'the tag'
git show v1
echo '=== log -p and --stat ==='
git log -p -2
git log --stat -2
git log --oneline -p -1
echo '=== blank lines and indentation move a hunk ==='
printf 'one\n\ntwo\n\nthree\n\nfour\n' > blocks.txt
git add blocks.txt
git commit -q -m blocks
printf 'one\n\ntwo\n\nthree\n\nthree and a half\n\nfour\n' > blocks.txt
git diff
printf 'def alpha():\n    return 1\n\n\ndef beta():\n    return 2\n' > mod.py
git add mod.py
git commit -q -m python
printf 'def alpha():\n    return 1\n\n\ndef middle():\n    return 15\n\n\ndef beta():\n    return 2\n' > mod.py
git diff
git status --short
git status
