#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Patience and histogram choose anchors from repeated input lines.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit diff show log
set -e

git init -q -b main .
cat > lines.txt <<'EOF'
u
u
d
d
d
w
u
c
b
d
b
u
w
EOF
git add lines.txt
git commit -q -m 'repeated lines before'
cat > lines.txt <<'EOF'
c
u
a
b
c
d
u
u
u
b
d
w
a
EOF

echo '=== named algorithms ==='
git diff --patience -U0 lines.txt
git diff --histogram -U0 lines.txt
git diff --diff-algorithm=patience -U0 lines.txt
git diff --diff-algorithm=histogram -U0 lines.txt
git -c diff.algorithm=patience diff -U0 lines.txt
git -c diff.algorithm=histogram diff --numstat lines.txt
git -c diff.algorithm=histogram diff --diff-algorithm=myers --numstat lines.txt
git diff --histogram --numstat lines.txt

echo '=== committed algorithms ==='
git add lines.txt
git commit -q -m 'repeated lines after'
git show -U0 --patience HEAD
git log -1 -p -U0 --diff-algorithm=histogram

echo '=== patience fallback with no unique common line ==='
printf 'same\nother\nsame\nother\n' > repeated.txt
git add repeated.txt
git commit -q -m 'no unique common lines'
printf 'other\nsame\nother\nsame\n' > repeated.txt
git diff --patience -U0 repeated.txt
