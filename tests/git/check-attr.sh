#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Attribute states, precedence, index fallback, macros and input framing.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit check-attr
set -e

git init -q -b main .
mkdir sub
printf '*.txt language=base review -draft caveat=unspecified\nsub/*.txt scope=top\n"sub/space name.txt" spaced\n[attr]bundle -diff merge=ours\n*.bin bundle\n' > .gitattributes
printf '*.txt language=sub !review local\n' > sub/.gitattributes
printf 'hello\n' > root.txt
printf 'hello\n' > sub/note.txt
printf 'hello\n' > 'sub/space name.txt'
printf 'binary\000x' > data.bin
git add .gitattributes sub/.gitattributes root.txt sub/note.txt 'sub/space name.txt' data.bin
git commit -q -m 'attributes and files'

echo '=== explicit and all ==='
git check-attr language review draft scope local -- root.txt sub/note.txt
git check-attr caveat -- root.txt
git check-attr --all -- root.txt sub/note.txt data.bin
git check-attr language root.txt
git check-attr --all -- 'sub/space name.txt'

echo '=== worktree, index and stronger info rules ==='
printf '*.txt language=worktree\n' >> .gitattributes
git check-attr language -- root.txt sub/note.txt
git check-attr --cached language -- root.txt sub/note.txt
printf '*.txt language=info review\n' > .git/info/attributes
git check-attr language review -- root.txt sub/note.txt
git check-attr --cached language review -- root.txt sub/note.txt

echo '=== source tree and configured global attributes ==='
git check-attr --source HEAD language review -- root.txt sub/note.txt
printf '*.txt global-token=global\n' > global.attributes
git -c core.attributesFile=global.attributes check-attr global-token -- root.txt sub/note.txt

echo '=== standard input and NUL records ==='
printf 'root.txt\nsub/note.txt\n' | git check-attr --stdin language review
printf 'root.txt\000sub/space name.txt\000' | git check-attr --stdin -z language review | od -An -tx1

echo '=== from a subdirectory ==='
(cd sub && git check-attr language local -- note.txt)
