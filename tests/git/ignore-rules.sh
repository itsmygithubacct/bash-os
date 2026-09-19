#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# .gitignore rules: anchoring, negation, directories, ** and per-directory
# files. Run through tests/git-parity.py, never on its own.
# requires: init check-ignore
set -e

git init -q -b main .

cat > .gitignore <<'PATTERNS'
# comments and blank lines are skipped

*.log
!keep.log
build/
/root-only.txt
docs/**/draft.md
sub/*.tmp
**/anywhere.dat
trailing-space
PATTERNS

mkdir -p build docs/a/b sub deep/sub nested/build
: > a.log
: > keep.log
: > root-only.txt
: > sub/root-only.txt
: > sub/x.tmp
: > deep/sub/y.tmp
: > docs/draft.md
: > docs/a/b/draft.md
: > deep/anywhere.dat
: > anywhere.dat
: > sub/nested-ignore
printf 'nested-ignore\n' > sub/.gitignore

for path in a.log keep.log build nested/build root-only.txt sub/root-only.txt \
            sub/x.tmp deep/sub/y.tmp docs/draft.md docs/a/b/draft.md \
            anywhere.dat deep/anywhere.dat sub/nested-ignore not-ignored.txt; do
  if git check-ignore -v "$path"; then :; else echo "not ignored: $path"; fi
done

git check-ignore -v --non-matching keep.log not-ignored.txt || echo "non-matching exits $?"
git check-ignore a.log docs/draft.md
if git check-ignore not-ignored.txt; then echo 'unexpected match'; else echo "no match exits $?"; fi
