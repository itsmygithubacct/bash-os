#!/usr/bin/env bash
# What ls-files says is here and what has happened to it, and what ls-tree
# says a tree holds: every selector, the letters -t puts in front, the
# paths named on the command line, and what the two of them refuse.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit checkout merge status ls-files ls-tree
set -e

git init -q -b main .
mkdir -p dir/sub
printf 'a\n' > kept.txt
printf 'b\n' > changed.txt
printf 'c\n' > gone.txt
printf 'd\n' > dir/inside.txt
printf 'e\n' > dir/sub/deep.txt
printf '*.log\nbuild/\n' > .gitignore
printf 'tracked\n' > tracked.log
git add -A
git add -f tracked.log
git commit -q -m 'the first commit'

printf 'B\n' > changed.txt
rm gone.txt
printf 'X\n' >> tracked.log
printf 'f\n' > new.txt
mkdir -p fresh/deeper build t2/git
printf 'g\n' > fresh/deeper/x.txt
printf 'h\n' > noise.log
printf 'i\n' > build/out.o
printf 'j\n' > t2/git-http.py
printf 'k\n' > t2/git/x.sh

echo '=== what the index holds, and what has happened to it ==='
git ls-files
git ls-files -c
git ls-files -m
git ls-files -d
git ls-files -s
git ls-files -t
git ls-files -d -s -t
git ls-files -m -t
git ls-files -m -d
git ls-files -c -m -d -t

echo '=== and what it does not hold ==='
git ls-files -o
git ls-files -o --exclude-standard
git ls-files -o --directory
git ls-files -o --directory --exclude-standard
git ls-files -o -t --exclude-standard
git ls-files -o -i --exclude-standard
git ls-files -o -i --exclude-standard --directory
git ls-files -c -i --exclude-standard
git ls-files -cdmo --exclude-standard
git ls-files -o --exclude-standard t2

echo '=== the paths named on the command line ==='
git ls-files dir
git ls-files -s dir/sub
git ls-files -o dir
git ls-files -m dir

echo '=== and what it refuses ==='
git ls-files -i || echo "said no: $?"
git ls-files -c -i || echo "said no: $?"

echo '=== a path the merge did not settle ==='
git add -A
git commit -q -m 'the second commit'
git checkout -q -b side
printf 'ONE\n' > changed.txt
git commit -q -am 'side changes it'
git checkout -q main
printf 'TWO\n' > changed.txt
git commit -q -am 'main changes it too'
git merge side || echo "merge said no: $?"
git ls-files -u
git ls-files -u -t
git ls-files -t
git ls-files -s
git merge --abort
git status --short

echo '=== a tree, one level at a time ==='
git ls-tree HEAD
git ls-tree -r HEAD
git ls-tree -r -t HEAD
git ls-tree -d HEAD
git ls-tree -l HEAD
git ls-tree HEAD dir
git ls-tree HEAD dir/
git ls-tree HEAD dir/inside.txt
git ls-tree -l HEAD dir/inside.txt
git ls-tree -r -d HEAD dir
git ls-tree -r -t HEAD dir/sub
git ls-tree --name-only HEAD dir/
git ls-tree --abbrev=8 HEAD dir
git ls-tree HEAD nosuch
git ls-tree HEAD dir kept.txt
git ls-tree -l -r HEAD
git ls-tree 'HEAD^{tree}' dir

echo '=== directories that hold nothing, or nothing but ignored files ==='
mkdir -p hollow shut/inside only-ignored deeper/down
printf 'shut/\n' >> .gitignore
printf 'a\n' > shut/inside/a.txt
printf 'b\n' > only-ignored/b.log
printf 'c\n' > deeper/down/c.log
git ls-files -o --directory --exclude-standard
git ls-files -o --directory
git ls-files -o -i --directory --exclude-standard
git ls-files -o -i --exclude-standard
git status --short
git status --ignored --short
git status --ignored --short -uall
git status --porcelain=v2 --ignored
