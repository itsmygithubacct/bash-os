#!/usr/bin/env bash
# Who last touched each line: over a straight history, across a merge
# where the two sides changed different lines, and across a rename, with
# the three shapes the answer is written in.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit branch checkout merge mv blame
set -e

git init -q -b main .
printf 'alpha\nbravo\ncharlie\ndelta\necho\nfoxtrot\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'

printf 'alpha\nBRAVO\ncharlie\ndelta\necho\nfoxtrot\n' > f.txt
GIT_AUTHOR_NAME='Bo Reader' GIT_AUTHOR_EMAIL='bo@bash-os.test' \
GIT_AUTHOR_DATE='1750000200 +0000' GIT_COMMITTER_DATE='1750000200 +0000' \
    git commit -q -am 'the second commit'

echo '=== a straight history ==='
git blame f.txt
git blame -s f.txt
git blame -l f.txt
git blame -L 2,3 f.txt
git blame -L 5 f.txt
git blame HEAD~1 -- f.txt

echo '=== a line from each side of a merge ==='
git checkout -q -b side HEAD~1
printf 'alpha\nbravo\ncharlie\ndelta\nECHO\nfoxtrot\n' > f.txt
GIT_AUTHOR_NAME='Cy Side' GIT_AUTHOR_EMAIL='cy@bash-os.test' \
GIT_AUTHOR_DATE='1750000400 +0000' GIT_COMMITTER_DATE='1750000400 +0000' \
    git commit -q -am 'the side commit'
git checkout -q main
GIT_AUTHOR_NAME='Dee Merger' GIT_AUTHOR_EMAIL='dee@bash-os.test' \
GIT_AUTHOR_DATE='1750000600 +0000' GIT_COMMITTER_DATE='1750000600 +0000' \
    git merge -q --no-edit side
cat f.txt
git blame f.txt
git blame -s f.txt

echo '=== and across a rename ==='
git mv f.txt g.txt
GIT_AUTHOR_NAME='Eve Mover' GIT_AUTHOR_EMAIL='eve@bash-os.test' \
GIT_AUTHOR_DATE='1750000800 +0000' GIT_COMMITTER_DATE='1750000800 +0000' \
    git commit -q -m 'the file is called something else now'
git blame g.txt
git blame -s g.txt
git blame -L 2,4 g.txt

echo '=== a file that came later ==='
printf 'only\nhere\n' > later.txt
git add later.txt
GIT_AUTHOR_DATE='1750001000 +0000' GIT_COMMITTER_DATE='1750001000 +0000' \
    git commit -q -m 'a file of its own'
git blame later.txt
git blame nosuchfile.txt || echo "said no: $?"

echo '=== and the history of the file, past the rename ==='
git log --oneline --follow g.txt
git log --oneline --follow -- g.txt
git log --follow --stat -1 g.txt
git log --oneline g.txt
git log --oneline -- g.txt

echo '=== what is not committed yet ==='
# With no revision named, git blames the file in the working tree: the lines
# that no commit holds are held against no commit, an id of nothing but
# zeros. The time it prints for those is now, so only -s can be compared.
printf 'first line\nsecond line\nthird line\n' > work.txt
git add work.txt
git commit -q -m 'a file to edit'
printf 'first line\nsecond changed\nthird line\nfourth added\n' > work.txt
git blame -s work.txt
git blame -s HEAD -- work.txt
git add work.txt
git blame -s work.txt
printf 'brand new\n' > fresh.txt
git blame fresh.txt 2>&1 || true
git add fresh.txt
git blame -s fresh.txt
git blame -s nosuchfile.txt 2>&1 || true
rm work.txt
git blame -s work.txt 2>&1 || true
