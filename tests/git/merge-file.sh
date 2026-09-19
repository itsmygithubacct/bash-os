#!/usr/bin/env bash
# The three-way merge of one file's three versions: what each side changed
# alone, what both changed the same way, and what neither can settle.
# Run through tests/git-parity.py, never on its own.
# requires: merge-file
set -e

printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n' > base.txt

echo '=== each side changed a different line ==='
printf 'ONE\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n' > ours.txt
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\nEIGHT\n' > theirs.txt
cp ours.txt work.txt
git merge-file -p work.txt base.txt theirs.txt
echo "status: $?"

echo '=== both changed the same line, the same way ==='
printf 'one\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight\n' > ours.txt
cp ours.txt theirs.txt
cp ours.txt work.txt
git merge-file -p work.txt base.txt theirs.txt
echo "status: $?"

echo '=== both changed the same line, differently ==='
printf 'one\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight\n' > ours.txt
printf 'one\ntwo\ndrei\nfour\nfive\nsix\nseven\neight\n' > theirs.txt
cp ours.txt work.txt
git merge-file -p work.txt base.txt theirs.txt || echo "conflicts: $?"

echo '=== labels ==='
git merge-file -p -L ours -L base -L theirs work.txt base.txt theirs.txt \
  || echo "conflicts: $?"

echo '=== one side added lines, the other changed nearby ==='
printf 'one\ntwo\nthree\nthree and a half\nfour\nfive\nsix\nseven\neight\n' > ours.txt
printf 'one\ntwo\nthree\nfour\nFIVE\nsix\nseven\neight\n' > theirs.txt
cp ours.txt work.txt
git merge-file -p work.txt base.txt theirs.txt
echo "status: $?"

echo '=== one side deleted what the other changed ==='
printf 'one\ntwo\nfour\nfive\nsix\nseven\neight\n' > ours.txt
printf 'one\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight\n' > theirs.txt
cp ours.txt work.txt
git merge-file -p work.txt base.txt theirs.txt || echo "conflicts: $?"

echo '=== both added at the end, differently ==='
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nours\n' > ours.txt
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\ntheirs\n' > theirs.txt
cp ours.txt work.txt
git merge-file -p work.txt base.txt theirs.txt || echo "conflicts: $?"

echo '=== writing the file in place ==='
cp ours.txt work.txt
git merge-file work.txt base.txt theirs.txt || echo "conflicts: $?"
cat work.txt

echo '=== an empty base ==='
: > empty.txt
printf 'ours only\n' > ours.txt
printf 'theirs only\n' > theirs.txt
cp ours.txt work.txt
git merge-file -p work.txt empty.txt theirs.txt || echo "conflicts: $?"

echo '=== no trailing newline ==='
printf 'one\ntwo\nthree' > ragged-base.txt
printf 'ONE\ntwo\nthree' > ours.txt
printf 'one\ntwo\nTHREE' > theirs.txt
cp ours.txt work.txt
git merge-file -p work.txt ragged-base.txt theirs.txt
echo "status: $?"
