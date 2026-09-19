#!/usr/bin/env bash
# Packfiles: making one, indexing it, checking it, and unpacking it again.
# A pack's index is a function of the pack, so indexing the same pack twice
# must give the same bytes — which is what the comparison here asks for,
# rather than that two implementations pack alike. The packs live under
# HOME, which the harness does not compare. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit rev-list pack-objects index-pack unpack-objects
# requires: verify-pack cat-file
set -e

git init -q -b main .
for i in 1 2 3 4; do
  printf 'line %d of the file\n' "$i" >> a.txt
  printf 'another file, revision %d\n' "$i" > b.txt
  git add .
  git commit -q -m "commit $i"
done

mkdir -p "$HOME/packs"
git rev-list --objects --all | cut -d' ' -f1 | sort > "$HOME/ids"
# Counting the ids here also leaves the input at end of file, which the
# next command must not inherit: it once read nothing and packed nothing.
wc -l < "$HOME/ids"
git pack-objects "$HOME/packs/made" < "$HOME/ids" > "$HOME/name"
cd "$HOME/packs"
name=$(cat "$HOME/name")
test -f "made-$name.pack" && echo 'the pack is there'
test -f "made-$name.idx" && echo 'so is its index'

echo '=== indexing it again gives the same index ==='
mkdir -p again
cp "made-$name.pack" again/copy.pack
cd again
git index-pack copy.pack > /dev/null
cmp -s copy.idx "../made-$name.idx" && echo 'the index is the same bytes'

echo '=== verifying it ==='
# Verifying says nothing when the pack is sound; the status is the answer.
git verify-pack copy.idx && echo 'verify says it is sound'

echo '=== unpacking it into a fresh repository ==='
cd "$HOME"
git init -q -b main unpacked
cd unpacked
# Nothing is printed: git keeps its progress off a pipe, and so does this.
git unpack-objects < "$HOME/packs/made-$name.pack"
# Every object the pack was made from is here, and is what it was. The
# harness runs real git's fsck over both trees afterwards.
while read -r id; do git cat-file -t "$id"; done < "$HOME/ids" | sort
cd "$HOME"
