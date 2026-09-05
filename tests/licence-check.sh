#!/usr/bin/env bash
# tests/licence-check.sh — every source states its licence, and only the files
# named here may be anything but MIT. Guards the repo's own licence claim
# (README, docs/PROVENANCE.md) as more loadables are imported.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
NON_MIT=""                      # every source is MIT; list a path here only with a reason
MIT='SPDX-License-Identifier: MIT|MIT License|\bMIT\b|Permission is hereby granted, free of charge'
GPL='SPDX-License-Identifier: GPL|GNU General Public License'
bad=0; n=0
for f in loadables/*.c loadables/*.h loadables/*/*.h tests/*.c; do
  [[ -f $f ]] || continue; n=$((n+1))
  if grep -qE "$MIT" "$f"; then continue; fi
  if grep -qE "$GPL" "$f"; then
    case " $NON_MIT " in *" $f "*) continue ;; esac
    echo "  GPL-licensed file not in the allowed list: $f"; bad=$((bad+1)); continue
  fi
  echo "  no licence marker: $f"; bad=$((bad+1))
done
for f in $NON_MIT; do [[ -f $f ]] || { echo "  allowed non-MIT file missing: $f"; bad=$((bad+1)); }; done
[[ -f LICENSE ]] || { echo "  LICENSE missing"; bad=$((bad+1)); }
echo "licence-check: $n files, $bad problems"; exit $(( bad>0 ? 1 : 0 ))
