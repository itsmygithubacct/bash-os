#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Instrument the embedding wrapper; the pinned upstream Perl remains uninstrumented.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
BX=$(readlink -f "${1:-out/bash-shell}")
python3 config/build-perl-loadable.py --sanitize --output out/bashperl-sanitize.so
ASAN_LIB=$("${CC:-cc}" -print-file-name=libasan.so)
[[ -f $ASAN_LIB ]] || { echo 'bashperl-sanitize: compiler has no libasan.so' >&2; exit 1; }
LD_PRELOAD="$ASAN_LIB${LD_PRELOAD:+:$LD_PRELOAD}" \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/bashperl.py "$BX" --module out/bashperl-sanitize.so
