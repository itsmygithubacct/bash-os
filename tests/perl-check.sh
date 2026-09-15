#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Optional Perl integration: compiled-in, fully static, and enable -f forms.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
export JOBS=${JOBS:-4}
./build.sh --include bashperl --name perl
python3 tests/perl-engine.py
python3 tests/bashperl.py out/bash-perl
python3 tests/profile-smoke.py out/bash-perl
./build.sh --include bashperl --name perl --static
python3 tests/bashperl.py out/bash-perl-static
python3 tests/profile-smoke.py out/bash-perl-static
./build.sh --profile shell
python3 tests/profile-smoke.py out/bash-shell
python3 config/build-perl-loadable.py
python3 tests/bashperl.py out/bash-shell --module out/bashperl.so
