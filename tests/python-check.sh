#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Optional Python integration: compiled-in and enable -f forms.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
export JOBS=${JOBS:-4}
./build-deps.sh
./build.sh --include bashpython --name python
python3 tests/bashpython.py out/bash-python
python3 tests/profile-smoke.py out/bash-python
./build.sh --profile shell --clean
python3 tests/profile-smoke.py out/bash-shell
python3 config/build-python-loadable.py
python3 tests/bashpython.py out/bash-shell --module out/bashpython.so
./build.sh --include pkg --name pkg
python3 tests/bashpython-package.py out/bash-pkg
