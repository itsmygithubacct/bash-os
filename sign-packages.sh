#!/usr/bin/env bash
# Create a pkg publisher key, or sign built packages into a release directory.
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/config/sign-packages.py" "$@"
