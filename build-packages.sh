#!/usr/bin/env bash
# Build loadables as standalone shared objects and pack each one for pkg.
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/config/build-packages.py" "$@"
