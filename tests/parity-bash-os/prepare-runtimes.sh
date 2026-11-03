#!/bin/bash
set -euo pipefail
jobs=${1:?usage: prepare-runtimes.sh JOBS}
[[ $jobs =~ ^[1-9][0-9]*$ && $jobs -le 16 ]] || exit 2
cd /src
chmod 0755 build.sh build-deps.sh build-perl.sh build-python.sh
perl_pid=
cleanup() {
    if [[ -n $perl_pid ]]; then
        kill "$perl_pid" 2>/dev/null || true
        wait "$perl_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
python3 config/build-perl.py --prefix /usr/lib/bash-os/perl --jobs "$jobs" &
perl_pid=$!
python3 config/build-deps.py --prefix /build-deps --python --jobs "$jobs"
wait "$perl_pid"
perl_pid=
python3 config/build-python.py --prefix /usr/lib/bash-os/python --deps-prefix /build-deps --jobs "$jobs"
