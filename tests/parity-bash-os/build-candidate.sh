#!/bin/bash
set -euo pipefail
jobs=${1:?usage: build-candidate.sh JOBS}
[[ $jobs =~ ^[1-9][0-9]*$ && $jobs -le 16 ]] || exit 2
cd /src
report_failure() {
    status=$?
    if (( status != 0 )) && [[ -f out/bash-parity-static.log ]]; then
        tail -160 out/bash-parity-static.log >&2
    fi
    exit "$status"
}
trap report_failure EXIT
JOBS="$jobs" ./build.sh --profile full --include-list config/bash-loadables-optional.list \
    --name parity --static --deps-prefix /build-deps \
    --perl-prefix /usr/lib/bash-os/perl --python-prefix /usr/lib/bash-os/python
case "$(dpkg --print-architecture)" in
    amd64) arch=x86_64 ;;
    arm64) arch=aarch64 ;;
    riscv64) arch=riscv64 ;;
    *) echo 'uv is pinned for amd64, arm64 and riscv64 only' >&2; exit 2 ;;
esac
python3 config/fetch-uv.py "$arch" --out /uv-data
