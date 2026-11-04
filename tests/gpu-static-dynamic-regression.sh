#!/usr/bin/env bash
# Run only in a disposable GPU VM after building both candidates and fixture.
# The hardware smoke test must not silently skip its native section.
set -euo pipefail
cd "$(dirname "$0")/.."
static=${1:?usage: gpu-static-dynamic-regression.sh STATIC_BASH DYNAMIC_BASH FIXTURE_SO RENDER_NODE}
dynamic=${2:?missing dynamically linked Bash}
fixture=${3:?missing driver fixture}
device=${4:?missing GPU render node}
[[ -x $static && -x $dynamic && -f $fixture && -f $fixture.missing.so ]] || {
    echo 'Missing candidate or driver fixture' >&2; exit 2;
}
[[ -c $device && -r $device && -w $device ]] || {
    echo 'A readable and writable render node is required' >&2; exit 2;
}
for candidate in "$static" "$dynamic"; do
    printf 'Qualifying %s against hardware\n' "$candidate"
    GPU_TEST_DEVICE="$device" python3 tests/gpu-smoke.py "$candidate"
    python3 tests/sol-gpu-frames.py "$candidate" --device "$device" --frames 2
    printf 'Qualifying %s against injectable driver\n' "$candidate"
    python3 tests/sol-gpu-errors.py "$candidate" "$fixture"
done
