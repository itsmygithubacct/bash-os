# free

`free` prints a memory summary from `/proc/meminfo`. Default units are
kibibytes (`-k`). `BASHOS_PROC_ROOT` selects an alternate proc tree so tests
can pin `meminfo`.

```sh
out/bash -c 'PATH=; free -k'
BASHOS_PROC_ROOT=/tmp/proc out/bash -c 'PATH=; free -k'
```

## Compatibility

`tests/free-check.sh` drives the shipped builtin with an empty `PATH`. On the
catalog binary it is **18/18**: default `-k` columns against a disposable
meminfo fixture, `--help`/`-V`, extra-operand failure, a missing meminfo
error, and GNU `free -k` header/field-name/row-label comparison that does not
use live counters. A fixture `MemTotal` of 424242 kB is printed as that total
and is not the host's live `MemTotal`.

The header line and field names match procps-ng 4.0.4 `free -k`:

`total used free shared buff/cache available`, then `Mem:` and `Swap:`.

`used` is `MemTotal - MemAvailable` when `MemAvailable` is present, the same
as GNU. `buff/cache` is not: the builtin uses
`Buffers + Cached + SReclaimable - Shmem`; GNU leaves `Shmem` inside
`buff/cache`. The two `buff/cache` columns differ by exactly `shared`.
BusyBox `free -k` uses a third `used` formula. None of those numeric
mismatches is a parser failure: the fixture still prints the known
`MemTotal`.

`--help` is `builtin_usage` (short catalog line on stderr). `-V` prints
`bashfree 1.0 (bash-loadable)`. GNU extra operands exit 1 with its own usage;
the builtin exits 2 with `unexpected operand`.

## Measurements, 2026-09-10

Catalog full binary SHA-256
`9b2c69c9b8dc1c8cb437904afeacc51919fc4db31fc676d0c41137a2c8caad73`,
`free.c` unchanged since that snapshot, pinned to CPU 11. Host: Intel Core
i7-9850H, Linux 6.12.96, x86-64, procps-ng 4.0.4. Raw JSON:
`~/research/bash-os/free.json`. `normalizer='fields'` on `free -k`.

JSON `status` is **INVALID**. No speed ratio.

| Implementation | status |
| --- | --- |
| builtin | `output-mismatch` vs GNU |
| BusyBox | `output-mismatch` vs GNU |
| GNU | `batch-mismatch` (live counters moved between the first capture and the repeated batch) |

The first-call mismatch is the `buff/cache` formula plus counters moving
between the GNU capture and the builtin capture. GNU then fails its own
whole-batch check because `free` rereads `/proc/meminfo` every invocation,
so the first snapshot cannot be repeated. The harness recorded no
`median_ms` on any side.

```sh
python3 bench/loadables.py --only free --cpu 11 --runs 7 \
  --binary out/bash-catalog-9b2c69c9 --output /tmp/free.json
```

Do not fold these numbers into the catalog snapshot JSON.
