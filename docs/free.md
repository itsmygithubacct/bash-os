# free

`free` prints a memory summary from `/proc/meminfo`. Default units are
kibibytes (`-k`). `BASHOS_PROC_ROOT` selects an alternate proc tree so tests
can pin `meminfo`.

```sh
./build.sh --include free --name free
out/bash-free -c 'PATH=; free -k'
BASHOS_PROC_ROOT=/tmp/proc out/bash-free -c 'PATH=; free -k'
```

## Compatibility

`buff/cache` is `Buffers + Cached + SReclaimable`, the same as procps-ng
4.0.4. Shmem stays inside that column; it is not subtracted. `-L` `CachUse`
uses the same total. `used` is `MemTotal - MemAvailable` when available is
present. Headers and row labels are unchanged.

`tests/free-check.sh` drives the shipped builtin with an empty `PATH`. On
`out/bash-free` it is **19/19**: default `-k` columns against a disposable
meminfo fixture, `-L` `CachUse`, `--help`/`-V`, extra-operand failure, a
missing meminfo error, and GNU `free -k` header/field-name/row-label
comparison that does not use live counters. A fixture `MemTotal` of 424242
kB is printed as that total. Fixture `buff/cache` is **7777**
(`1111+2222+4444`), not the old Shmem-subtracted **4444**.

The header line and field names match GNU `free -k`:

`total used free shared buff/cache available`, then `Mem:` and `Swap:`.

BusyBox `free -k` still uses a different `used` formula. `--help` is
`builtin_usage` (short catalog line on stderr). `-V` prints
`bashfree 1.0 (bash-loadable)`. GNU extra operands exit 1 with its own usage;
the builtin exits 2 with `unexpected operand`.

## Measurements, 2026-09-11

`out/bash-free` (one injected builtin), SHA-256
`cd938b49a2be1b3614ef707744efa9cf405c79d0ac53fd98ccd6d90408eb056e`,
pinned to CPU 11. Host: Intel Core i7-9850H, Linux 6.12.96, x86-64,
procps-ng 4.0.4. Raw JSON: `~/research/bash-os/free-buffcache.json`.
`normalizer='fields'` on `free -k`.

A single invocation of the rebuilt builtin matched GNU `free -k` **exactly**
(byte-identical, including `buff/cache`). The first-call `output-mismatch`
from the catalog snapshot is gone.

JSON `status` is still **INVALID**. No speed ratio. Live counters move
between invocations, so a whole-batch check cannot replay the first snapshot.

| Implementation | status |
| --- | --- |
| builtin | `batch-mismatch` (live `/proc/meminfo` changed across the batch) |
| GNU | `batch-mismatch` (same cause; GNU fails its own repeated-batch check) |
| BusyBox | `output-mismatch` vs GNU (`used` formula) |

The harness recorded no `median_ms` on any side.

```sh
python3 bench/loadables.py --only free --cpu 11 --runs 7 \
  --binary out/bash-free --output /tmp/free-buffcache.json
```

Do not fold these numbers into the catalog snapshot JSON.
