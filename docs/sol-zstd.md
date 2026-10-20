# zstd streaming completion

`zstd` and `zstdcat` stream input and output through two fixed 128 KiB buffers.
Compression uses a fresh libzstd streaming context for each input, with levels
1 through 19 and default level 3. Memory depends on the selected compression
level or decoder window, rather than total file size. The decoder explicitly
limits windows to 128 MiB and reads concatenated frames, including unknown-size
and skippable frames. Larger-window streams fail with a library diagnostic.
There is no total input or decompressed-output size cap.

Named destinations are written to a private temporary file in the destination
directory. After the codec, input close, metadata, and output close succeed,
`-f` publishes with `rename`; the default uses `link` to prevent overwriting a
destination created during processing. Failed processing preserves the source
and an existing destination and removes the temporary file. `--rm` removes the
source only after publication; a removal failure returns status 1 while keeping
the valid output. The command checks source identity before removal. Concurrent
path mutation between that check and `unlink` is outside this guarantee.
Publication is atomic visibility, without an fsync/power-loss durability claim.

`-o OUT -` now supports stdin to a named destination; `-o -` selects stdout.
Stdout receives bytes incrementally, so a failing decode may already have
written a valid prefix. `--rm` does not remove sources when output is stdout.
Forced destinations must be regular files; symlinks, devices, and directories
are refused. Same-inode input/output aliases are refused. The source's mode
and timestamps are preserved for named-file inputs; stdin destinations use
0666 filtered through the shell's umask.

No shared helper changes are required. Build with both `zstd,zstdcat`; their
existing libzstd dependency and companion declaration already cover the code.
An explicit `BASHOS_ZSTD_LIB` library must export the streaming APIs and
`ZSTD_DCtx_setParameter` (libzstd 1.4.0 or newer).

## Focused validation

Retain `tests/zstd-check.sh` and `tests/zstd-host.c`; the former adds streaming
and publication assertions. `tests/sol-zstd-check.py BINARY` adds independent
host validation of unknown-size/concatenated/skippable frames, truncation and
trailing garbage, the decoder-window limit, named stdin destinations, aliases,
symlinks, stdout ENOSPC, repeated calls, output before EOF, atomic visibility,
and a sparse input larger than 1 GiB under a 192 MiB address-space limit.
The large test validates the recovered bytes and crosses both former caps.
`tests/sol-zstd-rootfs.sh` checks a static binary in a root containing only that
binary and a test script (exit 77 reports unavailable namespace isolation).

`tests/sol-zstd-host.c` includes the production source and the historical host
harness. Under ASan/UBSan it injects buffer/context allocation failure, EINTR,
short/zero/error I/O, close and metadata failures, publication errors and races,
source-removal failure, and a stalled decoder. It checks temporary-file and FD
cleanup across repeated failures and successes. The legacy flipped-byte test now uses an independently generated checksummed
frame: a fixed byte flip in a checksum-free frame can still be valid data when
the streaming frame layout changes. The original error assertion is retained,
with an additional intact-fixture round-trip oracle. Compile it as a single
translation unit with the Bash build headers and `-lzstd -ldl`.

## Measurements

`bench/sol-zstd.py` measures fixed workloads with seven samples and a validated
warmup, alternating builtin/reference order on the gate's fixed CPU affinity.
Every invocation writes a separate result; every status and result is checked
after each timed batch. Compressed output is independently decoded by host
zstd and compared by size and SHA-256 with the original fixture. Frames need
not be byte-identical. Peak process RSS comes from `wait4` inside the small native
`bench/sol-zstd-rusage.c` launcher. It execs before forking the measured shell
and reports child usage, excluding its own inherited fixture-generator RSS
high-water mark. It includes the maximum descendant process, rather than a sum
across simultaneous processes. Build the launcher separately through the build
gate as `out/sol-zstd-rusage`; the benchmark never compiles it.

The matrix covers levels 1/3/19, the 423,000-byte catalog text and a deterministic
32 MiB fixture, stdin/stdout and named input/output, and decompression of both
sizes through both paths. The default-level blob cases are included as well.
`--historical` selects just the four original workload shapes for a baseline.
The historical [default-level report](zstd.md) and its dataset remain separate.
Raw reports record fixture/source/binary hashes, versions, sample distributions,
work counts, CPU affinity, environment, RSS and validation counts. Timings
include shell startup, output writes and named-file publication, use warm cache,
and do not claim cold-cache performance or disk durability.

## Validated results, 2026-10-20 UTC

The targeted dynamic and static builds passed 30 command checks and 35 extended
checks each. The ASan/UBSan harness passed 38 assertions with leak detection,
and the static isolated-root test passed with no shared libraries in its root.
The >1 GiB tests used a 192 MiB address-space limit.

Measurements used Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz, Linux 6.12.111+deb13-amd64, CPU 11,
Bash 5.3.15, GCC 14.2.0, and host zstd/libzstd 1.5.7. Other campaign work was
active; load averages are recorded in the reports. The original four default
workload shapes also passed a fresh baseline measurement, with builtin/host
median ratios 0.40, 0.36, 0.39, 0.37. No former default-level slowdown was reproduced.
These are within-run comparisons with the host CLI, without an old/new speedup
claim across separate builds.

The matrix below is median milliseconds per batch; text/blob use eight calls,
large uses one. RSS is the largest process RSS in KiB across seven samples.
Every row has seven fully validated samples for both implementations; the
matrix validates 1,408 outputs including warmups.

| Operation / fixture / level / path | Calls | Builtin ms | Host ms | B/H | Builtin RSS KiB | Host RSS KiB |
|---|---:|---:|---:|---:|---:|---:|
| compress-text-1-stdin | 8 | 12.927 | 31.677 | 0.41 | 4656 | 6352 |
| compress-text-1-named | 8 | 13.424 | 30.148 | 0.45 | 4636 | 4180 |
| compress-large-1-stdin | 1 | 111.296 | 107.133 | 1.04 | 4764 | 21248 |
| compress-large-1-named | 1 | 104.208 | 104.925 | 0.99 | 4760 | 19736 |
| compress-text-3-stdin | 8 | 13.442 | 34.256 | 0.39 | 7220 | 8728 |
| compress-text-3-named | 8 | 15.554 | 36.396 | 0.43 | 7108 | 4916 |
| compress-large-3-stdin | 1 | 17.536 | 40.841 | 0.43 | 7060 | 46628 |
| compress-large-3-named | 1 | 17.204 | 39.473 | 0.44 | 7240 | 46596 |
| compress-text-19-stdin | 8 | 1908.980 | 2508.009 | 0.76 | 91172 | 88832 |
| compress-text-19-named | 8 | 1875.817 | 2408.768 | 0.78 | 89344 | 13652 |
| compress-large-19-stdin | 1 | 287.303 | 354.999 | 0.81 | 95400 | 120368 |
| compress-large-19-named | 1 | 288.993 | 379.221 | 0.76 | 95332 | 120308 |
| decompress-text-3-stdin | 8 | 7.930 | 20.428 | 0.39 | 6236 | 5360 |
| decompress-text-3-named | 8 | 8.224 | 20.042 | 0.41 | 6148 | 5296 |
| decompress-large-3-stdin | 1 | 22.071 | 26.381 | 0.84 | 6148 | 7012 |
| decompress-large-3-named | 1 | 23.002 | 28.025 | 0.82 | 6184 | 6696 |
| compress-blob-3-stdin | 8 | 6.315 | 25.990 | 0.24 | 7080 | 6996 |
| decompress-blob-3-stdin | 8 | 6.789 | 19.796 | 0.34 | 4740 | 5972 |

Large level-1 compression is close to host timing; its sample ranges overlap.
Level 19 uses substantially more context memory than levels 1/3, including
small named inputs where the host CLI can size its context more narrowly.
The builtin remains bounded independently of total input size.

Implementation SHA-256: `8b354c2ed41b4abfd9815c9e2148b9cbff706ef0e0cd29b9e6986eaaaf15870f`.
Dynamic binary SHA-256: `482cce6bd7c9944b746a6b67802bdc1a47bdca60277f420cfa45fce8b4224113`.
The separate evidence files `benchmark-baseline-final.json` and
`benchmark-stream-final.json` record all distributions, hashes and validation
counts. Earlier setup failures and an RSS experiment with an inherited parent
high-water floor remain in the task receipt; they are excluded from this table.
The historical default-level report and dataset were left untouched.
