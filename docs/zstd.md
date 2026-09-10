# zstd behavior and performance

`zstd` compresses or decompresses files with libzstd. Default level is 3;
`-1`..`-19` select the level. `-d` decompresses, `-c` writes stdout, `-` is
stdin to stdout, `--rm` removes the source after success, and `-f` overwrites
an existing target. The target takes the source's mode and mtime. `zstdcat` is
`zstd -dc`. The subset and file semantics are those of `zstd(1)` that a script
uses; see [provenance](PROVENANCE.md).

```sh
./build.sh --include zstd,zstdcat --name zstd
out/bash-zstd -c 'PATH=; zstd -c -' < input > input.zst
out/bash-zstd -c 'PATH=; zstd -d -c -' < input.zst
```

Input is read whole (256 MiB cap). Compression is one-shot `ZSTD_compress`.
Decompression is streamed into a growing buffer (1 GiB cap) and does not trust
a frame's declared size for the allocation. The frame is written with
`write(2)` to the destination descriptor. `BASHOS_ZSTD_LIB` can override the
linked library; an unavailable override fails without affecting the shell.

## Compatibility

`tests/zstd-check.sh` holds the builtin to the host's `zstd(1)`: round trips
(including empty and NUL inputs), GNU reading our frames and us reading GNU's,
keep/`--rm`/`-f`/`-c`/`-o`/`-`, mode and mtime, truncated and bad-magic
inputs, missing files, suffix errors, a missing-library override, and rejected
levels. On the catalog binary that suite is **24/24**. `tests/zstd-host.c`
covers the buffer paths under ASan/UBSan.

Compressed frames are **not** byte-identical with `zstd(1)` at the same level
(one extra byte on every GNU frame in these fixtures). GNU `zstd -d` recovers
the original from both. Timed comparisons therefore validate by round-trip,
not by comparing frames. Debian BusyBox 1.35/1.37 has no `zstd` applet.

## Measurements, 2026-09-10

This is a follow-up to the [catalog snapshot](loadables-status.md), not a
replacement of it. The binary is the catalog full build: SHA-256
`9b2c69c9b8dc1c8cb437904afeacc51919fc4db31fc676d0c41137a2c8caad73`, Bash
5.3.15, the same `out/bash` as the 49-case table, pinned to CPU 11. `zstd.c`
is unchanged since that snapshot. Host: Intel Core i7-9850H, Linux 6.12.96,
x86-64, host libzstd and `zstd(1)` 1.5.7. The [measurement
summary](data/zstd-benchmarks.json) records fixture hashes, frame sizes,
pass counts, sample lists and timing ranges.

Seven samples followed output validation and warm-up. Each workload
interleaved the builtin and `/usr/bin/zstd`, rotating and reversing order.
A shared lock serialized this with other timed runs. Both implementations
ran from the same bash-os shell with startup files disabled, `LC_ALL=C`,
`TZ=UTC` and an empty `PATH`. GNU is an absolute path; timings include one
shell startup, the loop, redirections and GNU's fork/exec. Output went to
`/dev/null`.

Other work was active (load 6.5–6.7, SMT sibling ~42–59% busy). That is
recorded, not used as a skip. Compare implementations inside this run: they
shared the CPU and the contention. A speed ratio is not published for
incorrect output; every side here had JSON `status=ok` and
`validation_passes == passes`. Builtin and GNU ranges do not overlap on any
case.

Catalogue fixtures: `text` is 423,000 bytes of ASCII words, seed `20260908`;
`blob` is 1 MiB repeating 0–255. Compress uses `zstd -c -` at default level 3.
Decompress uses `zstd -d -c -` on a GNU-produced frame of that fixture.
Pass counts are calibrated toward a ~75 ms batch.

All times are **median milliseconds per batch**. Ratio is builtin ÷ GNU;
below 1.00 is faster than GNU.

| Case | Input | Calls | Builtin ms | GNU ms | Ratio | GNU / builtin |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| compress-text | 423,000 | 33 | 49.486 (45.782–61.160) | 151.354 (147.747–181.635) | **0.33×** | 3.06× |
| compress-blob | 1,048,576 | 41 | 45.168 (40.380–56.876) | 169.623 (160.489–179.675) | **0.27×** | 3.76× |
| decompress-text | 77,237 frame | 45 | 39.639 (29.729–47.259) | 156.202 (126.429–178.563) | **0.25×** | 3.94× |
| decompress-blob | 364 frame | 62 | 20.964 (16.254–28.480) | 181.932 (155.597–187.980) | **0.12×** | 8.68× |

`compress-text` is the algorithm cell: 423 KB at level 3, **3.06×** ahead of
`zstd(1)` on this calling pattern. `decompress-blob` is mostly avoided forks
(62 launches of a 364-byte frame) and is not a decompression-throughput
claim. Builtin frames were 77,236 and 363 bytes; GNU's were one byte larger;
both decoded to the original.

BusyBox is omitted: no applet. `zstdcat` is not timed separately; it is
`zstd -dc`.

The same compress-text workload on an aarch64 Cortex-A72 and on an Intel
Core i7-10700F, each against that host's `zstd(1)`, also finished ahead of
GNU (about 0.37× and 0.36×). Those binaries and absolute times are not this
snapshot.

To reproduce:

```sh
lock=/tmp/bash-os-loadable-bench.lock
flock "$lock" python3 bench/zstd.py --binary out/bash --runs 7 --cpu 11 \
  --output /tmp/zstd.json
```

Inspect every JSON result's `status`. Raw sample logs belong outside Git.
These numbers do not establish static, RISC-V, other levels, named-file
(non-stdout) paths or cold-cache performance.

## Remaining work

Whole-file input and one-shot compression remain the implementation limits
for large streams. Level, long-file and named-file cases are unmeasured.
No selected-case performance gap against `zstd(1)` appeared here.
