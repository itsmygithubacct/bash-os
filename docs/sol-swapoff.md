# swapoff software-path qualification

`swapoff` follows util-linux 2.41. Each spec is resolved before `swapoff(2)`:
an existing path is canonicalized, `LABEL=` / `UUID=` / `PARTLABEL=` /
`PARTUUID=` follow `/dev/disk/by-*`, and a missing plain path is passed through.
An empty spec prints `cannot find the device for` and does not call `swapoff`.
`--` permits a name beginning with `-`. Repeated named operands stay repeated.
A failed operand does not stop the rest, except `EPERM`, which exits 16 with
`Not superuser.`

`swapoff -a` reads `/proc/swaps` into a private snapshot, walks it backwards,
and does not drop duplicates. It decodes `\ooo` pathname escapes, reports
`parse error at line N -- ignored`, and still attempts the other rows. It then
walks inactive swap entries in `/etc/fstab`. `-a` may be combined with specs;
the specs are disabled first, and they are not quiet. `-a` itself is quiet
about a `swapoff failed` diagnostic.

Exit status matches util-linux: 0 when the attempted requests succeed, 2 for
`ENOMEM`, 4 for another `swapoff(2)` failure, 16 for usage or `EPERM`, 32 when
every `-a` table entry fails, 64 when some `-a` entries fail, and 255 when a
spec cannot be found. Help detects output failures.

The 2026-10-19 measurement later in this note describes the previous literal-path
parser. It is not the 0.1.4 contract.

## Safe validation

`tests/sol-swapoff-shim.c` interposes the libc `swapoff` symbol used by the actual
production shell. It never forwards requests. It redirects only `/proc/swaps`
reads to a private file, compares every request with an independently specified
ordered pathname list, injects request/open/read/close failures, and checks
balanced streams, a closed source before requests, and zero unexpected
requests. A seccomp filter denies raw
`swapon` and `swapoff` syscalls before any test code runs. The test also verifies
that filter using a NULL pathname. No test reads or disables host swap.

`tests/sol-swapoff-check.py` covers named paths, spaces/tabs/newlines/backslashes,
carriage returns, headers, duplicates, empty tables, malformed/NUL/overflow rows,
long lines, partial failures, permission and no-device errors, invalid options,
help output failure, and repeated calls with an empty `PATH`. Its persistent
shell case runs 1,000 mixed calls, including repeated read/close failures. It
checks requests/streams after each call and compares shell file descriptor
counts before and after the loop.

Build separately through the campaign build gate:

```sh
python3 "$GATED" build -- ./build.sh --include swapoff --name sol-swapoff
python3 "$GATED" build -- bash tests/sol-swapoff-build.sh
python3 tests/sol-swapoff-check.py --binary out/bash-sol-swapoff \
  --shim "$BASHOS_TASK_DIR/artifacts/swapoff-shim.so" \
  --output "$BASHOS_TASK_DIR/correctness.json"
python3 tests/sol-swapoff-check.py --binary /bin/bash \
  --shim "$BASHOS_TASK_DIR/artifacts/swapoff-shim.so" \
  --module "$BASHOS_TASK_DIR/artifacts/swapoff-sanitize.so" \
  --asan "$(cat "$BASHOS_TASK_DIR/artifacts/asan-path.txt")" \
  --output "$BASHOS_TASK_DIR/sanitizer.json"
```

The sanitizer module compiles the unchanged production source with ASan/UBSan;
the syscall boundary remains intercepted. Bash's process-wide leak detector is
disabled, while address/undefined-behavior errors abort. Fixture state is freed
at each test's end. No common-helper changes or companion loadables are needed;
the selector's default `_jsmn` staging remains unchanged.

On 2026-10-19 the targeted production binary passed all 57 checks, and the
ASan/UBSan module passed the same 57 checks. The source from the starting commit
(identical to the stated baseline) passed 12 and failed 45 under this stronger
contract; its failed report is retained separately. These are fixture checks,
not a count of independent defects. The production binary also has verified
dynamic relocations for `swapoff` and `fopen`, confirming the tested boundary.

## Measurement and limits

`bench/sol-swapoff.py` measures three fixed workloads: 64 named requests; an
empty table; and a 256-row table containing 128 unique escaped names and 128
duplicates. Each sample uses 200 calls in one shell, validating status, exact
request order/count, source opens/closes, and empty output after every call.
One warm-up precedes seven samples on one recorded CPU. Fixture and expected
sequence hashes, source/binary/shim hashes, environment, versions, raw samples
and validation statuses are recorded in the report.

```sh
python3 "$GATED" bench -- python3 bench/sol-swapoff.py \
  --binary out/bash-sol-swapoff \
  --shim "$BASHOS_TASK_DIR/artifacts/swapoff-shim.so" \
  --runs 7 --passes 200 --output "$BASHOS_TASK_DIR/benchmark.json"
```

These are syscall-shim batch timings, including startup, the shell loop and
fixture validation. There was no historical validated swapoff timing to
reproduce and no matched external comparison is claimed. The former parser's
invalid requests cannot serve as a performance baseline.

The 2026-10-19 run passed every workload, warm-up and measured sample. CPU
affinity was fixed to CPU 11 on an Intel Core i7-9850H, with Linux 6.12.111,
glibc 2.41, GCC 14.2 and Bash 5.3.15. Each sample contained 200 builtin calls.

| Work per sample | Median batch ms | Min–max ms |
|---|---:|---:|
| 12,800 named requests | 4.460 | 4.329–4.559 |
| 200 empty-table parses; no requests | 3.362 | 3.119–5.481 |
| 51,200 rows parsed; 25,600 deduplicated requests | 26.571 | 26.002–26.833 |

Raw samples and all validation statuses are in the task receipt's
`benchmark.json`. Its full provenance records source SHA-256
`a574decc46b93505298a5f0ac31265637b87ef8ab2dbe758afe2cbdf143ccd47`
and binary SHA-256
`cae32bd1eb4d2df9a84b68585c45dfd70ed3b7942ba3fc6ba39e18041f508a4c`.

Actual-device qualification remains separate: successful kernel swap removal,
reclamation under memory pressure, races with concurrent swap configuration,
real privilege/filesystem/device errors and elapsed device removal time require
a disposable host or VM with owned swap. None is established by these fixtures.
