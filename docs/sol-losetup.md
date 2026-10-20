# losetup software-path coverage

`loadables/losetup.c` implements native list, associated-file filtering, find,
explicit and selected-device attachment, read-only and partition-scan flags,
byte offsets and size limits, and single-device detach. Options can precede or
follow operands; `--` ends option parsing. Numeric byte counts retain the
existing unsigned, base-detected integer syntax, without size suffixes.

The implementation now propagates read-only backing-file fallback into device
open mode and `LO_FLAGS_READ_ONLY`, limits fallback to `EACCES`/`EROFS`
errors, opens descriptors with close-on-exec, preserves ioctl errno
across close, and diagnoses rollback failures. It rejects surplus operands and
incompatible actions before opening devices. Listing checks complete loop names,
reads direct-I/O status, retains backing paths up to PATH_MAX, recognizes associated-file aliases by device/inode,
and reports directory access failures while tolerating an absent block layer.
Failed writes return failure; later calls recover stdio state.

The original `LOOP_SET_FD` then `LOOP_SET_STATUS64` kernel path is retained.
Rollback clears an association only after this invocation successfully set it.
A failed `LOOP_SET_FD`, including a busy device, never triggers rollback.
A failed rollback is reported and can leave the new association present.
Similarly, if attachment succeeds but writing `--show` fails, the attachment
remains present and the command returns failure.

## Fixture boundary and assertions

`tests/sol-losetup-shim.c` includes the genuine production source with private
open/stat/opendir/close/ioctl replacements. The ordinary production binary has
no runtime fixture switch. Filesystem access in the module is redirected into
a temporary fixture tree; backing files are private regular files. Loop-control
and loop-device ioctls are interpreted by a stateful boundary and never forwarded
to the kernel. No host loop is attached or detached.

`tests/sol-losetup-fixtures.py` covers list aliases, associated-file aliases,
unused and malformed sysfs entries, missing fields and directory failures,
selected and explicit attachment, all combinations of the two supported flags,
offsets/limits including integer bounds, filename truncation, find exhaustion,
read-only fallback, control/backing/device/request failures, successful and
failed rollback, foreign association preservation, repeated calls, descriptor
and directory cleanup, argument rejection, empty `PATH`, and output failure
followed by recovery. The repeated request tests validate configured state
before detaching, so successful cleanup cannot hide a malformed request.
Native binary checks cover builtin registration, repeated help, invalid inputs
before device access, and write-error recovery. Existing device-fixture
assertions are retained unchanged.

The fixture starts with loop0 owned by a simulated other caller. Every final
state oracle includes that association. Private backing-file hashes must remain
unchanged. Sanitizer modules instrument production code and boundary code.

## Reproduction

Set `GATE` to the campaign resource wrapper and `EVIDENCE` to a private output
directory. Build and measurement admission are separate; the correctness driver
never compiles anything.

```sh
python3 "$GATE" build -- ./build.sh --include losetup,dmesg,blkid,lsblk --name sol-losetup-final
python3 "$GATE" build -- tests/sol-losetup-build.sh "$EVIDENCE/artifacts"
python3 tests/device-fixtures.py out/bash-sol-losetup-final
python3 tests/sol-losetup-fixtures.py --binary out/bash-sol-losetup-final --module "$EVIDENCE/artifacts/losetup-fixture.so"
python3 tests/sol-losetup-fixtures.py --binary out/bash-sol-losetup-final --module "$EVIDENCE/artifacts/losetup-sanitize.so" --preload "$(cat "$EVIDENCE/artifacts/libasan-path")"
python3 "$GATE" bench -- python3 bench/sol-losetup.py --binary out/bash-sol-losetup-final --module "$EVIDENCE/artifacts/losetup-fixture.so" --output "$EVIDENCE/bench.json"
```

Losetup itself requires no companion loadable or shared-helper change. The
three extra commands above are needed by the unchanged device-fixture suite;
the resolver stages `_jsmn` automatically in both selections. The broad util-linux
smoke suite requires many unrelated commands and is left to integrated testing.

## Measurements and qualification

The task-owned benchmark uses independent expected-result oracles. Discovery
checks each table separately as a multiset of rows, allowing filesystem directory
order while requiring every expected field and row exactly once. The request
case checks the selected device, flags, offset, limit and backing file before
each detach, then checks exact output, counts and final state for the batch.
Each sample uses a fresh shell and resets the shim to the same foreign loop0
association; fixtures are unchanged and hashed. The report records source and
binary SHA-256 values, options, work counts, versions, CPU affinity, warm-up and
seven validated samples. These are syscall-shim measurements, with no external
ratio or speedup claim. No prior valid losetup timing exists to reproduce.

The measurements below are historical results for commit `657322608ebd0498bf125b4a4ab1429096ff25f7`, before the backing-path buffer correction. They do not measure the corrected code. The expanded 15-test suite, including a backing pathname longer than 512 bytes and its alias, passes normally and under ASan/UBSan.

The 2026-10-19 run passed the existing nine device-fixture tests and all 14
focused tests, repeated with ASan/UBSan, with no skips. Measured on CPU 11,
Linux 6.12.111, Bash 5.3.15, GCC 14.2 and glibc 2.41; one warm-up and seven
samples per case. Raw reports and logs are retained with the task receipt.

| Fixture workload per sample | Median ms | Min–max ms |
|---|---:|---:|
| 100 listings × 128 devices; 12,800 rows, 51,200 metadata reads | 458.335 | 420.837–500.564 |
| 1,000 find/attach/check/detach cycles, one final explicit attach; 4,002 intercepted ioctls | 54.540 | 52.094–58.046 |

Discovery leaves only the original simulated foreign association. The request
batch leaves that association plus loop2 backed by the private image at offset
65,536, size limit 32,768, flags zero. Every earlier loop1 attachment is checked
at offset 4,096, size limit 8,192, read-only plus partscan flags before detach.
Both cases finish with no live fixture descriptors or directories and unchanged
fixture and image hashes. These are batch costs including shell/module setup,
private-file operations, validation-controller calls and captured output.

Remaining real-loop qualification: kernel permission enforcement, concurrent
loop allocation races, partition discovery, actual read-only block I/O, delayed
detachment, and offset/size enforcement require disposable hardware or a private
VM with loop support. The fixture proves software request construction and
cleanup behavior; it does not qualify those kernel outcomes. Automatic retries
on busy allocation, multiple-device detach, modern `LOOP_CONFIGURE`, and the
full util-linux formatting/option surface are outside this command's documented
subset. Real-loop latency and throughput remain unmeasured. The built-in does
not shell out to an external losetup implementation.
