# mkfs: private-image qualification

`mkfs` is a native ext2 formatter. It supports existing regular-file images and
Linux block devices, 1024/2048/4096-byte blocks, a label truncated to 16 bytes,
0–50 percent reserved blocks, and `-n` layout-only inspection. The image size is
taken from `fstat` or `BLKGETSIZE64`; there is no size operand. A trailing partial
block is left outside the filesystem. Layouts whose metadata cannot fit a group
are rejected before writing, including in dry runs. `--` ends option parsing.

There is no delegated formatter or external executable dependency. This checkout
has no `mkfs.ext4` wrapper or ext4 creation backend. The result has `dir_index`,
`filetype`, and `sparse_super` feature flags, linear initial directories, 128-byte
inodes, a root directory and preallocated lost+found. It has no journal or extents.
`-F` is a compatibility option: existing filesystems are replaced with or without
it; unsupported file types are always refused. A write/sync/close failure returns
failure and can leave a partially formatted image. Formatting is not atomic.

Build just this command:

```sh
python3 /path/to/gated.py build -- ./build.sh --include mkfs --name sol-mkfs
```

`config/helpers.json` declares no required companion for mkfs. The build selector
also stages its unconditional `_jsmn` helper. No shared helper changes are needed.

The focused contracts are:

```sh
python3 tests/sol-mkfs.py --binary out/bash-sol-mkfs --report /evidence/correctness.json
python3 /path/to/gated.py build -- bash tests/sol-mkfs-build.sh
python3 tests/sol-mkfs-faults.py --binary out/bash-sol-mkfs \
  --module "$BASHOS_TASK_DIR/artifacts/mkfs-shim.so" --report /evidence/faults.json
python3 tests/sol-mkfs.py --binary out/bash-sol-mkfs \
  --module "$BASHOS_TASK_DIR/artifacts/mkfs-sanitize.so" \
  --asan-lib "$(cat "$BASHOS_TASK_DIR/artifacts/asan-path.txt")" --report /evidence/sanitize.json
python3 tests/sol-mkfs-faults.py --binary out/bash-sol-mkfs \
  --module "$BASHOS_TASK_DIR/artifacts/mkfs-sanitize.so" \
  --asan-lib "$(cat "$BASHOS_TASK_DIR/artifacts/asan-path.txt")" --report /evidence/faults-sanitize.json
```

The tests allocate private regular-file images and guard against symlinks, hard
links, foreign ownership, and paths outside their fixture directory. No device is
formatted, mounted or attached to a loop device. The C fixture compiles the actual
production source and closes its open/ioctl boundary; simulated block-device
queries can only lead to writes to an owned regular image. It tests both successful
`BLKGETSIZE64` sizing and query failure, without issuing a real device ioctl.

The decoder checks superblock fields, primary/backup descriptors, every allocation
bitmap bit, zeroed unused inodes, root/lost+found inode pointers, and complete
records in every directory block. The three 8 MiB layouts additionally have fixed
expected counts. Images cover the 60-block lower limit, dirty preexisting content,
multiple groups, multiple descriptor blocks and nonintegral block sizes. Independent
`e2fsck -fn`, `dumpe2fs -h`, `debugfs -R 'ls -l /'`, and `blkid -p` inspect the result
when installed; unavailable tools are explicitly recorded. Assertions include
numeric/option errors, label truncation at byte boundaries, unchanged dry runs and
invalid layouts, repeated formats, empty PATH, diagnostic write failure, FIFO
refusal and persistent-shell FD cleanup. Failure injection checks every write
position on a minimal image, all scratch allocations, entropy input failures,
short/interrupted I/O, sync/close failures, and successful recovery in the same
shell. Helper boundary checks include whole bitmaps and all sparse-super powers
through the 32-bit range. ASan/UBSan instrument the production source; Bash-wide
leak detection is disabled, and the shim separately requires zero live scratch
allocations and zero image/entropy descriptors after every call.

The software scope is filesystem creation on regular images plus the simulated
block sizing branch. Physical-device operation, mounted filesystem behavior,
power-loss recovery and maximum-capacity filesystems are outside this fixture
qualification. No actual-device performance is claimed.

The final ordinary and ASan/UBSan module runs each passed all ten layouts,
19 invalid parsing cases, label/dry-run/size/output-error checks, and 24 repeated
formats in one shell. Each fault run passed 104 failure/recovery/block cases.
All four independent read-only tools were available and passed; no reference
checks were skipped.

## Matched creation measurement

Run the task-owned harness only through the measurement gate:

```sh
python3 /path/to/gated.py bench -- python3 bench/sol-mkfs.py \
  --binary out/bash-sol-mkfs --runs 7 --output /evidence/creation.json
```

Each pass creates eight fresh zero-filled sparse images of 8 MiB, with 1 KiB
blocks, 2048 128-byte inodes, 5% reserved blocks, label `fixture`, and matching ext2
features. mke2fs explicitly disables discard and lazy inode-table initialization.
Every image is independently checked after timing. A private mke2fs configuration disables inherited
ACL/xattr mount defaults and enables periodic checks. Both implementations must
complete successful image flushes in a separate strace profile; write calls and
bytes are reported separately. The timer includes shell startup and eight formats;
the external case includes eight executable launches. Fixture creation, validation
and cleanup are outside timing. One warm-up precedes seven samples in alternating
order, under a fixed recorded CPU affinity. Reports include sample distributions,
initial fixture hash, options, versions, source/harness/binary hashes and raw traces.
UUIDs, hash seeds and timestamps vary as part of normal formatting.

The starting implementation placed hash-seed bytes in journal/orphan fields;
independent `e2fsck -fn` returned 12 with “Can't find external journal”. The fix
places the seed at byte 236 and the hash-version byte at 252. Remaining preallocated
lost+found blocks now contain valid empty entries instead of zero record lengths.
A historical fixture with only its superblock repaired still failed `e2fsck` at
lost+found block 1, independently isolating that second defect.
A closed stderr can also let `open(IMAGE)` reuse fd 2; the formatter now rejects
that case before printing diagnostics into the image. Numeric parsing, dry-run
layout checks, full-bitmap boundaries and sync-error handling are covered by the
same focused tests.

On 2026-10-19, the final native binary passed the same correctness contracts.
The creation measurement passed all 16 warm-up/sample batches, checking 128
images with all four read-only tools; both separate profile images also passed.
The host was an Intel Core i7-9850H, Linux 6.12.111, glibc 2.41, GCC 14.2,
Bash 5.3.15 and e2fsprogs 1.47.2, pinned to CPU 11.

| Eight-image batch | Builtin | mke2fs |
|---|---:|---:|
| Median wall time | 11.116 ms | 30.290 ms |
| Minimum–maximum | 10.379–12.013 ms | 27.486–30.983 ms |
| Median per image | 1.390 ms | 3.786 ms |
| Writes per image | 275 calls / 279,808 bytes | 22 calls / 24,576 bytes |
| Additional zero-range work | none | 2 fallocate calls / 327,680 bytes |
| Successful fsync calls per image | 1 | 3 |
| Allocated bytes after creation | 282,624 | 352,256 |

The end-to-end creation latency ratio is 2.72 (mke2fs/builtin). These are equal
logical image-creation workloads with different write, zeroing, process-launch
and flush policies; the ratio is not a comparison of byte throughput, kernel
formatting speed, or a before/after optimization. There was no prior validated
mkfs timing to reproduce, and no speculative performance change was introduced.
The reference additionally zeroes the image's final 64 KiB. Its inode-table zeroing
uses `FALLOC_FL_ZERO_RANGE`; reporting only write bytes would undercount its work.

Raw logs/reports stay in the assigned evidence directory: `creation.json`,
`creation-*-strace.log`, `creation-analysis.json`, `correctness-native-final.json`,
`correctness-sanitize-final.json`, and `faults*-final.json`. Source SHA-256 is
`de4eead857ff15161e636e5b0f76f584cf543822fc3a51d39280db725cbc033f`;
native binary SHA-256 is
`95c94f2c7e74f9b52c7bae40e95b701f9c33b1a25c4e1a4aca9ba0d97dee8184`.
The raw report records the starting commit plus the exact source/diff hash;
the delivery receipt records the final commit containing that source.
