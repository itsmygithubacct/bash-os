# ipcctl: removal policy, IDs and syscall coverage

`ipcctl` is the narrow System V IPC removal API:

```sh
BASHOS_IPCRM_ALLOW_RMID=1 ipcctl --rm shm ID
BASHOS_IPCRM_ALLOW_RMID=1 ipcctl --rm msg ID
BASHOS_IPCRM_ALLOW_RMID=1 ipcctl --rm sem ID
```

Only the exact policy value `1` enables removal. Kernel ownership and permission
checks still apply. IDs are nonempty ASCII decimal digits in `[0, INT_MAX]`;
leading zeroes are accepted. Signs, whitespace, trailing text and overflow are
rejected before any syscall. Invalid operations, types and argument counts
produce usage errors before the policy check. A successful removal is silent;
a syscall error returns status 1 and names the type, ID and kernel errno text.
Help and version report write failures and allow a later invocation in the same
shell to write successfully.

The ID spelling rule tightens the previous `strtol` behavior, which accepted
leading whitespace, plus signs and negative zero. This is an internal API with
one numeric operand, so accepting those spellings served no documented use.

## Focused validation

`tests/sol-ipcctl-check.py` never compiles. It tests the actual native builtin and
a module that includes the production source behind closed `shmctl`, `msgctl`
and `semctl` interceptors. The interceptors never call the kernel. They check
IDs, `IPC_RMID`, null shm/msg buffers and semaphore number zero, and record the
exact request stream. Distinct IDs for each kind expose dispatch mistakes.

The native harness creates two `IPC_PRIVATE`, mode 0600 objects of each kind.
It checks denials preserve every object, removes each selected object with the
explicit policy allowance, verifies selected/nonselected objects independently
using libc `IPC_STAT`, and checks removed IDs against a libc errno oracle.
Cleanup operates only on IDs created by the harness. Allocation rejection is
reported explicitly with errno and fixture fallback; it is never counted as a
native pass.

Other assertions cover missing operands, malformed/overflowing IDs, boundaries,
policy values, injected EPERM/EACCES/EINVAL/EIDRM/ENOSYS, repeated reset/removal,
policy rereading, stable shell FD counts, empty PATH, `/dev/full` and recovery.
The final shell is linked with `-no-pie` to make sanitizer preload mapping
reliable. The same syscall module is tested with AddressSanitizer and UndefinedBehaviorSanitizer.

Build selection is `--include ipcctl`; no companion loadable or shared helper
change is required (`_jsmn` is staged by the existing build defaults).

```sh
# Prefix every compilation with the campaign build gate.
LDFLAGS_EXTRA=-no-pie ./build.sh --include ipcctl --name sol-ipcctl
bash tests/sol-ipcctl-build.sh "$EVIDENCE/modules"
python3 tests/sol-ipcctl-check.py --binary out/bash-sol-ipcctl \
  --module "$EVIDENCE/modules/ipcctl-shim.so" --report "$EVIDENCE/check.json"
python3 tests/sol-ipcctl-check.py --binary out/bash-sol-ipcctl \
  --module "$EVIDENCE/modules/ipcctl-shim-sanitize.so" \
  --preload "$(cat "$EVIDENCE/modules/asan-path.txt")" \
  --report "$EVIDENCE/sanitize.json"
```

## Measurement boundary

`bench/sol-ipcctl.py` times a fresh shell process containing 10,000 validated
cycles. Every cycle resets three private fixture records, calls production
`ipcctl` once per kind and verifies exactly three removals and no active records.
Every command status is checked. One warm-up precedes seven measured samples,
with a fixed single-CPU affinity. Each sample must match an independently
constructed output and have status zero and empty stderr.

The measured wall-clock boundary includes shell startup, module loading, the
Bash loop, fixture resets, three production request dispatches, status checks,
fixture verification, output capture and process wait. These are **syscall-shim
API timings**, with zero real kernel IPC calls. They do not measure kernel
allocation/removal latency. No external ratio or speedup is claimed. The raw
JSON records all samples, work counts, reset rules, fixture/source/binary hashes,
CPU affinity, compiler, Bash, Python, libc and kernel versions.

```sh
# Prefix this invocation with the campaign bench gate; it supplies CPU affinity.
python3 bench/sol-ipcctl.py --binary out/bash-sol-ipcctl \
  --module "$EVIDENCE/modules/ipcctl-shim.so" --samples 7 --cycles 10000 \
  --output "$EVIDENCE/benchmark.json"
```

Qualification is scoped to this Linux System V removal API. The fixture covers
permission-error propagation without altering credentials or unrelated IPC
objects. Other operating systems, attached-shm delayed destruction, and broader
`ipcrm` options are outside this command's narrow interface. No hardware is
required and no general `ipcrm` performance equivalence is asserted.

## Validated result, 2026-10-19

The native private-resource tests ran successfully; allocation fallback was not
needed. The final suite passed **154/154** assertions, and the ASan/UBSan module
run passed **154/154**. The unchanged baseline passed 143 and failed 11 of the
same assertions: four permissive ID spellings, three invalid-type diagnostics
under denied policy, and four help/version write-failure checks. Native and
fixture cases remain individually visible in the raw JSON reports.

On an Intel Core i7-9850H, Linux 6.12.111, glibc 2.41, GCC 14.2.0,
Bash 5.3.15 and Python 3.13.5, pinned to CPU 11, the syscall-shim batch
measured **104.475 ms median** for 10,000 cycles / 30,000 intercepted removals.
The seven samples were 123.063, 113.819, 112.058, 104.087, 100.756, 104.475
and 103.948 ms (range 100.756–123.063 ms; standard deviation 7.835 ms).
The separate warm-up took 125.934 ms. All eight passes validated. The median
amortizes to 10.448 µs per complete cycle, including the stated harness costs.
This provides an API workload measurement, not kernel syscall latency.

Production source SHA-256:
`1e981be829b082ee487297efb2e971942e23b70b31dbfa96d8dbc24e716634ca`.
Native shell SHA-256:
`c532a6b73b8492187534ade27ff23629bb351046951540892aa5abf1c169a069`.
Syscall fixture module SHA-256:
`380654c6e8cdf460ccc10f74a3e56e357b8d3aad050b9e9e0b50869aa927dead`.

The task evidence directory retains `baseline-check.json`, `final-check.json`,
`sanitize-check.json`, `benchmark.json`, command receipts and build logs.
Historical catalog and measurement files are unchanged. Integration should
register this focused test and link this report, classifying the metric as
syscall-shim/API with no external ratio.
