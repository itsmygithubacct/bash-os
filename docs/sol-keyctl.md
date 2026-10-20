# keyctl software contract and measurement

The builtin implements six Linux keyring verbs:

| Invocation | Result |
| --- | --- |
| `keyctl session [NAME]` | Join/create a session keyring; print its serial. Omit NAME for a new anonymous keyring. |
| `keyctl add TYPE DESC [KEYRING]` | Read binary stdin, add/update a key, and print its serial. |
| `keyctl search [KEYRING] TYPE DESC` | Print the matching key serial. |
| `keyctl print SERIAL` | Write payload bytes, without adding a newline. |
| `keyctl revoke SERIAL` | Revoke the key. |
| `keyctl clear [KEYRING]` | Remove the keyring's links. |

The default keyring is `@s`. Other recognized aliases are `@t`, `@p`, `@u`,
`@us`, and `@g`; kernel availability and permissions still apply. Numeric
references accept decimal digits with an optional leading minus and must fit
the signed 32-bit key serial ABI. Empty ring operands, whitespace, plus signs,
overflow, and extra operands return usage status 2. Syscall, input, and output
errors return status 1.

Types contain 1–31 bytes and cannot begin with a dot. Names/descriptions contain
at most 4095 bytes. Session names and new `keyring` descriptions cannot begin
with a dot. An empty description is forwarded so the key type can decide
whether to generate or reject it. `add` buffers at most 1048575 payload bytes,
detecting overflow after one extra byte; types can impose smaller limits. These
limits follow the Linux [keyctl syscall implementation](https://github.com/torvalds/linux/blob/master/security/keys/keyctl.c).
For example, the Linux [user key type](https://github.com/torvalds/linux/blob/master/security/keys/user_defined.c)
requires a nonempty payload of at most 32767 bytes. The builtin preserves kernel
errors rather than restricting all types to that smaller limit.

`print` probes the size and then reads the bytes. If the key grows, it expands
the buffer and retries, allowing four data reads before returning failure.
Shrinking and zero-length payloads work. No bytes are emitted from a buffer
whose required size exceeds its capacity. Output is flushed before successful
return, and a later invocation can recover after a failed output redirection.

The focused tests include the production C source with only `syscall` replaced
by a closed fixture. Unrecognized calls fail; no fixture request can reach a
live keyring. They check binary payloads, update identity, search state,
missing/revoked keys, type/name/payload boundaries, every ring alias and signed
ABI boundaries, strict operand validation, syscall denials, input/output
failures, size races, and 500 repeated lifecycles with descriptor ownership
checks. The fixture's state and request counts are independent assertions.
The same source is instrumented with ASan/UBSan.

The real-kernel probe runs only inside test children. Its first mutation is an
anonymous `session` join. A failed join exits immediately, without clearing,
adding to, or revoking anything in the inherited session. On success, cleanup
uses only the serial returned by that join. All key serials come from additions
to that private ring. No live test uses user, group, or preexisting named rings.
The probe checks twenty binary add/update/search/print/revoke/clear cycles when
the host permits keyring syscalls. A policy denial is recorded as **blocked**,
separately from fixture passes.

Build only the selected command; no companion loadables or shared-helper edits
are required. The build resolver stages its default `_jsmn` helper unchanged.
Builds and measurements must run through the campaign's resource gate. The
commands below separate compilation from noncompiling tests:

```sh
python3 "$CAMPAIGN/scripts/gated.py" build -- bash -c \
  './build.sh --include keyctl --name sol-keyctl --no-strip && bash tests/sol-keyctl-build.sh'
python3 tests/sol-keyctl-check.py --binary out/bash-sol-keyctl \
  --module "$BASHOS_TASK_DIR/artifacts/keyctl-shim.so" \
  --report "$BASHOS_TASK_DIR/correctness.json"
python3 tests/sol-keyctl-check.py --binary out/bash-sol-keyctl \
  --module "$BASHOS_TASK_DIR/artifacts/keyctl-sanitize.so" \
  --real-module "$BASHOS_TASK_DIR/artifacts/keyctl-real-sanitize.so" \
  --preload "$(cat "$BASHOS_TASK_DIR/artifacts/asan-path.txt")" \
  --report "$BASHOS_TASK_DIR/sanitize.json"
python3 "$CAMPAIGN/scripts/gated.py" bench -- python3 bench/sol-keyctl.py \
  --binary out/bash-sol-keyctl --module "$BASHOS_TASK_DIR/artifacts/keyctl-shim.so" \
  --validation "$BASHOS_TASK_DIR/correctness.json" \
  --mode shim --output "$BASHOS_TASK_DIR/benchmark-shim.json"
python3 "$CAMPAIGN/scripts/gated.py" bench -- python3 bench/sol-keyctl.py \
  --binary out/bash-sol-keyctl --module "$BASHOS_TASK_DIR/artifacts/keyctl-shim.so" \
  --validation "$BASHOS_TASK_DIR/correctness.json" \
  --mode kernel --output "$BASHOS_TASK_DIR/benchmark-kernel.json"
```

The benchmark uses a fixed 256-byte payload containing every byte value. Each
cycle runs session/add/search/print/revoke/clear/clear: seven builtin calls and
eight injected syscalls. Every cycle's serials, payload, syscall count, and
final link/revoke state are compared against a fixed expected transcript.
Each batch resets fixture state identically. A full validation batch precedes
one warm-up and at least seven timed samples on one recorded CPU. The raw
report includes all sample results, distributions, fixture/source/binary hashes,
versions, affinity, work counts, and kernel-probe status. Timings include shell
startup, loops, redirections, fixture controls, and output capture. They are
syscall-shim timings, with no keyutils ratio or claimed kernel speedup.

The kernel mode uses a new anonymous keyring and one seeded user key per child.
Each cycle updates the key from the fixed payload, searches the owned ring,
and reads the key: three builtin calls and four syscalls. Each update and search
must return the seed key's serial, and every payload must equal the fixed input.
The key stays linked throughout the batch; setup and cleanup add seven builtin
calls/syscalls per batch. Cleanup revokes that key, clears the owned ring twice,
and revokes the owned ring. Neither mode compares different implementations or
claims an improvement over the previously unmeasured implementation.

Validation on 2026-10-19 passed 122 fixture cases natively and with the loadable
and fixture instrumented by ASan/UBSan. Both runs also passed twenty private
real-kernel lifecycles with 4103-byte binary payloads. All seven focused
regression cases failed against the historical implementation and passed after
the fixes; those historical failures received no timings. The initial queued
baseline-only build was canceled before compilation so the final shell and
baseline/final fixture modules could share one gated build.

Seven timed samples after one warm-up, pinned to CPU 11 on an Intel Core
i7-9850H with Linux 6.12.111+deb13-amd64, Bash 5.3.15, GCC 14.2, and Python
3.13.5, gave these batch times:

| Work per batch | Median ms | Min–max ms |
| --- | ---: | ---: |
| Shim: 1000 lifecycles, 7000 builtin calls, 8000 injected syscalls | 55.537 | 52.015–59.703 |
| Kernel: 1000 update/search/read cycles, 3000 builtin calls, 4000 syscalls, plus setup/cleanup | 50.033 | 44.812–52.148 |

These rows perform different operations and are not a speed comparison. All
warm-ups and timed passes returned zero and matched their full expected
transcripts. Raw samples are in `$BASHOS_TASK_DIR/benchmark-shim.json` and
`benchmark-kernel.json`, with original validation receipts preserved separately.
They identify the starting commit plus exact working-tree source hashes. The
measured executable SHA-256 is
`b6f97c4e764eddd073748a6d230e5cf85d7dcc949377501e81950ac695c1dc2f`.

Real-kernel quota enforcement, credential/LSM denials, named-ring sharing, and
actual concurrent updates remain unqualified. Read races, permission failures,
and unavailable-syscall responses use injection. Injected cases establish the
builtin's software behavior across those responses; they do not establish
kernel behavior or latency. Full keyutils CLI compatibility, expiry,
link/unlink, permission
editing, and request-key upcalls are outside this six-verb interface.
