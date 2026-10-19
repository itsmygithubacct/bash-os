# Crypto state, failures and wrapper overhead

The command-owned work in `loadables/crypto.c` covers handle lifetime, primitive
output errors, authenticated decryption, hex conversion and input allocation.
The shared mbedTLS, Monocypher and authentication libraries are unchanged.
This is bounded primitive/API coverage; it is not a cryptographic certification
or a TLS/network interoperability qualification.

`tests/crypto-state.py` retains the prior output-binding and pool tests and adds
invalid, closed and reused handles across all handle-consuming secret subcommands, repeated
HKDF/scrub operations and failed handle-output writes. The additional
`tests/sol-crypto-check.py` uses Python hashlib/HMAC and cryptography/OpenSSL as
independent byte-for-byte references. It checks empty and binary messages,
hash padding and buffer boundaries, HMAC stack/heap key boundaries, AEAD key
and nonce sizes, large blocks, repeated invocations, file offsets, descriptor
cleanup, nonce-guard failures, authentication failures with no plaintext output,
and failed/closed stdout followed by a valid call in the same shell. AES-SIV's
empty-message oracle uses reference CMAC primitives because cryptography 43's
AESSIV interface rejects empty input.

Build the smoke group with `--include crypto,acme,uuidgen,wg,totp`. The last four
commands are called by `tests/final-smoke.py ... crypto`; crypto itself has no
required companion builtin. The resolved helpers are `_bashos_authcrypto`,
`_jsmn`, `_mbedtls` and `_monocypher`, with `-lpthread`.

Run normal checks against that binary with:

```sh
python3 tests/crypto-state.py out/bash-sol-crypto-after
python3 tests/sol-crypto-check.py out/bash-sol-crypto-after
python3 tests/final-smoke.py out/bash-sol-crypto-after crypto
bash tests/crypto-check.sh out/bash-sol-crypto-after
```

`tests/sol-crypto-sanitize.sh` compiles only crypto and its selected helpers,
loads them into the tested Bash ABI, and runs both dedicated suites and the
crypto smoke group. Set `BASHOS_TASK_DIR` to a private evidence directory. All
compilation, including this script, must run through the campaign build gate.

The unchanged catalog harness measures `crypto sha256 -x` against `sha256sum`,
using the exact `bytes(range(256))*4096` blob and eleven invocations per batch.
`bench/sol-crypto.py` supplements it with fixed size variants, a large SHAKE hex
output and a ChaCha20-Poly1305 allocation workload. It captures and validates
every output and fail-fast status in each warmup and timed batch, then records
seven samples with rotating implementation order. Timings include shell
startup and captured output. SHAKE and AEAD timings have no external ratio;
their independent references establish correctness, not matched work timings.
Before/after comparisons use the same host, CPU affinity, compiler flags,
helper selection, fixtures, options and work counts.

`bench/sol-crypto-profile.c` wraps allocation, read and conversion calls while
including the production crypto source. These are command-wrapper counts,
not counts inside separately linked helper primitives, and are not timing
measurements. Compile it as a shared loadable against the selected Bash tree
and staged helper headers, then load it with `enable -f`. Instrumented outputs
must pass the same independent references. Sampling with perf was denied by
host policy (`perf_event_paranoid=3`); validated strace profiles and these
counters provide the available overhead evidence. No host policy was changed.

The implementation routes fixed digest/MAC/X25519 output through the checked
emitter and clears stale stdout errors at invocation entry. Hex output uses a
bounded 4 KiB buffer rather than snprintf per digest byte or putchar per
nibble; temporary encoded text is wiped. Secret length and PHC reporting now
flush and propagate output failures too.

The slurp helper sizes regular files from their current offset, with an extra
byte for the EOF probe. Nonseekable/growing inputs still grow geometrically,
but copy, wipe and free the previous allocation instead of allowing realloc
to release an unwiped plaintext copy. Read/allocation failures wipe accumulated
input. This changes allocation behavior for pipe input; the timing claims
below are for the recorded regular-file fixtures. Both paths have independent
large-block correctness coverage.

AES-GCM and ChaCha20-Poly1305 use common cleanup exits within each command.
Decoded keys are wiped on parameter, input, allocation, guard, crypto and
output failures. Encryption wipes input before writing output; decryption
wipes its output buffer on both success and failure and emits nothing until
authentication succeeds. ChaCha now writes ciphertext and tag together and
returns the write status. Empty AES-GCM decryption no longer depends on the
platform's malloc(0) behavior.

The final native checks pass 11 state tests, nine reference/boundary tests
(with hundreds of subcases), 56 crypto smoke checks and the existing failed
SHA-256 write check. Both Python suites and all 56 smoke checks also pass with
ASan/UBSan instrumenting crypto and its 102 selected helper objects. The
baseline suite reproduced 38 failed-output regressions; those paths now pass.
Initial setup failures (a missing smoke companion selection, a counter-build
include-order error and the reference library's empty-SIV restriction) are
retained in the evidence rather than counted as successful checks.

The measurements use CPU 11 on an Intel Core i7-9850H, Linux
6.12.111+deb13-amd64, GCC 14.2, Bash 5.3.15, OpenSSL 3.5.7 and
cryptography 43.0.0. Both binaries use the same five-command selection,
`-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`, and retain symbols.
Each cell below is the seven-sample batch median (minimum–maximum), in
milliseconds. One full batch warmed each implementation first. The paired
run is the basis for change comparisons; separate snapshots varied in
absolute time on this active host.

| Work per invocation | Passes | Before ms | After ms | GNU ms |
|---|---:|---:|---:|---:|
| SHA-256, 0 B | 1000 | 65.55 (60.79–80.58) | 63.77 (57.63–76.36) | 4192.75 (3972.68–4457.87) |
| SHA-256, 64 B | 1000 | 75.97 (58.42–84.43) | 72.67 (56.11–75.15) | 4281.16 (4135.29–4669.69) |
| SHA-256, 8192 B | 200 | 33.35 (27.87–45.66) | 29.94 (25.58–42.79) | 910.97 (834.81–1259.47) |
| SHA-256, 1 MiB | 11 | 116.86 (96.90–159.14) | 117.23 (98.19–157.87) | 121.40 (99.79–155.76) |
| SHA-256, 16 MiB | 3 | 456.57 (428.03–519.14) | 467.02 (436.45–582.32) | 316.49 (293.97–363.90) |
| SHAKE-256, empty input, 65536 B digest as hex | 50 | 291.96 (248.78–301.72) | 199.83 (175.64–222.04) | — |
| ChaCha20-Poly1305 encrypt, 1 MiB | 11 | 126.37 (119.40–135.43) | 131.48 (123.06–146.33) | — |

The unchanged catalog harness reports before 57.182 ms versus
59.280 ms GNU (0.965×), and after 115.571 ms versus
127.873 ms GNU (0.904×), for the precise 11-pass 1 MiB blob case.
The historical 1.50× catalog slowdown was not reproduced before this
change. Large-input SHA-256 still favors GNU: the paired 16 MiB case is
1.48× external time. The shared compression backend is unchanged;
no SHA-256 throughput speedup is claimed.

SHAKE hex output improved 1.46× in the paired run. AEAD has a 4% higher
median with overlapping sample ranges; no AEAD wall-time speedup is
claimed. Its measured wrapper allocation work falls from 99 resizes to
zero and from 57,626,624 to 23,068,859 requested allocation bytes over
eleven calls. Wrapper reads fall from 110 to 22. These are request/count
reductions, not peak-memory measurements. The SHAKE profile reduces
1,441,803 character-output operations to eleven newline writes; SHA-256
reduces 352 formatted conversions to zero over eleven calls. Profiled
outputs match before/after and their independent references.

Raw reports in the task evidence directory are `catalog-before.json`,
`catalog-after.json`, `sizes-before.json`, `paired-after.json`,
`profile-before.json` and `profile-after.json`, alongside build/test logs,
manifests and source hashes. They retain all seven samples, fixture and
binary SHA-256 values, source hashes/HEAD, tool versions, affinity, work
counts and environment. Timed SHAKE/AEAD rows carry no external ratio.
Historical reports and shared catalog/registration files are unchanged.

To reproduce the additional workload through the campaign bench gate:

```sh
python3 bench/sol-crypto.py --before out/bash-sol-crypto-smoke-before \
  --binary out/bash-sol-crypto-after --output "$BASHOS_TASK_DIR/paired.json"
```
