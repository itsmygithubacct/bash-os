# head and sed in a persistent shell

`head` and `sed` now start each stdin redirection with a fresh input stream.
For a file containing `a\nb\nc\n`, these loops print `a\n` three times and
`A\nb\nc\n` three times respectively:

```bash
for ((i=0; i<3; i++)); do head -n 1 < "$input"; done
for ((i=0; i<3; i++)); do sed s/a/A/g < "$input"; done
```

`sed s/a/A/g` preserves an unterminated final line. Pattern-space printing,
hold-space operations, `n`/`N`, write-file commands and in-place editing also
retain the line-ending information. When one invocation prints an unterminated
pattern more than once, it separates the output records: `sed p` on `a` prints
`a\na`, matching GNU and BusyBox. Each invocation owns that output state, so
three separate calls on `a` produce `aaa`.

## Input lifetime and errors

The stock Bash `head` used the process-wide `stdin` object. Its `getc` calls
filled a buffer past the requested line; subsequent shell redirections changed
fd 0 but left the old bytes buffered. Clearing EOF would still leave those
bytes. The earlier `sed` also used `stdin`, and its `getline` loop left the EOF
indicator set after the first invocation. It separately removed the input
newline and unconditionally printed one, losing the unterminated-line case.

Both commands now duplicate fd 0 into a private `FILE` and close it after the
call. On seekable stdin, `fseeko(stream, 0, SEEK_CUR)` returns stdio's unread
bytes to the shared descriptor position before closing. This lets a later
shell `read` continue immediately after `head`'s last line or `sed`'s early
quit. Simply closing a buffered duplicate would lose that data.

Nonseekable input uses unbuffered stdio to avoid consuming a later reader's
bytes. `sed` no longer preloads a whole following line; it peeks one byte only
when evaluating a `$` address. Thus `sed '1q'` and `sed '1q;$p'` return after the
first complete line even while a pipe producer remains open.

Read, open and output failures return a nonzero status. A later successful
file cannot erase an earlier `head` error, and a `sed q` status cannot hide an
I/O failure. Output streams are flushed before returning, and stdout's error
indicator is cleared after recording failure so subsequent shell output works.

## Scope and compatibility

These remain command subsets, with the following limits:

- `head` retains Bash's positive `-n N`, legacy `-N`, default ten lines, and
  named-file headers. It does not implement GNU byte counts, zero/negative
  counts, quiet/verbose flags or the `-` stdin operand. Its inherited `atoi`
  count parsing is not a strict GNU numeric parser.
- `sed` uses extended regular expressions by default with limited BRE escape
  translation; `-E` is a no-op. Its option parser and command set are not full
  GNU sed. Numbering, hold space and address ranges restart for each named
  file. Regex operations are text based; binary-regex parity is not claimed.
- `sed q` preserves an unterminated line like BusyBox; GNU sed 4.9 adds a
  newline for this command. Conversely, `sed -n p` preserves it like GNU;
  BusyBox 1.37 adds a newline for some explicit print commands. These are
  separate reference differences, not byte-equivalence claims for those cases.
- The existing `sed l` long-line wrap width differs from GNU. `R` still adds
  a newline to an unterminated line read from its auxiliary file.
- A `$` address needs lookahead. If it is evaluated before an early quit on
  a pipe, the peeked byte cannot be returned to the kernel pipe for a later
  shell reader. Seekable stdin restores that byte. Ordinary `q`, `n` and `N`
  paths do not have this limitation.
- Avoiding pipe read-ahead uses byte-at-a-time input syscalls on pipes and
  terminals. The regular-file benchmark does not measure that throughput.
  Signal interruption and full GNU exit-code equivalence are outside the
  focused parity suite.

## Building and validation

The correction to stock `head` is
[`patches/head-stdin.patch`](../patches/head-stdin.patch), applied by
[`build.sh`](../build.sh) only when no source override supplies `head`.
The patch is included in the build cache key, and patch failure stops the
build. GNU Bash 5.3's source header and GPL-3.0-or-later licence remain intact;
the patch is distributed on those terms. There is no new `loadables/head.c`:
the catalog remains **278 commands, 247 local sources and 31 stock sources**.

```bash
JOBS=2 ./build.sh --profile core
python3 tests/head-sed-parity.py out/bash-core
bash tests/head-sed-sanitize.sh out/bash-core
python3 tests/profile-smoke.py out/bash-core
bash tests/licence-check.sh
```

The focused suite compares bytes and success statuses against installed GNU
and BusyBox tools, and checks repeated/changing/empty redirections, partial
reads, pipes, shell input after commands, descriptor lifetime, read/write
failures, quit codes, write files and in-place backups. Explicitly incompatible
reference cases above are selected by name in the test rather than silently
normalized. BusyBox checks are skipped with a message if it is unavailable.

The sanitizer runner compiles the patched stock `head` and local `sed` with
ASan/UBSan, binds calls to those replacements, and loads them into the real
shell for the same suite. It maps sed's legacy descriptor to the static
command name for testing. Leak detection is disabled for the uninstrumented
host Bash; memory/undefined-behavior checks remain active, and the suite also
runs 128 calls under a low descriptor limit.

Use the existing harness for the reviewed 423,000-byte fixture, preserving
its fixed pass counts and at least seven samples. Serialize timing with the
shared advisory lock when other worktrees are benchmarking:

```bash
flock "$BENCH_LOCK" python3 bench/loadables.py --binary out/bash-core \
  --only head --passes 80 --runs 7 --cpu "$CPU" --output /tmp/head.json
flock "$BENCH_LOCK" python3 bench/loadables.py --binary out/bash-core \
  --only sed --passes 14 --runs 7 --cpu "$CPU" --output /tmp/sed.json
```

Inspect each JSON result's `status`; a zero harness exit alone is insufficient.
The old builtins fail validation on these workloads, so no before/after
speedup ratio is meaningful.

## Measurements, 2026-09-08

The core profile was built before (`ef66d79`) and after (`ab893cb`) with GCC
14.2, `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`, dynamic linking and
stripping. The corrected binary SHA-256 is
`4e88251aab8d48d50cd1235735a051c8aff36c4c0b8a6cfecafd316e0804a0fc`.
These measurements use the same harness cases as the historical review, but
both builds here use the core profile; the historical table used full.

Each entry is the median milliseconds per batch, followed by min–max across
seven timed samples. Both runs used CPU 11 on an Intel Core i7-9850H, Linux
6.12.96, with the shared timing lock held. References were GNU coreutils 9.7,
GNU sed 4.9 and BusyBox 1.37.0. All variants ran in the same selected Bash
binary with empty `PATH`, `LC_ALL=C`, fresh stdin redirection on every call,
warm input and stdout directed to `/dev/null`. Times include shell startup,
redirections and external fork/exec costs.

| Case / build | Calls | Builtin ms | BusyBox ms | GNU ms |
|---|---:|---:|---:|---:|
| head before | 80 | INVALID: repeated output | 56.421 (53.099–70.083) | 45.573 (44.441–63.436) |
| head corrected | 80 | 7.585 (6.405–12.587) | 57.999 (53.715–70.882) | 44.876 (43.531–48.017) |
| sed before | 14 | INVALID: final newline | 127.281 (110.056–146.075) | 82.763 (79.076–97.471) |
| sed corrected | 14 | 93.785 (90.842–117.850) | 125.502 (108.744–137.108) | 78.527 (76.877–102.432) |

The unchanged 423,000-byte, unterminated text fixture has SHA-256
`fb6bb6eb8b1cfd98fb3003298131a665522fd5b2df04e7d9c7574a2dd63241ee`.
Arguments were `head -n 100` and `sed s/alpha/OMEGA/g`. All three corrected-run
variants passed single-call and complete-batch byte validation. The before
run failed builtin validation and therefore has no valid builtin timing.

Other work was active: the one-minute load average was 6.22 during the before
run, and 5.29–5.03 during the corrected run; corrected-run five-minute averages
were 7.88–7.79. The ranges show contention. These results establish valid
output and deployment costs for this calling pattern, not a speedup over the
incorrect implementations or a claim about pipe throughput.
