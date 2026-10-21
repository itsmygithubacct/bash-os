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

Positive line-count `head` and `sed` use unbuffered stdio on nonseekable
input to avoid consuming a later reader's bytes. Head byte counts use bounded
reads; tail exclusion consumes through EOF. Ownership follows the opened
operand or duplicated stdin, even when opening a file reuses descriptor zero
because shell stdin was closed. Closing that file must close descriptor zero;
closing a stdin duplicate must leave shell stdin open.

`sed` evaluates lookahead only for a reached `$` address. On Linux pipes
and FIFOs it uses `tee(2)` to inspect availability without removing a byte;
sockets use `MSG_PEEK`. Thus even `sed '$!q'` leaves the complete next record
for another reader. If the producer remains open with no following byte, a
reached `$` must wait for data or EOF. `sed '1q'` and `sed '1q;$p'` need no
lookahead and return after the first complete line.

Read, open and output failures return a nonzero status. A later successful
file cannot erase an earlier `head` error, and a `sed q` status cannot hide an
I/O failure. Output streams are flushed before returning, and stdout's error
indicator is cleared after recording failure so subsequent shell output works.

## Scope and compatibility

Head supports the options described below; sed retains its command subset.
The compatibility boundaries are:

- `head` supports byte counts, zero and negative (tail-excluding) counts,
  quiet/verbose headers, `-` stdin operands, NUL-delimited records, long options
  and GNU numeric suffixes, in addition to positive line counts and legacy
  `-N`. See [the head completion report](sol-head.md) for semantics, focused
  coverage and separate first-N/tail-exclusion measurements.
- `sed` defaults to BRE; `-E`/`-r` select ERE. Numbering, hold space, address
  ranges and `n`/`N` span named operands by default. `-s` and `-i` start separate
  file cycles. The option parser and command set remain a GNU sed subset.
  Length-aware GNU regex matching supports embedded NUL subjects: glibc's
  engine, or a private GNU sed 4.9 engine on other libcs. Bracket expressions
  may contain the regex delimiter. `e` commands continue across a
  backslash-newline. A `v` token is accepted when it is not newer than 4.9,
  so `v 4.9` and `v 4.09.0` are accepted and `v 4.9.0` and `v 4.10` are
  rejected. A blank after the token separates the next command. In-place
  replacement is pinned to the parent directory. A
  repeated group that can match empty and contains an anchor followed by a
  consumer is matched directly when it is one capturing group of anchors,
  literals and GNU classes. `\b` and `\B` are left to the engine. In a
  multibyte locale that direct match runs for bytes below 0x80 and is
  refused for a higher byte when the pattern uses a word class or
  case-insensitive match. Any other pattern of that shape is searched with
  one register: no match is unchanged, and a match is refused because
  filling the other registers may not return. An address passes no
  registers and runs. A finite repeat that hits a blocked consumer fails
  only a substitution: `/(|^b){1,3}/p` on `bb` prints the line twice.
  A star does not consume a failed `\>` between word characters, so
  `s/(|\>b)*/[&]/g` on `ab` prints `[]a[]b[]` and `s/(|\>b)*/x/g` on
  ` abc` prints `x xaxbxcx`. `+` and a finite bound still use that span.
  A repeated group the engine can finish is left to the engine.
  Substitutions the direct matcher does not cover stay refused when one
  register matches, because filling the other registers may not return
  and that span is not GNU sed's text. The refused shapes are a prefix
  before the group (`a(|^b)+` and `.(|^b)+`), a nested group
  (`((|^b))+`), and a consumer after the group (`(|^b)+b`), including
  the same shapes with `` \` ``, `\<` and `\>`. Addresses of those
  shapes pass no registers and run.
  `-z`, `--sandbox`,
  `--follow-symlinks` and `\cREGEXc` addresses are supported; `--posix` and
  `--debug` are rejected. See [the focused completion notes](sol-sed.md) and
  [the follow-up notes](opus-sed-followup.md) for the tested scope.
- `sed q` and `l` follow GNU framing, including an unterminated last pattern;
  `R` preserves an unterminated auxiliary record. BusyBox 1.37 differs for
  these and for some explicit `-n` prints, so the suite compares those cases
  with GNU only.
- Linux pipes, FIFOs and sockets have a nonconsuming `$` lookahead. Terminals
  and other platforms use `poll` and `FIONREAD` where available, and stdio
  `ungetc` otherwise; only seekable input can return such a fallback byte to
  a shared descriptor. A canonical terminal EOF marker followed by already
  queued input is misclassified (the Linux terminal driver offers no
  nonconsuming way to see it); non-Linux kernels are unqualified.
- Avoiding pipe read-ahead uses byte-at-a-time input syscalls for positive
  line-count `head` and ordinary `sed` input on pipes and terminals. Head byte
  counts read bounded blocks, and tail exclusion consumes the complete pipe
  using blocks. The historical regular-file benchmark does not measure pipe
  throughput.
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
