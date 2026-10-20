# wc character, word and display-width completion

`wc -m` in a multibyte locale now scans ASCII runs a machine word at a time
and decodes non-ASCII characters directly from the input block. Only a sequence
split across a block boundary is copied. Character-only requests avoid word
classification and display-width calculation. Combined `-m/-w/-L` requests
retain locale decoding, invalid-byte word membership, Unicode whitespace,
`POSIXLY_CORRECT`, combining-character widths and tab stops.

The C-locale character-only read path already existed at the starting revision.
The historical 1.60× external-runtime figure is a separate measurement from an
older binary; it must not be used as a paired baseline for this change.

Read errors now return failure, including a directory redirected onto stdin.
An empty `--files0-from` list succeeds without output, and an unterminated final
name has room for its terminator at an allocation boundary. Stream error flags
are cleared on entry for subsequent calls in the same shell.

## Coverage

The retained `tests/wc-check.sh` and `tests/wc-tail-parity.sh` cover their previous
write-error, GNU comparison and corrected word-count cases. The additional
`tests/sol-wc-check.py` checks the following with an empty `PATH`:

- C, C.UTF-8 and en_US.utf8, with and without `POSIXLY_CORRECT`;
- `-m`, `-w`, `-L`, their combinations, all fields and default counts;
- malformed, truncated and split UTF-8 at 64 KiB and 128 KiB boundaries;
- wide and combining characters, embedded NULs, binary bytes, Unicode spaces,
  tabs, carriage returns and form feeds;
- distinct repeated redirections, empty inputs between calls, locale changes,
  pipes, partial stdin consumption and repeated `-` operands;
- named-file totals, maximum-of-width totals, invalid options, missing files,
  read errors, write errors followed by recovery, and descriptor cleanup;
- empty, invalid, unterminated and allocation-boundary NUL-separated name lists.

The independent fixture oracle spells out the relevant whitespace and width
rules. On the measured glibc build, `mbrtowc` also accepts the fixture encoding of
U+110000 as one nonprinting `wchar_t`; the oracle accounts for that behavior
explicitly. Python's strict Unicode decoder would incorrectly reject it. These
results cover the listed locales on glibc, rather than every libc/encoding pair.

`tests/sol-wc-sanitize.sh` builds the production source as an ASan/UBSan loadable
and runs the same assertions in the actual shell. Run this compiling test through
the build resource gate. No shared helper changes are required. `wc` has no
required companion; the retained combined parity suite additionally needs `tail`
and `cat` in the selected test binary.

## Measurement method

`bench/sol-wc.py` accepts one or more `--binary LABEL=PATH` arguments and an
`--output REPORT.json`. Run it through the benchmark resource gate, after builds
have completed through the build gate. It compares each builtin with GNU `wc`
from the same shell, reopens stdin on every pass, warms each case once, then
interleaves seven samples, reversing order each round. Every invocation must
succeed and produce the independently expected character count.

The matrix contains ASCII text and valid mixed UTF-8 near 4 KiB, 423 KB and
4 MiB in each of the three locales. The 423 KB ASCII seed matches the existing
`wc-characters` workload. Reports record exact fixture bytes, logical character
counts and work per batch, fixture/source/binary hashes, tool versions, fixed CPU
affinity, environment, sample distributions and separately probed peak resident
memory. `bench/sol-wc-rusage.c` uses a fresh C parent and `fork`/`wait4` to avoid
the Python driver's inherited high-water RSS, which can inflate the raw `wait4`
RSS from timed child processes. Build this launcher separately through the build
gate as `out/sol-wc-rusage` (or pass its path with `--rusage`).
Reported memory is the maximum for the shell and its waited-for descendants,
not a sum or an incremental allocation attributed solely to `wc`. GNU may use
file metadata or seeking in single-byte locales; byte work is the logical input
counted, rather than a claim that both implementations read every byte.

`bench/sol-wc-calls.c` and `bench/sol-wc-profile.py` count calls to `mbrtowc`,
`wcwidth`, `iswprint` and `iswspace` in the real executable. A shell/redirection
control is subtracted. This profile has no timing ratio. Compile the interposer
through the build gate and run its profile through the benchmark gate.

The existing `bench/loadables.py` is also run unchanged through the task-owned
`bench/sol-wc-loadables.py` adapter for `wc-characters`, `wc-counts` and `wc-width`
with 42 passes and seven samples in its C locale. The adapter captures timed
output and validates every count row against an independent ASCII fixture oracle;
the shared harness normally discards timed output after a separate validation
batch. Short-row validation overhead is included on both sides. Fixture scanning
and hashing are cached during the initial validation, before timed samples.
Raw reports and exact command receipts are retained outside the repository in
the task evidence directory. Historical reports and shared catalog files are
unchanged. Full-catalog and isolated static-rootfs checks remain integration
checks; they are not claimed by this targeted build.

## Validated results

The native and ASan/UBSan runs each passed 8,979 assertions. The retained suites
passed all seven `wc-check` checks and 216 parity/corrected-word checks. The
targeted host smoke test passed six checks with only `wc`, `tail` and `cat`
selected. The expanded baseline suite exposed the ignored redirected-directory
read error before the fix.

The call-count profile independently validated each output on 422,994 input
bytes, subtracting the no-op shell control:

| input | characters | decoder calls before | decoder calls after | width calls before | width calls after |
|---|---:|---:|---:|---:|---:|
| ASCII | 422,994 | 422,994 | 0 | 398,112 | 0 |
| mixed UTF-8 | 357,918 | 357,918 | 48,808 | 325,380 | 0 |

Word-space and printability classification calls also fall to zero for `-m`.
Non-ASCII decoding still uses `mbrtowc`, including its locale-specific treatment
of malformed and incomplete sequences. The profile counts calls rather than
attributing time to individual library functions.

The final paired run used CPU 11, GCC 14.2, glibc 2.41, Bash 5.3.15 and GNU
coreutils 9.7. Each table entry is the median batch time in milliseconds over
seven validated samples, after a validated warmup. These C.UTF-8 results include
shell startup; the GNU column also includes launching the external command on
each pass.

| input | bytes / characters per pass | passes | before ms | after ms | GNU ms |
|---|---:|---:|---:|---:|---:|
| ASCII, 4 KiB | 4,096 / 4,096 | 42 | 6.487 | 1.370 | 29.208 |
| ASCII, 423 KB | 423,000 / 423,000 | 12 | 197.469 | 2.105 | 33.800 |
| ASCII, 4 MiB | 4,194,304 / 4,194,304 | 3 | 488.137 | 3.245 | 54.509 |
| mixed UTF-8, near 4 KiB | 4,094 / 3,465 | 42 | 8.672 | 2.785 | 46.227 |
| mixed UTF-8, 423 KB | 423,000 / 357,924 | 12 | 152.645 | 17.682 | 41.586 |
| mixed UTF-8, near 4 MiB | 4,194,303 / 3,549,027 | 3 | 399.125 | 44.083 | 81.859 |

Thus the 423 KB ASCII and mixed UTF-8 batches improve by 93.8× and 8.6×
respectively against the preserved baseline binary in this paired run.
The complete report also covers C and en_US.utf8: all 18 cases passed for the
baseline, revised builtin and GNU reference. The revised binary's separate
validated memory probes reported 3,228–3,780 KiB peak RSS across the matrix.
For example, the largest mixed batch counts 12,582,909 logical input bytes and
10,647,081 characters. Counting these streams uses a bounded block buffer;
the optional filename-list parser stores its list separately. Full sample
distributions, memory probes and hashes are in
`bench-paired-v2.json` in the task evidence.

The historical three-case reproduction used 423,000 ASCII bytes per pass and
42 passes (17,766,000 logical bytes per batch), with all timed output checked:

| C-locale workload | baseline builtin ms | revised builtin ms | GNU ms (revised run) |
|---|---:|---:|---:|
| `wc -m` | 4.324 | 3.669 | 31.008 |
| `wc -lwc` | 73.827 | 70.095 | 78.558 |
| `wc -L` | 16.529 | 16.286 | 76.793 |

The baseline character runtime was already 0.144× its matched GNU reference;
the revised run is 0.118×. The historical 1.60× gap does not reproduce on the
starting source. Small C-locale differences are not evidence of a new speedup
in that existing path. All three implementations, including BusyBox, passed
all three cases; the separate before/after reports retain seven samples and
66 independently validated timed/probe batches each. These reports are
`loadables-before-v2.json` and `loadables-after-v2.json`.

The initial baseline report is retained separately. Its timing/output evidence
is valid, but its direct Python-parent `wait4` RSS includes inherited high-water
memory and should not be used for command memory claims. The first final run
completed the call profile, then stopped because `/usr/bin/time` was unavailable.
The final retry uses the compiled C launcher above; no failed or historical
report was replaced.
