# sed follow-up: delimiters, addresses, GNU options and limits

This follow-up closes the review items left after the [sed completion
work](sol-sed.md). GNU sed 4.9 is the reference throughout. The focused suite
is `tests/opus-sed-followup-gnu.py`.

## Escaped delimiters

GNU sed removes the backslash from an escaped delimiter before it reads any
other escape. The character is then an ordinary character for the regex,
replacement or `y` set:

| Script | Input | Output |
|---|---|---|
| `s.a\.b.X.` | `axb` | `X` (the dot is a regex operator) |
| `sn\nnXn` | `anb` | `aXb` (`\n` is the letter n) |
| `st\ttXt` | `atb` | `aXb` (`\t` is the letter t) |
| `sx\x41xXx` | `ax41b` | `aXb` (no hexadecimal escape) |
| `s1a1[\1]1` | `ab` | `[1]b` (no backreference) |
| `sUaU\UbU` | `ab` | `Ubb` (no case conversion) |
| `yna\nnbbn` | `an` | `bb` |

`\&` remains a literal ampersand when `&` is the delimiter. The commit
`9311979` stopped keeping the backslash before regex operators, but other
escapes still took precedence over the delimiter. A newline cannot be a
delimiter for `s`, `y` or an address.

## Addresses and commands

`\cREGEXc` addresses accept any delimiter except newline, including
backslash. They support the `I` and `M` flags, ranges, `!`, blocks and
empty-regex reuse. A delimiter inside a bracket expression is part of the
expression, including after `[^` and inside `[:` `[=` `[.` names. The same
scan is used for the regex half of `s///`. The replacement half and `y`
still end at the first unescaped delimiter. `z` empties the pattern space.
`v [VERSION]` reads one version token the way GNU sed reads a label.
Leading blanks are skipped. The token ends at the next blank, semicolon,
`}`, newline or `#`, and that character stays for the next command. A
blank that ends the token separates the next command (`v 4.9 p` runs `p`).
A letter does not (`v 4.9p` is the token `4.9p`). An
empty token is accepted. The token is accepted when `strverscmp` does not
find it newer than 4.9 (`v 4.9`, `v 4.09.0`, `v 4.8.`, `v -1`, `v 4.`).
A newer token is rejected (`v 4.9.0`, `v 4.9.`, `v 4.10`, `v 5`).

`e COMMAND` runs the command and writes its output before the cycle's
output. The command continues across a backslash-newline: the backslash is
dropped, the newline is kept, and spaces or tabs on the next line are
skipped. A semicolon does not end it. A blank command, or one that is only
`;` or `}`, is the pattern-space form. Bare `e` replaces the pattern space
with the output of running it. Both forms, and the `s///e` flag, still require
`BASHSED_ALLOW_EXEC=1`. Output from `e` loses one trailing record separator,
and the result is always a complete record. `s///e` also loses one trailing
separator. When the replacement is empty and the first match either starts a
non-global substitution or ends the pattern space, GNU takes a shortcut that
also completes the record; the builtin follows that shortcut too.

`w /dev/stdout` and `w /dev/stderr` share their streams but, as in GNU sed,
track pending newlines separately. Therefore `sed 'p;w /dev/stdout'` on an
unterminated `a` prints `aa\na`.

## Options

- `-z`, `--null-data` and `--zero-terminated` use NUL as the record separator.
  `N`, `G` and `H` join with NUL. `P`, `D` and `W` split at NUL. `=`, `l`,
  `i`, `c`, `F`, `R` and the `l` wrap marker also use NUL. `a` text, `r` files
  and `e` output keep their own bytes. With the `M` flag, `^` and `$` anchor at
  NUL-separated records, because the regex is searched one record at a time
  as in GNU sed.
- `--sandbox` rejects `e`, `r`, `R`, `w`, `W`, `s///e` and `s///w` while
  parsing, before any write file is created. Other commands are unaffected.
- `--follow-symlinks` resolves links one at a time. A relative target is
  joined to the link's directory, so `F` reports `sub/../file` as GNU does.
  `-i` then edits, and backs up, the final target. Dangling links and loops
  fail with status 4. The walk uses `openat` and `readlinkat` from the held
  parent: an absolute target restarts at `/`, and `..` stays relative to that
  directory.
- Without `--follow-symlinks`, `-i` reads through a symlink and replaces the
  link with the edited regular file, as GNU sed does. The builtin used to
  refuse symlinks. The parent directory stays open for the temporary file,
  the backup and the final `renameat`. Before those replacements, the
  directory and the final directory entry are checked again; a changed
  identity deletes the temporary file and returns status 4. A backup suffix
  that contains `/` is rejected so the backup cannot leave that directory.
  Directories, FIFOs and devices are still refused (status 4). The source is
  opened without blocking and then checked with `fstat`.
- `-b`/`--binary` is accepted and does nothing, as on other POSIX systems.
  `--version` prints a `sed (bash-os loadable)` line and returns 0.
- `--posix` and `--debug` are **not implemented**. They, like any other
  unknown long option, fail with status 1 and print
  `unsupported option`. The suite checks this.

These settings belong to one invocation. The suite checks in one persistent
shell with empty PATH and a 32-descriptor limit that `-z`, `--sandbox` and
`--follow-symlinks` do not affect later calls.

## Regex search and performance

Case-sensitive regexes now get a 256-byte fastmap, as in GNU sed, so a search
skips positions where no match can start. Under `-z`, the `M` flag clears
`newline_anchor`. The search then runs over each NUL-separated record and
keeps the preceding context. Offsets are returned relative to the whole
pattern space.

The review found that on static musl the branch workload ran slower than
GNU sed. perf is unavailable on the build hosts (`perf_event_paranoid` is 3),
and gprofng cannot preload its collector into a static binary. The cause was
therefore found with paired timings. Every successful `s///` allocated an
output buffer, copied it into the pattern space and freed it. Every literal
search also paid musl's per-call two-way `memmem` setup. Now the output
buffer lasts for the invocation and is swapped with the pattern space.
Literals of up to 32 bytes use `memchr` and `memcmp`; longer needles keep
`memmem`. If allocation fails while a result is being built, the command
reports an error instead of leaving the pattern space unchanged.

glibc's `set_regs` does not return when `re_search` is asked for registers
and the pattern is a repeated group that can match empty and that contains,
in one alternative, an anchor (`^`, `` \` ``, `\<` or `\>`) followed by a
consumer. The global substitution retry is that call, including when an
empty `s//` reuses an address regex. If the whole pattern is one capturing
group of anchors, literals and the GNU classes `\s` `\S` `\w` `\W`, sed
matches it directly and never calls `re_search`. `s/(|^b)+/x/g` on `.b`
therefore prints `x.xbx`. A finite upper bound does not record that empty
iteration when the next byte is a consumer the anchor rejected, and the
search stops, so `s/(|^b){1,3}/<\1>/` on `bb` stays `bb` and with `g` on
`.b` prints `<>.b`. An unlimited `+` or `*` is unchanged. The same shape
with `` \` ``, `$` or `\<` is handled the same way. `\b` and `\B` are not: `re_search` returns for them,
and the direct matcher does not reproduce its spans, so `s/(|\bb)+/[&]/g`
on `ab` is run by the engine and prints `[]a[b]`. `s/(|\Bb)+/[&]/g` on
`.b` prints `[].[b]`. `\>` followed by a literal uses the span glibc
returns on subjects where that search finishes (`s/(|\>b)+/[&]/g` on `ab`
prints `[]a[b]`) and still does not call `re_search` where it does not.
`\'` is not one of those anchors, so `s/(|\'b)+/[&]/g` is run by the regex
engine and prints `[].[b]`. A repeated group glibc can finish, such as
`s/([a]|^)+/X/g` or `s/b(|^)+/X/g`, is also run by the engine. Any other
pattern of the hanging shape, including `a(|^b)+`, `((|^b))+` and
`a\(\|^b\)\+`, is refused with `regex may hang; refusing pattern` before
it is compiled. Ordinary patterns, including `(^a)+` and `\(a\)\+`, still
use the regex engine. In a multibyte locale that direct match still runs
when every pattern-space byte is below 0x80, so `s/(|\<b)+/x/g` on `.b`
prints `x.x` under C.UTF-8 and `s/(|^b)+/x/gI` on `.B` prints `x.xBx`.
A byte at or above 0x80 is refused for a word or case-insensitive direct
match, because the matcher classifies bytes and that is not GNU sed's
multibyte word or case class. `\b` and `\B` stay with the engine in every
locale. Address searches pass no registers;
they are the only other `re_search` call, and a refused pattern never
reaches either call.

`bench/opus-sed-followup.py` runs builtin variants and GNU sed 4.9 in one
process. It uses the sol-sed fixtures and expected bytes computed in Python.
Each variant gets one warmup, then seven samples in rotating order. A sample
is eight calls, and every call's output file and status are checked. Runs
used an Intel Core i7-9850H, CPU 11 and Linux x86-64, through the campaign
bench gate. Host load was about 9 when each run started, so the spread is
wide. Cells give the median and range in milliseconds per eight calls.
"Before" is `9311979`; "after" is `b752690`, whose binaries are
byte-identical to the measured ones.

| libc | Workload | Before | After | GNU sed | After / GNU |
|---|---|---:|---:|---:|---:|
| musl 1.2.5 static | Historical substitution | 91.1 (81.8–94.6) | 85.8 (72.1–102.3) | 122.5 (114.5–131.3) | 0.70 |
| musl 1.2.5 static | Substitution/branch loop | 271.5 (248.6–300.8) | 186.7 (177.1–205.7) | 233.8 (207.0–252.1) | 0.80 |
| musl 1.2.5 static | Multifile hold/range/substitution | 99.0 (82.6–131.2) | 88.1 (75.7–108.1) | 98.5 (87.3–143.1) | 0.89 |
| glibc | Historical substitution | 39.3 (36.0–53.0) | 41.9 (36.7–49.4) | 118.7 (111.4–127.0) | 0.35 |
| glibc | Substitution/branch loop | 132.1 (125.6–192.6) | 105.7 (97.5–125.9) | 247.0 (222.0–301.4) | 0.43 |
| glibc | Multifile hold/range/substitution | 55.4 (46.3–69.6) | 57.5 (48.9–68.8) | 101.7 (92.4–113.9) | 0.57 |

The glibc run suggested the literal loop might be slower than glibc's
`memmem` for plain substitution, so a second paired glibc run compared three
builds. One was the commit before the optimization, one was this commit,
and one kept `memmem` on glibc:

| Workload | Before optimization | This commit | glibc `memmem` | GNU sed |
|---|---:|---:|---:|---:|
| Historical substitution | 31.3 (30.7–33.5) | 32.8 (29.9–38.4) | 30.3 (29.2–31.3) | 95.1 (90.7–101.1) |
| Substitution/branch loop | 106.3 (82.6–140.8) | 79.9 (74.1–103.1) | 97.6 (88.3–105.4) | 169.7 (157.3–204.6) |
| Multifile hold/range/substitution | 36.5 (32.3–42.6) | 34.8 (30.8–38.1) | 36.9 (32.3–39.5) | 64.2 (56.3–70.4) |

The substitution difference is within noise, while the shared literal loop
is clearly faster for branching. One search path is therefore used on every
libc. The original musl slowdown no longer reproduces: all three musl
workloads now run faster than GNU sed. Load on the second run rose to about
20, and its timings are lower than the first run's for every command, so the
two runs must not be compared with each other. Neither table should be
compared with the historical sol-sed timings. Raw reports, with every
sample, per-pass validation counts and the SHA-256 of each binary, source
and fixture, are in the task receipt as `bench-ab1-musl.json`,
`bench-ab1-glibc.json` and `bench-ab2-glibc.json`.

## Remaining limits

- **Canonical terminal EOF before queued input.** `tests/sol-sed-terminal-eof.py`
  is still a strict failure on Linux, and it is not a skip. The Linux
  terminal driver stores an EOF marker as a flagged NUL. `FIONREAD`
  (`inq_canon`) subtracts that marker, and `poll` reports the same readiness
  for `\x04b\n` and `b\n`. The only ways to see the marker are a consuming
  `read` or toggling `ICANON`, and toggling clears the line flags, turning
  the marker into a NUL data byte. A consuming read would lose a byte of
  ordinary queued input. That breaks the guarantee, checked by
  `sol-sed-complete.py`, that later readers receive every byte. The builtin
  keeps that guarantee, so a line followed by a queued EOF marker and more
  data is not treated as the last line. GNU itself reads ahead one whole
  terminal line, so it loses that line from later readers.
- **Non-Linux kernels.** The `tee(2)` pipe peek is Linux-only. Other systems
  use `MSG_PEEK`, `poll`/`FIONREAD` and stdio fallbacks, and none of these
  paths has run on a non-Linux kernel.
- **`--posix`, `--debug`.** Rejected, as described above.

## Validation

The final commit passed, on glibc and on static musl 1.2.5:

- 817 checks in the new suite;
- 276 focused cycle and consumption checks;
- 312 framing, CLI and terminal checks;
- 1,008 binary regex comparisons;
- 12 signal checks;
- 977 head/sed parity checks;
- 8 stream checks;
- 156 mixed-reader checks.

The musl binary also passed the isolated-rootfs check. ASan/UBSan modules
passed all six suites run by `tests/sol-sed-sanitize.sh` on both the system
and the portable regex backends. The commit was also merged onto the
integration branch, using the merge resolution in the task receipt. It built
and passed the same suites. `tests/sol-sed-terminal-eof.py` fails, as
described above.

```
./build.sh --include sed,head,fold,expand,nl,pr,tac,bc --name opus-sed-followup
for t in opus-sed-followup-gnu sol-sed-parity sol-sed-complete sol-sed-binary-regex \
         sol-sed-signals head-sed-parity sed-streams input-lifetime; do
  python3 tests/$t.py out/bash-opus-sed-followup
done
python3 tests/sol-sed-terminal-eof.py out/bash-opus-sed-followup   # strict; fails
bash tests/sol-sed-sanitize.sh out/bash-opus-sed-followup          # via build gate
python3 bench/opus-sed-followup.py REPORT.json \
  before=OLD_BASH,OLD_SED_C after=NEW_BASH,NEW_SED_C               # via bench gate
```
