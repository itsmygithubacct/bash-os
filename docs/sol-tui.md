# tui API validation and traffic workloads

Validation is incomplete. The baseline build and targeted regression probes ran,
but the updated build was deferred by the campaign resource gate for sustained
host load and I/O pressure. The updated C changes have not been compiled; the
new PTY suite has not passed end to end. Sanitizer checks, updated top/more
revalidation and seven-sample latency measurements remain required. There are
no measured latency results or speedup claims in this report.

`tui` is a persistent cell API. It has no equivalent external command suitable
for a command-speed ratio. `tests/sol-tui-check.py` drives the production builtin
with an empty `PATH` and a private controlling PTY. A separate Python ECMA-48
interpreter checks characters, attributes, colors, cursor movement and terminal
restoration; it does not call the production screen or `vt` decoder.

The checks cover persistent draw cursors, clipping and wrapping, erase, box and
line drawing, clear-to-end operations, color-mode changes on existing cells,
ANSI SGR/control parsing, CSI/SS3 keys, ESC pushback, timeout and EOF statuses,
line editing/cancellation, grow/shrink resize, malformed arguments, output
failure/retry, repeated init/end, descriptor counts, subshell queries, restored
signal dispositions, normal exit and TERM/HUP restoration. EOF and write failures
replace only the owned child's tty descriptor with `/dev/null` or `/dev/full`;
no unrelated terminal or process is touched.

The argument contract now rejects extra arguments, malformed/overflowing numbers,
invalid colors and multi-character line glyphs (status 2). Coordinates are signed
16-bit integers, line lengths are 0..32767, and timeout is -1..INT_MAX. `--` permits
a text argument that looks like an option. `attr` accepts all supplied attributes
without silently truncating after eight. UTF-8 line glyphs use a complete scalar.
The screen remains a scalar-per-cell model: these fixtures qualify ASCII and
single-column UTF-8 glyphs, not wide/combining grapheme layout.

The shared screen fixes make resize queries apply pending geometry, retain a
separate test-and-clear resize notification, invalidate rendition after changing
color mode, skip unchanged cells between sparse edits, and expose retryable
refresh failures through an additive `bls_refresh_checked` API. Existing consumers
retain the void `bls_refresh` entry point. Screen teardown restores the previous
signal dispositions and registers process-exit cleanup once. The key helper adds
only a pending-pushback query, allowing screen input to drain queued bytes before
polling the terminal.

Reproduce the targeted build and tests (wrap builds and measurements in the
campaign's gates when running inside that campaign):

```sh
./build.sh --include tui,top,more --name sol-tui
python3 tests/sol-tui-check.py out/bash-sol-tui
bash tests/sol-tui-sanitize.sh out/bash-sol-tui
python3 tests/sol-more-check.py out/bash-sol-tui
python3 tests/sol-more-helper-check.py out/bash-sol-tui
python3 bench/sol-tui.py --binary out/bash-sol-tui --output /tmp/tui-api.json
```

The sanitizer script compiles the actual tui, screen and key sources into one
ASan/UBSan replacement module and runs the same PTY assertions. Its build must be
gated. Sanitizer leak detection is disabled for the hosting Bash process;
repeated lifecycle checks independently verify descriptor and terminal cleanup.

The benchmark uses a fixed 24×80 screen, initially filled with `A`, with the
logical and physical cursors parked at (0,0). Each sample executes 200 draw/refresh
calls. No-op redraws the identical screen; sparse alternates three cells between
`B` and `A`; full alternates all 1,920 cells. Every sample validates statuses,
exact terminal bytes, printed cell counts and every decoded frame. Each case has
one validated warm-up and seven samples on one recorded CPU. Timing spans command
submission through acknowledgement and terminal drain, before decoding. It
includes Bash dispatch/loops and PTY consumer scheduling. Reports retain source
and binary hashes, fixture hashes, versions, options and individual samples.

For the default 200-call batches, the exact expected traffic is:

| Workload | Changed/printed cells per refresh | Bytes per refresh | Bytes per batch |
|---|---:|---:|---:|
| no-op | 0 | 0 | 0 |
| sparse | 3 | 30 | 6,000 |
| full | 1,920 | 2,079 | 415,800 |

These counts exclude initialization/teardown and include cursor parking. The
sparse positions are (2,3), (2,70), and (20,70), using zero-based coordinates.
The baseline correctness probe emitted 14 character cells for two changed cells
on one row and accepted malformed coordinates, colors and extra arguments. The
baseline PTY test also exposed stale colors after a color-mode change. Invalid
baseline workloads must not receive a speedup claim.
