# more: paging, stream ownership, and buffering

`more` keeps nonterminal output byte-exact, including NULs, long records,
unterminated final records, and multiple-file headers. Each call owns its input
stream, including a duplicate of redirected stdin. Quitting with unread input
therefore cannot leave buffered bytes for the next redirected invocation.

Nonterminal copying uses bounded 64 KiB reads and private output buffering.
Each successful read is flushed immediately, so pipes remain responsive while
their producer stays open. Readiness waits and partial writes check Bash
interrupts; a full output pipe cannot trap the pager in an unchecked retry.
Bash's persistent stdio buffering and signal state
are preserved. The regular-file bulk path was already faster than the external
reference on the reproduced historical case. The new path also avoids
line-by-line copying on nonterminal pipes.

Interactive mode owns one terminal descriptor per operand. An unwind handler
restores termios and the previous SIGWINCH disposition, closes the descriptor,
and frees temporary line storage on normal exit and Bash interrupts. The shared
key decoder has an optional safe-point callback; `more` uses it to check Bash
interrupts inside interrupted-read retries and escape-sequence assembly. The
original `bl_read_key` API retains its behavior for other consumers.

Enter now maps from the decoder's `BL_KEY_RET` to one-line navigation. Help
re-prompts without consuming a record; literal search includes bytes after a
NUL; `q` stops the entire operand list. Numeric page sizes reject overflow.

## Validation

`tests/sol-more-check.py BINARY` exercises exact bytes for files, redirected
stdin and pipes; distinguishable repeated inputs; stdout ordering; invalid
arguments; input/output errors and recovery; and private controlling PTYs.
Terminal cases cover paging, Enter/j/Down, PgDn/f, ignored backward keys, ESC
pushback, help, search/backspace, resize at a prompt and during blocked input,
EOF, repeated quit, SIGINT during key/search/FIFO reads, descriptor cleanup,
terminal restoration, and restoration of the shell's WINCH trap.
The interrupt fixture waits for an actual shell prompt before sending another
command. A separate full-pipe check requires SIGINT to return without a reader
draining the output.

`tests/sol-more-helper-check.py BINARY` revalidates `top` batch/interactive mode
and `tui` CSI/Enter/pushback behavior through the original shared decoder API.
Build with `--include more,less,top,tui` for these checks and the existing
`tests/pager-interrupts.py` and `tests/regressions.py BINARY PagerTests`.
Only `more` needs the instrumented module in `tests/sol-more-sanitize.sh`;
run that script through the build gate.

The scope is this forward-streaming pager's documented interface, not complete
POSIX or util-linux `more` conformance. Backward navigation remains deliberately
ignored; search is literal and accepts at most 127 pattern bytes. Interactive
input is counted by newline records rather than rendered wrapping height. A
full-page EOF may require the next advance key to discover EOF; the pager does
not wait for speculative lookahead from an open pipe. No physical terminal
qualification or external interactive-pager equivalence is claimed.

## Measurement

The unchanged `bench/loadables.py --only more --passes 12 --runs 7` reproduces
the historical two-file case with output sent to `/dev/null`. Its output oracle
covers a separate repeated validation batch. `bench/sol-more.py` supplements it
with complete output/status validation on every warmup and timed sample:

* Historical operands: `more -n 100 text copy`, 12 invocations per sample,
  846,070 bytes per invocation, including headers.
* Large copy: a 32 MiB binary fixture on redirected stdin and through a pipe,
  three invocations per sample for each input type. Both implementations use
  stdin; this avoids util-linux's extra single-binary-operand header.
* Interactive paging: three invocations per sample, each 3,107 lines / 52,819
  input bytes, 31 prompts, 31 space keys, and final EOF on a private PTY. Every
  page is checked against independently generated line and prompt bytes.

The captured-output cases compare the builtin and `/usr/bin/more` from the same
shell on identical fixtures. Interactive timings have no external ratio. Each
driver records seven samples after warmup, CPU affinity, versions, fixture
hashes, binary/source hashes, and reset rules. Syscall profiles are separate
validated runs. All builds and measurements use their campaign resource gates;
raw reports and logs remain outside the repository.

The historical 3.32× slowdown did not reproduce on the starting build. The
unchanged historical driver recorded 4.090 ms for the builtin and 15.404 ms for
the external command (12 invocations, output to `/dev/null`). The more rigorous
captured-output adapter also found the builtin faster on those operands.

The remaining bottleneck was nonterminal pipe input: three 32 MiB copies took
430.480 ms in the starting builtin versus 123.318 ms externally. A separate
validated syscall profile recorded 131,201 descendant writes for one pass,
including the producer and shell. The regular-file fast path was already
present; pipes still took the line-by-line paging/drain path.

An initial large-copy trial correctly failed its byte oracle because the
external command emitted a filename header for the binary file operand.
Those timings are not used for a large-copy comparison. The corrected workload
redirects the identical fixture onto stdin for both commands. The failed trial
and corrected reports are preserved separately.

All final cases passed with seven samples after warmup on CPU 11. Median batch
times in milliseconds follow; regular/pipe copy batches contain 96 MiB of
validated output. Both compared columns use the same captured-output sink.

| Workload | Starting builtin | Final builtin | Final external |
|---|---:|---:|---:|
| Historical operands, 12 passes | 8.066 | 7.247 | 17.995 |
| 32 MiB regular stdin, 3 passes | 57.819 | 53.506 | 69.379 |
| 32 MiB pipe stdin, 3 passes | 430.480 | 83.864 | 117.701 |
| PTY paging, 3 invocations | 26.303 | 24.811 | not compared |

The pipe case improved 5.13× against the starting build. Its separate one-pass
profile fell from 131,201 to 640 descendant writes and from 8,328 to 648 reads;
the final path added 1,025 readiness polls so blocked reads/writes remain
interruptible. These totals include the shell and producer and use a pipe
capture sink for profiling. The untraced timing samples use regular-file
capture. Small regular-copy and PTY differences should be read with their raw
sample distributions; PTY timings include the controller and event checks.

The unchanged historical `/dev/null` driver recorded 3.304 ms versus
12.732 ms externally on the final build. That driver validates a separate
repeated batch, rather than capturing every timed pass. The table above and
task adapter supply the stricter per-sample byte/event evidence.

Final correctness: 40 native cases and the same 40 under ASan/UBSan passed,
including blocked output. The final fixture finds nine failures in the
starting build. Existing pager write-error and interrupt regressions, plus the
`top`/`tui` shared-decoder checks, also passed. Intermediate failed builds and
tests are retained with the raw evidence; no failures were skipped or marked
as expected passes.
