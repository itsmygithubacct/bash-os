# Loadable status and benchmark work queue

This is the **2026-09-12** review of the complete
[build catalog](../config/bash-loadables.list) at `63cb23d`, measured on one
binary in one run. Every loadable that can be measured now has a number:
**297 cases covering 248 of the 279 loadables**, seven samples each, pinned to
one CPU under a shared lock. The [CSV](loadables-status.csv) has one row per
loadable for filtering by profile, status, priority, counterpart, metric kind
and measurement; the
[current measurement summary](data/loadable-benchmarks-current.json) retains
fixture hashes, sample counts and timing ranges. The
[original snapshot](data/loadable-benchmarks.json) remains available for
historical comparison; its batch sizes and host conditions differ.

**A metric is one of two kinds.** 155 loadables are *compared* against an
external program or a BusyBox applet on the same fixture and carry a ratio. 93
are *self-timed*: nothing else implements the thing — the persistent-handle,
terminal, protocol and policy APIs — so pass 1 becomes its own expected output,
the repeated batch is a determinism check, and both reference columns print an
em dash. A self-timed figure says whether an implementation got faster than it
was, which is what it is for; it is never presented as a ratio. See
[reading the catalog](#reading-the-catalog).

**The remaining 31 loadables have no metric, and each says why** in its Next
work column rather than leaving an empty row. Some are inherent: `halt`,
`poweroff` and `reboot` are a few lines each whose only work is `reboot(2)`;
`keyctl` prints a kernel-assigned serial that is new in every process; `tui`
writes to a terminal the harness cannot give it. Others are waiting on one
specific thing, such as a fixture-root hook for the socket tables, which would
make `ss` and `netstat` measurable together.

**Repeated invocation is checked, not assumed.** A builtin runs in the shell
process, so its stdio state outlives the call. Six loadables — `more`, `less`,
`uuencode`, `xargs`, `obj` and `bsdgames` — read the persistent `stdin` stream
and left its EOF flag set, so a second `CMD < FILE` in the same shell read
nothing and still exited 0. That is silent data loss, and a pipeline-shaped
check cannot see it because a pipeline forks. All six are fixed on this binary;
[`tests/repeat-input-check.sh`](../tests/repeat-input-check.sh) is the gate, and
every case here validates a batch of at least three invocations before it is
timed.

Two comparisons were corrected on this binary as well. `coreutils nproc` now
counts the affinity mask, as GNU's does, instead of the online processor count;
and `col` terminates its output like util-linux, including for an input whose
last line has no newline, which is what let its large text fixture be measured.

Dedicated scope, regression and benchmark reports cover
[head and sed](head-sed.md), [fold](fold.md), [expand](expand.md), [bc](bc.md),
[nl](nl.md), [pr](pr.md), [tac](tac.md), [zstd](zstd.md) and
[hostid](hostid.md). The [PTY broker and live-pane changes](ptybroker.md) have
dedicated lifecycle and binary-I/O regression suites. A corrected invalid
baseline is not reported as a speedup — expect a slower number when a wrong
command becomes right. Raw run logs stay outside the repository.


<!-- BEGIN SUMMARY -->
Catalog: **280 loadables** (249 local sources, 31 stock Bash sources). Command benchmark: **297 cases covering 248 loadables**; 248 loadables passed the selected output checks, 0 have confirmed correctness findings. The other 32 have no individual command timings here; GPU transport measurements are reported separately.

Metric kinds: **155 compared** against an external program or a BusyBox applet, **93 self-timed** where no counterpart implements the command and the repeated batch is a determinism check instead, **32 with no metric**. A self-timed figure is comparable with another run of the same case, never presented as a ratio.

| Profile | Included loadables |
| --- | --- |
| shell | 0 |
| pure | 28 |
| core | 89 |
| device | 160 |
| server | 215 |
| desktop | 155 |
| full | 280 |

Command measurement source: `63cb23df1c3012dde4b07657cc27e4f1e5015b2f`. This refresh measured the full build at `63cb23d` on one binary: **297 cases covering 248 of 279 loadables**, seven samples each, pinned to one CPU under the shared benchmark lock. 0 loadables are self-timed, having no external program or BusyBox applet that implements them; for those the repeated batch is a determinism check and no ratio is shown. The 31 loadables still without a metric each carry a written blocker rather than an empty row. The measured binary also carries the repeated-input fix: more, less, uuencode, xargs, obj and bsdgames read the persistent stdin stream and left its EOF flag set, so a second in-process invocation read nothing and still exited 0; tests/repeat-input-check.sh is the gate. coreutils nproc now counts the affinity mask as GNU's does, and col terminates its output like util-linux, which is what let col's large text fixture be measured. tests/run.sh was not re-run in full for this refresh.

Historical [CI at 5fde494](https://github.com/itsmygithubacct/bash-os/actions/runs/34214029478) passed all nine jobs on the pre-integration tree. This measurement is `c591f19` after leftover ar/tee/diff follow-ups landed.

Historical baseline: `af3c8c488d6b4d81025a5feab4d04f8ee5e402f5`; [CI](https://github.com/itsmygithubacct/bash-os/actions/runs/34175141733) passed all nine jobs (including 48 native test groups). Those older suites did not detect the repeated-input findings. Coverage labels describe the mapped fixtures, not a guarantee that every option works.
<!-- END SUMMARY -->

## Recommended order

These priorities target general shell workloads. A device or application that
depends on a particular service can change the order. `P1` means a confirmed
correctness problem, `P2` a performance candidate confirmed in a second run,
`P3` a scope or evidence gap to investigate, and `P4` no priority from the
selected measurement. `P4` does not mean the implementation is complete.

Ratios are **BOS time divided by reference time**: `3.0×` means bash-os took
three times as long. A speed ratio is never published for incorrect output.

<!-- BEGIN PRIORITIES -->
| Priority | Loadable / case | Evidence | Next step |
| --- | --- | --- | --- |
| P3 | Unmeasured commands and APIs | No per-command timing is available; many only have small fixtures. | Choose by target profile and application use, establish equivalent outputs, then time. |
<!-- END PRIORITIES -->

## Reading the catalog

- Profiles: **P** pure, **C** core, **D** device, **S** server, **T** desktop,
  **F** full. The shell profile injects none. Desktop is an alternative to
  server, not its superset. The CSV uses full names and lists required companion
  loadables. See [build profiles](build-profiles.md) for exact inclusion lists.
- **Parity** means comparisons against a reference for selected fixtures;
  **Query parity** covers only selected read-only queries. **Contract** means
  assertions about a defined behavior. **Smoke** covers a small invocation;
  **Negative checks** only validates rejection paths. **Bench checked** is an
  output check in this new harness without another mapped command fixture.
  **Build/help** means no more specific behavioral evidence is mapped here.
- **S** links to an ASan/UBSan harness; **Fz** links to a bounded fuzz target.
  Coverage is limited to the exercised paths. Image fuzzing covers the shared
  decoder used by `tiv`, `kitty` and `sixel`, not every operation of those commands.
  **Limited** links to known scope differences below.
- Targets are comparison candidates, not claims of complete CLI compatibility.
  BusyBox availability is for the installed 1.37.0 build. `—` means no candidate
  in that build or no applicable reference. `missing` is an unavailable external
  program. An API fixture needs matching operations, state and outputs before
  a comparison makes sense.
- All timings are **milliseconds per batch**, in **BOS / BusyBox / external**
  order. The linked case gives arguments, input and invocation count. **N/M**
  means not measured, never zero. **INVALID** means output validation failed.
  Where a command has several cases, the main row shows a failing case first,
  otherwise the largest BOS/external ratio; the appendix includes every case.
- A metric is one of two kinds, and the difference decides what it can be used
  for. A **compared** metric validates the builtin's bytes against an external
  program or a BusyBox applet on the same fixture and reports a ratio; it
  answers "is this faster or slower than the userland it replaces". A
  **self-timed** metric applies where no counterpart implements the thing at
  all — the persistent-handle, terminal and protocol APIs — and reports the
  builtin's own batch time with an em dash in both reference columns. It
  answers only "did this get faster or slower than it was", which is enough to
  iterate on, and it is never presented as a ratio. In a self-timed case the
  repeated batch is a **determinism check**: identical passes must produce
  identical bytes, so a correctness regression still fails the case rather than
  quietly producing a better number.
- An em dash in a reference column therefore means one of two things, separated
  in the CSV: the tool is absent from this host, or no counterpart applies.
  Neither is a measurement and neither is a failure.
- `*` marks a stock source from Bash's `examples/loadables/`; other names link
  to local sources. See [provenance](PROVENANCE.md). Helpers, aliases and
  dispatcher subcommands are not additional catalog entries.

## All loadables

<!-- BEGIN CATALOG -->
| Loadable | Profiles | Status / evidence | Targets: BB; external | Batch ms: BOS / BB / external | Work | Next work |
| --- | --- | --- | --- | --- | --- | --- |
| [`acme`](../loadables/acme.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; certbot / acme.sh | 66.960 / — / —; [acme-jwk-thumbprint](#case-acme-jwk-thumbprint), 28 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`apropos`](../loadables/apropos.c) | T F | [Contract](../tests/misc-smoke.py) | —; apropos | 62.856 / — / 355.389; [apropos](#case-apropos), 41 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ar`](../loadables/ar.c) | C D S T F | [Bench checked](#case-ar) | ar; ar | 4.196 / 76.195 / 103.790; [ar](#case-ar), 100 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `asort`* | F | [Contract](../tests/misc-smoke.py) | —; gawk asort() | 176.690 / — / —; [asort-index-numeric](#case-asort-index-numeric), 3 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`at`](../loadables/at.c) | S F | [Contract](../tests/misc-smoke.py) | —; at (missing) | 66.285 / — / —; [at-list](#case-at-list), 32 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`audit`](../loadables/audit.c) | S F | [Contract](../tests/network-smoke.py) | —; auditctl / ausearch | 8.634 / — / —; [audit-decode-text](#case-audit-decode-text), 127 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`auth`](../loadables/auth.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | 61.420 / — / —; [auth-policy-parse](#case-auth-policy-parse), 11 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`awk`](../loadables/awk.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | awk; awk | 71.547 / 146.081 / 76.655; [awk](#case-awk), 13 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `basename`* | P C D S T F | [Contract](../tests/host-smoke.sh) | basename; basename | 3.641 / 85.311 / 72.291; [basename](#case-basename), 121 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashbase64`](../loadables/bashbase64.c) | D S F | [Bench checked](#case-bashbase64) | base64; base64 | 9.783 / 68.918 / 54.979; [bashbase64](#case-bashbase64), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashclock`](../loadables/bashclock.c) | D S F | [Bench checked](#case-bashclock-sleep) | —; Bash EPOCHREALTIME / Python time | 11.268 / 101.577 / 86.586; [bashclock-sleep](#case-bashclock-sleep), 126 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashdhcp`](../loadables/bashdhcp.c) | D S F | [Bench checked](#case-bashdhcp-parse-message) | udhcpc; dhclient / udhcpc | 5.662 / — / —; [bashdhcp-parse-message](#case-bashdhcp-parse-message), 126 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`bashinotify`](../loadables/bashinotify.c) | D S F | [Bench checked](#case-bashinotify-drain) | inotifyd (not in build); inotifywait (missing) | 11.727 / — / —; [bashinotify-drain](#case-bashinotify-drain), 123 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`bashio`](../loadables/bashio.c) | D S F | [Bench checked](#case-bashio-pread-hex) | —; Python os.pread/os.pwrite | 13.266 / 417.067 / 119.680; [bashio-pread-hex](#case-bashio-pread-hex), 80 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashjson`](../loadables/bashjson.c) | D S F | [Bench checked](#case-bashjson) | —; jq | 35.133 / — / 282.417; [bashjson](#case-bashjson), 67 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashkmod`](../loadables/bashkmod.c) | D S F | [Bench checked](#case-bashkmod-aliases) | modprobe; modprobe / insmod / rmmod | 54.468 / — / —; [bashkmod-aliases](#case-bashkmod-aliases), 50 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`bashlogger`](../loadables/bashlogger.c) | D S F | Build/help | logger; logger | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashmount`](../loadables/bashmount.c) | D S F | [Bench checked](#case-bashmount-findmnt) | mount; mount / umount / findmnt | 63.388 / — / 461.233; [bashmount-findmnt](#case-bashmount-findmnt), 42 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashpoll`](../loadables/bashpoll.c) | D S T F | [Bench checked](#case-bashpoll-wait) | —; Python selectors / socket | 6.634 / — / —; [bashpoll-wait](#case-bashpoll-wait), 130 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`bashsyslogd`](../loadables/bashsyslogd.c) | D S F | Build/help | syslogd; rsyslogd / syslogd | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashtermraw`](../loadables/bashtermraw.c) | D S F | [Bench checked](#case-bashtermraw-stty-g) | stty; stty | 7.277 / — / —; [bashtermraw-stty-g](#case-bashtermraw-stty-g), 122 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`batch`](../loadables/batch.c) | S F | [Contract](../tests/misc-smoke.py) | —; batch (missing) | 4.539 / — / —; [batch-queue](#case-batch-queue), 20 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`bc`](../loadables/bc.c) | S T F | [Parity](../tests/bc-parity.py); [limited](#scope-notes); [S](../tests/bc-sanitize.sh) | bc; bc | 5.573 / 70.617 / 70.232; [bc](#case-bc), 80 passes | P3 | Decide required option scope; see limitations. |
| [`bignum`](../loadables/bignum.c) | T F | [Contract](../tests/misc-smoke.py) | bc; Python int / bc | 4.854 / 105.697 / 88.863; [bignum-mul](#case-bignum-mul), 120 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`binhex`](../loadables/binhex.c) | D S F | [Bench checked](#case-binhex-decode) | xxd; xxd | 28.387 / 165.367 / 153.055; [binhex-decode](#case-binhex-decode), 78 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`blkid`](../loadables/blkid.c) | D S F | [Bench checked](#case-blkid-type) | blkid; blkid | 5.483 / INVALID / 115.923; [blkid-type](#case-blkid-type), 90 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`blockdev`](../loadables/blockdev.c) | D S F | Build/help | blockdev; blockdev | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bsdgames`](../loadables/bsdgames.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; bsdgames (missing) | 100.655 / 13.390 / 8.014; [bsdgames-rot13](#case-bsdgames-rot13), 3 passes; 2 cases total | P3 | Confirm bsdgames-rot13 (12.56× external time), then profile. |
| [`buf`](../loadables/buf.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 52.113 / 18.860 / 16.641; [buf-text](#case-buf-text), 19 passes; 2 cases total | P3 | Confirm buf-text (3.13× external time), then profile. |
| [`cal`](../loadables/cal.c) | T F | [Contract](../tests/misc-smoke.py) | cal; cal (missing) | 4.041 / 67.281 / —; [cal](#case-cal), 87 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`caps`](../loadables/caps.c) | S F | [Smoke](../tests/system-smoke.sh) | —; capsh / setpriv | 4.926 / — / —; [caps-probe](#case-caps-probe), 98 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| `cat`* | P C D S T F | [Contract](../tests/host-smoke.sh) | cat; cat | 7.979 / 58.076 / 57.517; [cat](#case-cat), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chattr`](../loadables/chattr.c) | D S F | [Bench checked](#case-chattr) | —; chattr | 72.971 / — / 136.683; [chattr](#case-chattr), 23 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chgrp`](../loadables/chgrp.c) | C D S T F | [Bench checked](#case-chgrp) | chgrp; chgrp | 6.706 / 96.560 / 96.715; [chgrp](#case-chgrp), 113 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `chmod`* | P C D S T F | [Bench checked](#case-chmod) | chmod; chmod | 4.131 / 94.122 / 72.522; [chmod](#case-chmod), 112 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chown`](../loadables/chown.c) | C D S T F | [Bench checked](#case-chown) | chown; chown | 6.185 / 116.742 / 100.327; [chown](#case-chown), 139 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chrt`](../loadables/chrt.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | —; chrt | 4.512 / — / 66.058; [chrt](#case-chrt), 102 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`cksum`](../loadables/cksum.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; cksum | 51.604 / — / 87.076; [cksum](#case-cksum), 47 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`claude`](../loadables/claude.c) | F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | 73.361 / — / 99.722; [claude-unescape](#case-claude-unescape), 11 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`clip`](../loadables/clip.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 50.945 / 70.097 / 34.676; [clip-text](#case-clip-text), 37 passes | P3 | Confirm clip-text (1.47× external time), then profile. |
| [`cluster`](../loadables/cluster.c) | F | [Smoke](../tests/misc-smoke.py) | —; API fixture | 19.949 / 33.839 / 37.845; [cluster-members](#case-cluster-members), 40 passes | P3 | Add peer membership, timeout and disconnect fixtures. |
| [`cmp`](../loadables/cmp.c) | C D S T F | [Bench checked](#case-cmp) | cmp; cmp | 34.083 / 175.192 / 44.558; [cmp](#case-cmp), 53 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`col`](../loadables/col.c) | C D S T F | [Bench checked](#case-col) | —; col | 63.252 / — / 123.393; [col](#case-col), 20 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`colrm`](../loadables/colrm.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; colrm | 71.451 / — / 132.323; [colrm](#case-colrm), 24 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`column`](../loadables/column.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; column | 91.162 / — / 370.905; [column](#case-column), 7 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`comm`](../loadables/comm.c) | C D S T F | [Bench checked](#case-comm) | —; comm | 47.510 / — / 94.195; [comm](#case-comm), 61 passes | P3 | Profile input/output and allocation costs on the comm fixture, then measure the proposed change. |
| [`coreutils`](../loadables/coreutils.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; Individual coreutils programs | 70.476 / 142.003 / 24.170; [coreutils-tac](#case-coreutils-tac), 30 passes; 8 cases total | P3 | Confirm coreutils-tac (2.92× external time), then profile. |
| [`cp`](../loadables/cp.c) | C D S T F | [Contract](../tests/host-smoke.sh) | cp; cp | 14.260 / 76.472 / 90.361; [cp](#case-cp), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`cred`](../loadables/cred.c) | S F | [Smoke](../tests/system-smoke.sh) | —; API fixture | 4.779 / — / —; [cred-status](#case-cred-status), 140 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`cron`](../loadables/cron.c) | S F | [Contract](../tests/large-smoke.py) | crond; cron / crond | 85.678 / — / —; [cron-next](#case-cron-next), 7 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`crontab`](../loadables/crontab.c) | S F | [Contract](../tests/misc-smoke.py) | crontab; crontab | 29.185 / — / —; [crontab-install](#case-crontab-install), 67 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`crypto`](../loadables/crypto.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | sha256sum; sha256sum / openssl | 74.628 / 69.599 / 49.871; [crypto](#case-crypto), 11 passes | P3 | Confirm crypto (1.50× external time), then profile. |
| [`csplit`](../loadables/csplit.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; csplit | 38.202 / — / 49.438; [csplit](#case-csplit), 40 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`curl`](../loadables/curl.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; curl | 75.538 / — / 237.534; [curl-loopback-body](#case-curl-loopback-body), 23 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`cut`](../loadables/cut.c) | P C D S T F | [Parity](../tests/cut-parity.sh) | cut; cut | 31.713 / 351.001 / 171.164; [cut](#case-cut), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`date`](../loadables/date.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | date; date | 3.498 / 62.097 / 55.546; [date-year](#case-date-year), 84 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dd`](../loadables/dd.c) | C D S T F | [Bench checked](#case-dd) | dd; dd | 6.519 / 67.475 / 59.376; [dd](#case-dd), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`df`](../loadables/df.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | df; df | 13.644 / 85.095 / 76.287; [df](#case-df), 105 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dhcp6`](../loadables/dhcp6.c) | S F | [Contract](../tests/network-smoke.py) | udhcpc6; dhclient -6 | 5.132 / — / —; [dhcp6-parse](#case-dhcp6-parse), 140 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`dhcpd`](../loadables/dhcpd.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | udhcpd; dnsmasq / dhcpd | 23.475 / — / —; [dhcpd-respond](#case-dhcpd-respond), 92 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`dhcpd6`](../loadables/dhcpd6.c) | S F | [Contract](../tests/network-smoke.py) | —; kea-dhcp6 (missing) | 20.798 / — / —; [dhcpd6-respond](#case-dhcpd6-respond), 110 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`dialog`](../loadables/dialog.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; dialog (missing) | 101.396 / — / —; [dialog](#case-dialog), 4 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`diff`](../loadables/diff.c) | C D S T F | [Bench checked](#case-diff) | diff; diff | 53.559 / 45.836 / 30.127; [diff](#case-diff), 24 passes | P3 | Confirm diff (1.78× external time), then profile. |
| `dirname`* | P C D S T F | [Bench checked](#case-dirname) | dirname; dirname | 4.278 / 89.054 / 80.979; [dirname](#case-dirname), 118 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dmesg`](../loadables/dmesg.c) | D S F | [Bench checked](#case-dmesg-kmsgfixture) | dmesg; dmesg | 67.456 / — / —; [dmesg-kmsgfixture](#case-dmesg-kmsgfixture), 21 passes; self-timed | P3 | Carry the partial record across reads instead of dropping it. |
| [`dmsetup`](../loadables/dmsetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; dmsetup | N/M | P3 | Define required mapper mutation verbs and add isolated device fixtures. |
| [`dns`](../loadables/dns.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | nslookup; dig / drill | 202.979 / — / —; [dns-checkzone](#case-dns-checkzone), 3 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`doas`](../loadables/doas.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; doas (missing) | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`du`](../loadables/du.c) | C D S T F | [Bench checked](#case-du-tree) | du; du | 21.473 / INVALID / 78.546; [du-tree](#case-du-tree), 80 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ed`](../loadables/ed.c) | C D S T F | [Bench checked](#case-ed) | ed; ed (missing) | 50.030 / 94.375 / —; [ed](#case-ed), 54 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`env`](../loadables/env.c) | C D S T F | [Contract](../tests/regressions.py) | env; env | 41.177 / 82.037 / 66.746; [env](#case-env), 72 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`escdelay`](../loadables/escdelay.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 4.538 / — / —; [escdelay](#case-escdelay), 117 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`expand`](../loadables/expand.c) | C D S T F | [Parity](../tests/expand-parity.py); [limited](#scope-notes); [S](../tests/expand-sanitize.sh) | expand; expand | 62.889 / 318.800 / 85.473; [expand](#case-expand), 38 passes | P3 | Decide required option scope; see limitations. |
| [`expect`](../loadables/expect.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; expect (missing) | 144.904 / — / —; [expect](#case-expect), 3 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`expr`](../loadables/expr.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | expr; expr | 3.517 / 74.861 / 66.925; [expr](#case-expr), 99 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`fail2ban`](../loadables/fail2ban.c) | S F | [Contract](../tests/network-smoke.py) | —; fail2ban-client (missing) | 67.854 / — / —; [fail2ban-format-status](#case-fail2ban-format-status), 22 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| `fdflags`* | D S F | [Bench checked](#case-fdflags-scan) | —; Python fcntl | 175.166 / — / —; [fdflags-scan](#case-fdflags-scan), 3 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`fdisk`](../loadables/fdisk.c) | D S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | fdisk; fdisk | 22.054 / — / —; [fdisk-list](#case-fdisk-list), 99 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`fifo`](../loadables/fifo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`file`](../loadables/file.c) | T F | [Contract](../tests/misc-smoke.py) | —; file | 4.226 / — / 930.774; [file](#case-file), 103 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`fincore`](../loadables/fincore.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; fincore | 6.363 / — / 95.140; [fincore](#case-fincore), 131 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`find`](../loadables/find.c) | C D S T F | [Contract](../tests/regressions.py) | find; find | 23.972 / 91.591 / 84.618; [find](#case-find), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `finfo`* | D S F | [Bench checked](#case-finfo-mode) | stat; stat | 4.192 / 78.260 / 86.951; [finfo-mode](#case-finfo-mode), 106 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`flock`](../loadables/flock.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | —; flock | 41.694 / — / 76.570; [flock](#case-flock), 77 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `fltexpr`* | D S F | [Bench checked](#case-fltexpr) | awk; awk / bc | 4.054 / 98.425 / 179.773; [fltexpr](#case-fltexpr), 129 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`fold`](../loadables/fold.c) | C D S T F | [Parity](../tests/fold-parity.py); [limited](#scope-notes); [S](../tests/fold-sanitize.sh) | fold; fold | 40.912 / 152.660 / 94.866; [fold](#case-fold), 36 passes | P3 | Decide required option scope; see limitations. |
| [`free`](../loadables/free.c) | C D S T F | [Bench checked](#case-free-procfixture) | free; free | 4.362 / — / —; [free-procfixture](#case-free-procfixture), 141 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`fsck`](../loadables/fsck.c) | D S F | [Contract](../tests/misc-smoke.py) | —; fsck | 4.728 / — / —; [fsck](#case-fsck), 135 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`fsfreeze`](../loadables/fsfreeze.c) | D S F | Build/help | fsfreeze; fsfreeze | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fstrim`](../loadables/fstrim.c) | D S F | [Bench checked](#case-fstrim) | fstrim; fstrim | 60.860 / — / —; [fstrim](#case-fstrim), 6 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`fw`](../loadables/fw.c) | S F | [Contract](../tests/large-smoke.py) | —; nft / iptables | 85.912 / — / —; [fw-batch-dryrun](#case-fw-batch-dryrun), 11 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`genl`](../loadables/genl.c) | D S F | [Bench checked](#case-genl-ctrl-list) | —; API fixture | 34.018 / — / —; [genl-ctrl-list](#case-genl-ctrl-list), 80 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| `getconf`* | D S F | [Bench checked](#case-getconf) | —; getconf | 4.359 / — / 78.629; [getconf](#case-getconf), 132 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`getfacl`](../loadables/getfacl.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; getfacl (missing) | 54.144 / — / —; [getfacl](#case-getfacl), 54 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`git`](../loadables/git.c) | S F | [Parity](../tests/git-parity.py); [S](../tests/git-sanitize.sh); [Fz](../tests/fuzz-pack.c) | —; git | N/M | P3 | Add a matched workload and timing. |
| [`gpu`](../loadables/gpu.c) | T F | [Contract](../tests/gpu-smoke.py); [S](../tests/gpu-sanitize.sh) | —; API fixture | 58.201 / — / —; [gpu](#case-gpu), 30 passes; self-timed | P3 | Measure application frame latency and driver behavior on the intended device. |
| [`grep`](../loadables/grep.c) | C D S T F | [Parity](../tests/grep-parity.sh); [limited](#scope-notes); [S](../tests/grep-host.c) | grep; grep | 55.156 / 400.840 / 48.656; [grep-lines](#case-grep-lines), 57 passes; 2 cases total | P3 | Decide required option scope; see limitations. |
| [`halt`](../loadables/halt.c) | D S F | Build/help | halt; halt | N/M | P3 | Add behavioral fixtures, then timing. |
| `head`* | P C D S T F | [Parity](../tests/head-sed-parity.py); [limited](#scope-notes); [S](../tests/head-sed-sanitize.sh) | head; head | 8.272 / 58.363 / 49.007; [head](#case-head), 78 passes | P3 | Decide required option scope; see limitations. |
| [`hexdump`](../loadables/hexdump.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | hexdump; hexdump | 73.849 / 90.759 / 132.514; [hexdump](#case-hexdump), 11 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`hl`](../loadables/hl.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; highlight (missing) | 90.435 / — / —; [hl](#case-hl), 3 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`hostid`](../loadables/hostid.c) | D S F | [Bench checked](#case-hostid) | hostid; hostid | 6.459 / 125.787 / 102.292; [hostid](#case-hostid), 149 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`hostname`](../loadables/hostname.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | hostname; hostname | 3.781 / 81.150 / 65.586; [hostname-s](#case-hostname-s), 105 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`http`](../loadables/http.c) | D S F | [Contract](../tests/network-smoke.py) | wget; curl | 13.083 / — / —; [http-response-body](#case-http-response-body), 67 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`httpd`](../loadables/httpd.c) | S F | [Contract](../tests/httpd-host.c); [S](../tests/run.sh) | httpd; HTTP server fixture | 21.646 / — / —; [httpd-part](#case-httpd-part), 72 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`hwclock`](../loadables/hwclock.c) | D S F | Build/help | hwclock; hwclock | N/M | P3 | Add behavioral fixtures, then timing. |
| `id`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | id; id | 5.229 / 89.174 / 90.460; [id-user](#case-id-user), 108 passes; 3 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`index`](../loadables/index.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git update-index | 78.713 / — / 40.886; [index-read](#case-index-read), 5 passes | P3 | Confirm index-read (1.93× external time), then profile. |
| [`integrity`](../loadables/integrity.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | 87.463 / — / —; [integrity-manifest](#case-integrity-manifest), 8 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`ionice`](../loadables/ionice.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | ionice; ionice | 4.929 / 97.557 / 78.169; [ionice](#case-ionice), 129 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ip`](../loadables/ip.c) | D S F | [Bench checked](#case-ip) | ip; ip | 7.474 / ERROR / 167.878; [ip](#case-ip), 129 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ipcctl`](../loadables/ipcctl.c) | D S F | Build/help | ipcs (not in build); ipcs / ipcrm | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ipcmk`](../loadables/ipcmk.c) | D S F | Build/help | —; ipcmk | N/M | P3 | Add behavioral fixtures, then timing. |
| [`join`](../loadables/join.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; join | 72.419 / — / 47.218; [join](#case-join), 18 passes | P3 | Confirm join (1.53× external time), then profile. |
| [`jq`](../loadables/jq.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; jq | 76.858 / — / 110.380; [jq](#case-jq), 12 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`keyctl`](../loadables/keyctl.c) | S F | Build/help | —; keyctl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`kgetch`](../loadables/kgetch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 4.173 / — / —; [kgetch](#case-kgetch), 127 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`killall`](../loadables/killall.c) | C D S T F | Build/help | killall; killall (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`killall5`](../loadables/killall5.c) | F | [Bench checked](#case-killall5-dryrun) | —; killall5 | 75.938 / — / —; [killall5-dryrun](#case-killall5-dryrun), 24 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`kitty`](../loadables/kitty.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; kitten icat | 57.415 / — / —; [kitty](#case-kitty), 37 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`ldap`](../loadables/ldap.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-ldap.c) | —; ldapsearch (missing) | 12.463 / — / —; [ldap-filter-test](#case-ldap-filter-test), 99 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`less`](../loadables/less.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | less; less | 65.529 / 21.682 / 128.587; [less](#case-less), 29 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`link`](../loadables/link.c) | C D S T F | [Bench checked](#case-link) | link; link | 4.270 / 88.007 / 72.466; [link](#case-link), 116 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `ln`* | P C D S T F | [Bench checked](#case-ln) | ln; ln | 4.655 / 88.537 / 82.347; [ln](#case-ln), 121 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`locale`](../loadables/locale.c) | T F | [Contract](../tests/misc-smoke.py) | —; locale / Python locale | 5.965 / — / —; [locale-current](#case-locale-current), 133 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`login`](../loadables/login.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | login; login | 31.149 / 328.381 / 213.816; [login-lookup](#case-login-lookup), 81 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `logname`* | P C D S T F | [Bench checked](#case-logname) | logname; logname | 5.657 / 109.838 / 93.747; [logname](#case-logname), 138 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`losetup`](../loadables/losetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | losetup; losetup | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lpr`](../loadables/lpr.c) | F | [Smoke](../tests/misc-smoke.py); [limited](#scope-notes) | lpr (not in build); lpr (missing) | 52.958 / 156.186 / 87.841; [lpr-list](#case-lpr-list), 25 passes | P3 | Decide whether real print delivery belongs in this loadable. |
| [`ls`](../loadables/ls.c) | C D S T F | [Bench checked](#case-ls) | ls; ls | 16.738 / 91.091 / 80.018; [ls](#case-ls), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`lsattr`](../loadables/lsattr.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; lsattr | 41.320 / — / —; [lsattr](#case-lsattr), 73 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`lsblk`](../loadables/lsblk.c) | D S F | [Bench checked](#case-lsblk) | —; lsblk | 44.954 / — / 99.149; [lsblk](#case-lsblk), 61 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`lsof`](../loadables/lsof.c) | D S T F | [Smoke](../tests/system-smoke.sh) | —; lsof | 80.041 / — / —; [lsof-walk](#case-lsof-walk), 14 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`mail`](../loadables/mail.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | sendmail (not in build); sendmail / mailq | 74.488 / — / —; [mail-newaliases](#case-mail-newaliases), 32 passes; self-timed | P3 | Add a controlled submission/delivery benchmark. |
| [`man`](../loadables/man.c) | T F | [Contract](../tests/misc-smoke.py) | —; man | 4.080 / — / 1280.398; [man](#case-man), 93 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `mkdir`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | mkdir; mkdir | 5.097 / 125.204 / 138.417; [mkdir](#case-mkdir), 144 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `mkfifo`* | P C D S T F | [Bench checked](#case-mkfifo) | mkfifo; mkfifo | 5.558 / 100.869 / 102.612; [mkfifo](#case-mkfifo), 133 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`mkfs`](../loadables/mkfs.c) | D S F | [Contract](../tests/misc-smoke.py) | —; mkfs | N/M | P3 | Add a matched workload and timing. |
| [`mkswap`](../loadables/mkswap.c) | D S F | [Bench checked](#case-mkswap) | mkswap; mkswap | 8.386 / ERROR / 226.295; [mkswap](#case-mkswap), 136 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `mktemp`* | P C D S T F | [Bench checked](#case-mktemp) | mktemp; mktemp | 10.779 / 127.203 / 104.423; [mktemp](#case-mktemp), 115 passes | P3 | Apply -u before sh_mktmpfd so the template is only expanded. |
| [`mlock`](../loadables/mlock.c) | D S F | [Smoke](../tests/system-smoke.sh) | —; API fixture | 25.498 / — / —; [mlock-trylock](#case-mlock-trylock), 95 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`more`](../loadables/more.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | more; more | 44.587 / — / 13.423; [more](#case-more), 12 passes | P3 | Confirm more (3.32× external time), then profile. |
| [`mouse`](../loadables/mouse.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 4.716 / — / —; [mouse](#case-mouse), 141 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`mv`](../loadables/mv.c) | C D S T F | [Bench checked](#case-mv) | mv; mv | 23.831 / 93.961 / 107.932; [mv](#case-mv), 93 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`nano`](../loadables/nano.c) | T F | [Contract](../tests/final-smoke.py); [limited](#scope-notes); [S](../tests/final-sanitize.sh) | —; nano | 58.070 / — / —; [nano](#case-nano), 12 passes; self-timed | P3 | Decide required option scope; see limitations. |
| [`nano2`](../loadables/nano2.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; nano | 32.194 / — / —; [nano2](#case-nano2), 22 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`nc`](../loadables/nc.c) | D S F | [Contract](../tests/network-smoke.py) | nc; nc | 76.105 / 93.394 / 90.063; [nc-loopback-stream](#case-nc-loopback-stream), 24 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ncdu`](../loadables/ncdu.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; ncdu | 24.306 / ERROR / 84.469; [ncdu-print](#case-ncdu-print), 92 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`netids`](../loadables/netids.c) | S F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; suricata (missing) | 34.975 / — / —; [netids-compile](#case-netids-compile), 67 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`netstat`](../loadables/netstat.c) | D S F | Build/help | netstat; netstat (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`nice`](../loadables/nice.c) | C D S T F | [Contract](../tests/regressions.py) | —; nice | 27.693 / — / 43.905; [nice](#case-nice), 52 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`nl`](../loadables/nl.c) | C D S T F | [Parity](../tests/nl-parity.py); [limited](#scope-notes); [S](../tests/nl-sanitize.sh) | nl; nl | 44.415 / 208.982 / 116.079; [nl](#case-nl), 48 passes | P3 | Decide required option scope; see limitations. |
| [`nohup`](../loadables/nohup.c) | C D S T F | [Contract](../tests/regressions.py) | —; nohup | 35.808 / — / 57.743; [nohup](#case-nohup), 66 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`notify`](../loadables/notify.c) | T F | [Contract](../tests/misc-smoke.py) | —; systemd-notify | 5.690 / — / —; [notify](#case-notify), 112 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`ns`](../loadables/ns.c) | S F | [Smoke](../tests/system-smoke.sh) | unshare; unshare / nsenter | 36.275 / 69.345 / 54.335; [ns-spawn-user](#case-ns-spawn-user), 66 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ntp`](../loadables/ntp.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | ntpd (not in build); chronyc / ntpd | 4.275 / — / —; [ntp-nts-selftest](#case-ntp-nts-selftest), 111 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`obj`](../loadables/obj.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git hash-object / cat-file | 93.039 / — / 113.102; [obj-batch-check](#case-obj-batch-check), 3 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`od`](../loadables/od.c) | C D S T F | [Bench checked](#case-od) | od; od | 76.907 / 63.034 / 139.173; [od](#case-od), 13 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`opt`](../loadables/opt.c) | T F | [Contract](../tests/misc-smoke.py) | getopt; getopt | 4.021 / 91.234 / 73.572; [opt](#case-opt), 125 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`pack`](../loadables/pack.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git pack-objects / index-pack | 85.684 / — / 85.170; [pack-cat](#case-pack-cat), 7 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`passwd`](../loadables/passwd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | passwd; passwd | 71.498 / 346.203 / 112.850; [passwd-list](#case-passwd-list), 26 passes; 2 cases total | P3 | Split passwd records on a fixed field count rather than strtok_r. |
| [`paste`](../loadables/paste.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | paste; paste | 68.804 / 367.963 / 68.106; [paste](#case-paste), 9 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `pathchk`* | P C D S T F | [Bench checked](#case-pathchk) | —; pathchk | 3.741 / — / 91.079; [pathchk](#case-pathchk), 158 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`pax`](../loadables/pax.c) | C D S T F | [Contract](../tests/host-smoke.sh) | —; pax (missing) | 4.052 / 60.076 / 87.453; [pax](#case-pax), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`payload`](../loadables/payload.c) | F | [Smoke](../tests/misc-smoke.py); [limited](#scope-notes) | —; API fixture | 139.990 / — / —; [payload-list](#case-payload-list), 3 passes; self-timed | P3 | Add an installer-boundary fixture and document the external helper. |
| [`pcap`](../loadables/pcap.c) | D S F | [Contract](../tests/network-smoke.py) | —; tcpdump (missing) | 82.602 / — / —; [pcap-info](#case-pcap-info), 4 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`pcre`](../loadables/pcre.c) | S F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; pcre2grep / grep -P | 66.335 / ERROR / 15.711; [pcre](#case-pcre), 14 passes | P3 | Confirm pcre (4.22× external time), then profile. |
| [`pgrep`](../loadables/pgrep.c) | C D S T F | [Bench checked](#case-pgrep-kthreadd); [limited](#scope-notes) | —; pgrep | 55.789 / — / 536.619; [pgrep-kthreadd](#case-pgrep-kthreadd), 34 passes | P3 | Decide required option scope; see limitations. |
| [`pidof`](../loadables/pidof.c) | C D S T F | [Bench checked](#case-pidof-kthreadd) | pidof; pidof | 70.167 / 145.782 / 188.382; [pidof-kthreadd](#case-pidof-kthreadd), 26 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ping`](../loadables/ping.c) | D S F | Build/help | ping; ping | N/M | P3 | Add behavioral fixtures, then timing. |
| [`pkg`](../loadables/pkg.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | 71.074 / — / —; [pkg-search](#case-pkg-search), 10 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`pkill`](../loadables/pkill.c) | C D S T F | Build/help; [limited](#scope-notes) | —; pkill | N/M | P3 | Decide required option scope; see limitations. |
| [`pkt`](../loadables/pkt.c) | D S F | [Contract](../tests/network-smoke.py) | —; scapy (missing) | 73.685 / — / —; [pkt-refs](#case-pkt-refs), 10 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`poweroff`](../loadables/poweroff.c) | D S F | Build/help | poweroff; poweroff | N/M | P3 | Add behavioral fixtures, then timing. |
| [`pr`](../loadables/pr.c) | C D S T F | [Parity](../tests/pr-parity.py); [limited](#scope-notes); [S](../tests/pr-sanitize.sh) | —; pr | 24.161 / — / 367.248; [pr](#case-pr), 77 passes | P3 | Decide required option scope; see limitations. |
| `printenv`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | —; printenv | 3.833 / — / 88.990; [printenv-lcall](#case-printenv-lcall), 149 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`prlimit`](../loadables/prlimit.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; prlimit | 3.905 / — / 81.730; [prlimit-cpu](#case-prlimit-cpu), 120 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`procstat`](../loadables/procstat.c) | D S T F | [Contract](../tests/procstat-smoke.py); [S](../tests/procstat-sanitize.sh) | —; iostat / mpstat / sar / pidstat / pmap / pldd | 69.377 / — / —; [procstat-pidstat](#case-procstat-pidstat), 21 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`ps`](../loadables/ps.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | ps; ps | 77.492 / — / —; [ps-procfixture](#case-ps-procfixture), 10 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`pty`](../loadables/pty.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; Python pty | 35.534 / — / —; [pty-spawn](#case-pty-spawn), 55 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`ptybroker`](../loadables/ptybroker.c) | T F | Build/help | —; ptybroker (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`readlink`](../loadables/readlink.c) | C D S T F | [Bench checked](#case-readlink) | readlink; readlink | 4.081 / 86.580 / 67.526; [readlink](#case-readlink), 114 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `realpath`* | P C D S T F | [Bench checked](#case-realpath) | realpath; realpath | 4.497 / 105.446 / 86.555; [realpath](#case-realpath), 139 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`reboot`](../loadables/reboot.c) | D S F | Build/help | reboot; reboot | N/M | P3 | Add behavioral fixtures, then timing. |
| [`renice`](../loadables/renice.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | renice; renice | N/M | P3 | Add behavioral fixtures, then timing. |
| [`rev`](../loadables/rev.c) | C D S T F | [Bench checked](#case-rev) | rev; rev | 75.272 / 40.518 / 142.930; [rev](#case-rev), 16 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `rm`* | P C D S T F | [Bench checked](#case-rm) | rm; rm | 4.760 / 96.093 / 84.547; [rm](#case-rm), 146 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `rmdir`* | P C D S T F | [Bench checked](#case-rmdir) | rmdir; rmdir | 5.591 / 108.131 / 90.280; [rmdir](#case-rmdir), 113 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`rngseed`](../loadables/rngseed.c) | D S F | [Contract](../tests/rngseed-host.c); [S](../tests/run.sh) | seedrng (not in build); systemd-random-seed (missing) | N/M | P3 | Add a matched workload and timing. |
| [`rsync`](../loadables/rsync.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; rsync | 83.694 / — / 510.283; [rsync-rsh-shim](#case-rsync-rsh-shim), 11 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`rtspcat`](../loadables/rtspcat.c) | F | Build/help | —; ffmpeg / openRTSP | N/M | P3 | Add a controlled RTSP/RTP stream with loss, reordering and framing checks. |
| [`scm`](../loadables/scm.c) | F | [Contract](../tests/misc-smoke.py) | —; Python socket SCM_RIGHTS | 7.274 / — / —; [scm-recv-fd](#case-scm-recv-fd), 140 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`scp`](../loadables/scp.c) | S F | [Contract](../tests/network-smoke.py) | —; scp | 79.594 / — / —; [scp-openssh-get](#case-scp-openssh-get), 11 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`screen`](../loadables/screen.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; screen (missing) | 48.750 / — / —; [screen](#case-screen), 35 passes; self-timed | P3 | Measure live PTY relay, backpressure and cleanup. |
| [`script`](../loadables/script.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; script | 15.221 / — / 96.830; [script](#case-script), 121 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`scrub`](../loadables/scrub.c) | F | [Contract](../tests/misc-smoke.py) | —; API fixture | 70.278 / — / —; [scrub](#case-scrub), 14 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`sed`](../loadables/sed.c) | C D S T F | [Parity](../tests/head-sed-parity.py); [limited](#scope-notes); [S](../tests/head-sed-sanitize.sh) | sed; sed | 60.450 / 72.189 / 50.711; [sed](#case-sed), 8 passes | P3 | Decide required option scope; see limitations. |
| [`seq`](../loadables/seq.c) | P C D S T F | [Parity](../tests/seq-parity.sh) | seq; seq | 58.058 / 1453.282 / 58.236; [seq](#case-seq), 42 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`setfacl`](../loadables/setfacl.c) | D S F | [Bench checked](#case-setfacl) | —; setfacl (missing) | 16.312 / — / —; [setfacl](#case-setfacl), 106 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| `setpgid`* | D S F | Build/help | —; Python os.setpgid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`setsid`](../loadables/setsid.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | setsid; setsid | 41.821 / 78.786 / 66.349; [setsid](#case-setsid), 76 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sftp`](../loadables/sftp.c) | S F | [Contract](../tests/network-smoke.py) | —; sftp | 71.368 / — / —; [sftp-openssh-get](#case-sftp-openssh-get), 10 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`signal`](../loadables/signal.c) | D S F | [Contract](../tests/system-smoke.sh) | kill; kill -l / Bash kill | 4.125 / 93.663 / 75.454; [signal](#case-signal), 123 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sixel`](../loadables/sixel.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; img2sixel (missing) | 66.926 / — / —; [sixel](#case-sixel), 17 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`slabtop`](../loadables/slabtop.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; slabtop | 45.530 / — / —; [slabtop-procfixture](#case-slabtop-procfixture), 43 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| `sleep`* | P C D S T F | [Bench checked](#case-sleep) | sleep; sleep | 7.296 / 57.680 / 50.605; [sleep](#case-sleep), 73 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sort`](../loadables/sort.c) | C D S T F | [Parity](../tests/sort-parity.sh) | sort; sort | 65.850 / 159.089 / 72.353; [sort-text](#case-sort-text), 24 passes; 2 cases total | P3 | Profile input/output and allocation costs on the sort-text fixture, then measure the proposed change. |
| [`split`](../loadables/split.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; split | 39.089 / — / 79.789; [split](#case-split), 75 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sqlite`](../loadables/sqlite.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; sqlite3 / Python sqlite3 | 71.464 / — / —; [sqlite-step-aggregate](#case-sqlite-step-aggregate), 8 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`ss`](../loadables/ss.c) | D S F | Build/help | —; ss | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ssh`](../loadables/ssh.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; ssh | 85.527 / — / 157.368; [ssh-known-hosts-list](#case-ssh-known-hosts-list), 3 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sshd`](../loadables/sshd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sshd | 48.869 / — / —; [sshd-sessions](#case-sshd-sessions), 22 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`stat`](../loadables/stat.c) | P C D S T F | [Parity](../tests/stat-parity.sh) | stat; stat | 3.734 / 84.927 / 88.969; [stat](#case-stat), 111 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`strace`](../loadables/strace.c) | F | [Contract](../tests/large-smoke.py) | —; strace (missing) | 21.439 / — / —; [strace-summary](#case-strace-summary), 20 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| `strftime`* | P C D S T F | [Bench checked](#case-strftime) | date; date / Bash printf | 3.884 / 95.763 / 77.586; [strftime](#case-strftime), 127 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`strings`](../loadables/strings.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | strings; strings | 31.086 / 89.794 / 135.007; [strings](#case-strings), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `strptime`* | P C D S T F | [Bench checked](#case-strptime) | —; Python datetime.strptime | 6.371 / 100.038 / 81.646; [strptime](#case-strptime), 99 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`su`](../loadables/su.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | su; su | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sudo`](../loadables/sudo.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sudo | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sv`](../loadables/sv.c) | S F | [Contract](../tests/large-smoke.py) | —; runit sv | 70.040 / 170.369 / 20.870; [sv-log](#case-sv-log), 29 passes | P3 | Confirm sv-log (3.36× external time), then profile. |
| [`swapoff`](../loadables/swapoff.c) | D S F | Build/help | swapoff; swapoff | N/M | P3 | Add behavioral fixtures, then timing. |
| [`swapon`](../loadables/swapon.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | swapon; swapon | 4.965 / ERROR / 158.530; [swapon](#case-swapon), 133 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `sync`* | P C D S T F | [Bench checked](#case-sync) | sync; sync | 6.060 / 26.317 / 19.704; [sync](#case-sync), 20 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sysctl`](../loadables/sysctl.c) | D S F | [Contract](../tests/system-smoke.sh) | sysctl; sysctl | 5.243 / 104.840 / 82.706; [sysctl](#case-sysctl), 132 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tac`](../loadables/tac.c) | C D S T F | [Parity](../tests/tac-parity.py); [limited](#scope-notes); [S](../tests/tac-sanitize.sh) | tac; tac | 12.658 / 297.716 / 62.572; [tac](#case-tac), 63 passes | P3 | Decide bounded-memory input and GNU regex scope; see the tac follow-up. |
| [`tail`](../loadables/tail.c) | C D S T F | [Parity](../tests/wc-tail-parity.sh) | tail; tail | 5.086 / 130.316 / 48.358; [tail](#case-tail), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`taskset`](../loadables/taskset.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | taskset; taskset | 3.885 / 81.463 / 68.646; [taskset](#case-taskset), 112 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `tee`* | P C D S T F | [Bench checked](#case-tee) | tee; tee | 9.377 / 109.351 / 71.588; [tee](#case-tee), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`termpixel`](../loadables/termpixel.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 14.138 / — / —; [termpixel](#case-termpixel), 40 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`termpixel_pong`](../loadables/termpixel_pong.c) | F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 9.831 / — / —; [termpixel_pong](#case-termpixel_pong), 128 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`timeout`](../loadables/timeout.c) | C D S T F | [Contract](../tests/system-smoke.sh) | timeout; timeout | 42.515 / 96.238 / 77.952; [timeout](#case-timeout), 71 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tinfo`](../loadables/tinfo.c) | T F | [Bench checked](#case-tinfo) | —; infocmp / tput | 4.743 / — / 115.249; [tinfo](#case-tinfo), 149 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tiv`](../loadables/tiv.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; chafa (missing) | 64.860 / — / —; [tiv](#case-tiv), 22 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`toml`](../loadables/toml.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh); [Fz](../tests/fuzz-toml.c) | —; Python tomllib | 75.296 / — / —; [toml-emit](#case-toml-emit), 8 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`top`](../loadables/top.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | top; top | N/M | P3 | Add a matched workload and timing. |
| [`totp`](../loadables/totp.c) | F | [Contract](../tests/misc-smoke.py) | —; oathtool (missing) | 69.106 / — / —; [totp-generate](#case-totp-generate), 28 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`touch`](../loadables/touch.c) | C D S T F | [Bench checked](#case-touch) | touch; touch | 3.790 / 106.752 / 85.989; [touch](#case-touch), 141 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tput`](../loadables/tput.c) | T F | [Bench checked](#case-tput) | —; tput | 3.828 / — / 72.676; [tput](#case-tput), 87 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tr`](../loadables/tr.c) | C D S T F | [Bench checked](#case-tr) | tr; tr | 51.589 / 96.332 / 56.872; [tr](#case-tr), 65 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`truncate`](../loadables/truncate.c) | C D S T F | [Bench checked](#case-truncate) | truncate; truncate | 4.111 / 79.522 / 70.703; [truncate](#case-truncate), 113 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ts`](../loadables/ts.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; tree-sitter (missing) | 92.345 / — / —; [ts-parse](#case-ts-parse), 5 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| `tty`* | P C D S T F | [Bench checked](#case-tty) | tty; tty | 7.886 / 108.412 / 89.124; [tty](#case-tty), 104 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tui`](../loadables/tui.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`tz`](../loadables/tz.c) | T F | [Contract](../tests/misc-smoke.py) | date; date / Python zoneinfo | 3.934 / 97.291 / 76.610; [tz](#case-tz), 127 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`uclampset`](../loadables/uclampset.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; uclampset | 4.706 / — / 83.286; [uclampset](#case-uclampset), 136 passes | P3 | Decide whether to implement the missing setter surface. |
| `uname`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | uname; uname | 4.157 / 84.628 / 71.632; [uname-s](#case-uname-s), 120 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`undo`](../loadables/undo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 93.490 / — / —; [undo-composite-group](#case-undo-composite-group), 4 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`unexpand`](../loadables/unexpand.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | unexpand; unexpand | 77.234 / 98.328 / 38.787; [unexpand](#case-unexpand), 9 passes | P3 | Confirm unexpand (1.99× external time), then profile. |
| [`uniq`](../loadables/uniq.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | uniq; uniq | 75.157 / 430.537 / 88.138; [uniq](#case-uniq), 19 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `unlink`* | P C D S T F | [Bench checked](#case-unlink) | unlink; unlink | 6.687 / 115.302 / 98.092; [unlink](#case-unlink), 120 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`uptime`](../loadables/uptime.c) | D S T F | [Smoke](../tests/system-smoke.sh) | uptime; uptime | 8.099 / INVALID / 123.802; [uptime](#case-uptime), 108 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`userdb`](../loadables/userdb.c) | S F | [Contract](../tests/system-smoke.sh) | —; getent | 43.921 / — / —; [userdb-lookup](#case-userdb-lookup), 58 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`utf8`](../loadables/utf8.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; Python Unicode / grapheme library | 10.202 / — / —; [utf8-length-grapheme](#case-utf8-length-grapheme), 128 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`utmp`](../loadables/utmp.c) | D S F | [Contract](../tests/system-smoke.sh) | who; utmpdump / who | 66.585 / — / —; [utmp-dump](#case-utmp-dump), 10 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`uudecode`](../loadables/uudecode.c) | C D S T F | [Bench checked](#case-uudecode) | uudecode; uudecode (missing) | 36.842 / 100.351 / —; [uudecode](#case-uudecode), 59 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`uuencode`](../loadables/uuencode.c) | C D S T F | [Bench checked](#case-uuencode) | uuencode; uuencode (missing) | 52.132 / 101.080 / —; [uuencode](#case-uuencode), 51 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`uuidgen`](../loadables/uuidgen.c) | F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; uuidgen (missing) | 80.899 / — / —; [uuidgen-v3-md5](#case-uuidgen-v3-md5), 4 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`vec`](../loadables/vec.c) | T F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; NumPy | 65.339 / — / —; [vec-dot](#case-vec-dot), 8 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`vi`](../loadables/vi.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | vi; vi | 72.150 / — / 364.084; [vi-write](#case-vi-write), 19 passes; 2 cases total | P3 | Clamp the cursor to the new last line after a delete. |
| [`vmstat`](../loadables/vmstat.c) | D S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; vmstat | 37.667 / — / —; [vmstat-diskstats](#case-vmstat-diskstats), 79 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`vt`](../loadables/vt.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; API fixture | 97.209 / — / —; [vt](#case-vt), 6 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`w`](../loadables/w.c) | D S T F | [Smoke](../tests/system-smoke.sh) | w; w | 73.105 / — / —; [w-utmpfixture](#case-w-utmpfixture), 5 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`wall`](../loadables/wall.c) | T F | [Negative checks](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; wall | 74.486 / — / —; [wall](#case-wall), 10 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`watch`](../loadables/watch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | watch; watch | 122.955 / — / —; [watch](#case-watch), 3 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`wc`](../loadables/wc.c) | C D S T F | [Parity](../tests/wc-tail-parity.sh) | wc; wc | 50.015 / 130.113 / 31.315; [wc-characters](#case-wc-characters), 42 passes; 3 cases total | P3 | Confirm wc-characters (1.60× external time), then profile. |
| [`wg`](../loadables/wg.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; wg (missing) | 13.683 / — / —; [wg-pubkey](#case-wg-pubkey), 178 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`wget_wch`](../loadables/wget_wch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 5.059 / — / —; [wget_wch](#case-wget_wch), 114 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`wgetch`](../loadables/wgetch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | 5.935 / — / —; [wgetch](#case-wgetch), 200 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`whatis`](../loadables/whatis.c) | T F | [Contract](../tests/misc-smoke.py) | —; whatis | 69.855 / — / 318.006; [whatis](#case-whatis), 8 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`whiptail`](../loadables/whiptail.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; whiptail | 78.187 / — / —; [whiptail](#case-whiptail), 3 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`who`](../loadables/who.c) | D S T F | [Smoke](../tests/system-smoke.sh) | who; who | 64.049 / ERROR / 363.221; [who-quick](#case-who-quick), 37 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `whoami`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | whoami; whoami | 4.025 / 102.466 / 86.040; [whoami](#case-whoami), 130 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`wipefs`](../loadables/wipefs.c) | D S F | [Bench checked](#case-wipefs) | —; wipefs | 21.150 / — / 1379.523; [wipefs](#case-wipefs), 99 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`write`](../loadables/write.c) | T F | [Negative checks](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; write (missing) | 50.224 / — / —; [write](#case-write), 25 passes; self-timed | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`xargs`](../loadables/xargs.c) | C D S T F | [Contract](../tests/regressions.py) | xargs; xargs | 2991.690 / 1954.000 / 2684.932; [xargs](#case-xargs), 3 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`xattr`](../loadables/xattr.c) | S F | [Contract](../tests/system-smoke.sh) | —; getfattr / setfattr | 6.451 / — / —; [xattr-list](#case-xattr-list), 141 passes; self-timed; 2 cases total | P4 | Self-timed baseline: no external program or applet implements this, so compare a change against this figure rather than a ratio. |
| [`zcat`](../loadables/zcat.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | zcat; zcat | 56.812 / 171.397 / ERROR; [zcat](#case-zcat), 52 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`zlib`](../loadables/zlib.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | gzip; gzip / xz / zstd / bzip2 | 88.246 / 101.960 / 94.144; [zlib-bzip2](#case-zlib-bzip2), 7 passes; 3 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`zstd`](../loadables/zstd.c) | S T F | [Parity](../tests/zstd-check.sh); [S](../tests/zstd-host.c) | —; zstd | 50.259 / — / 123.087; [zstd-decompress](#case-zstd-decompress), 56 passes | P3 | See the dedicated zstd report; extend sizes and levels if a slower case appears. |
| [`zstdcat`](../loadables/zstdcat.c) | S T F | [Parity](../tests/zstd-check.sh) | —; zstdcat | 52.119 / — / 121.452; [zstdcat](#case-zstdcat), 56 passes | P4 | Extend sizes/options; no selected-case performance priority. |
<!-- END CATALOG -->

## Repeated-input findings

Five commands in the current measured build return success while repeated
calls with freshly redirected stdin produce different output from fresh
external commands: `colrm`, `column`, `strings`, `od` and `hexdump`.
Worker progress is recorded in the queue; these findings are cleared only
after integration and fresh output validation.

For example, the measured `column` implementation emits the aligned table
only on the first of these three calls:

```bash
bench_input=$(mktemp)
printf 'alpha\tbeta\none\ttwo\n' > "$bench_input"
out/bash --noprofile --norc -c '
  for ((i=0; i<3; i++)); do column -t < "$1"; done
' _ "$bench_input"
# Expected: the aligned table three times.
rm -- "$bench_input"
```

For automatically managed fixtures, use:

```bash
python3 bench/loadables.py --quick --only colrm,column,strings,od,hexdump \
  --output /tmp/loadable-check.json
```

`--quick` still validates at least three invocations in the same shell. It
reduces timed samples, not this correctness check. The harness records failures
in JSON and continues collecting other cases; exit zero means the report was
written, not that every command passed.

The completed fixes establish why clearing an EOF flag alone is insufficient:
the shell's shared `stdin` stream can also retain buffered bytes from an older
redirection. Each builtin needs input owned by its invocation and correct
descriptor cleanup. The new regressions cover repeated redirects, mixed files,
pipes, empty input and interleaving with other builtins. The `nl` suite also
checks that opening a named file while stdin is closed leaves stdin closed.

## Additional correctness checks

<!-- BEGIN UNTIMED -->
No additional untimed findings are recorded.
<!-- END UNTIMED -->

## Scope notes

These are specific reviewed limits or gaps, not an exhaustive option audit.
Source comments alone were not treated as proof of an unimplemented feature.

<!-- BEGIN NOTES -->
| Loadable | Scope / limitation |
| --- | --- |
| `ar` | Truncated headers, extract write errors and short member bodies are rejected; tests/ar-check.sh matches GNU 2.44 including /dev/full unlink and archive-link identity. |
| `bc` | Repeated stdin is fixed. User functions, output-base printing, control flow, comments and file operands remain outside the supported language subset. [source](../docs/bc.md) |
| `bsdgames` | The headless games read stdin with fgets and now clearerr(stdin) at the builtin entry; before, a second game in the same shell read nothing and exited 0 without playing. [source](../tests/repeat-input-check.sh) |
| `cluster` | Only a version smoke check is mapped here. |
| `col` | Repeated redirected stdin is fixed; tests/col-check.sh matches GNU on three fresh redirections. Output is newline-terminated as util-linux does, including an unterminated final line, which is what the large text fixture has. File operands are a bash-os extension: util-linux col reads stdin only and rejects an operand, so that path has no reference. [source](../tests/col-newline-check.sh) |
| `colrm` | Repeated redirected stdin is fixed; tests/colrm-check.sh matches GNU on three fresh redirections. |
| `column` | Repeated redirected stdin is fixed; tests/column-check.sh matches GNU on three fresh redirections. |
| `comm` | Repeated-input and write-failure contracts are covered by tests/comm-check.sh. The timed comm case remains slower than GNU on this host. |
| `coreutils` | Dispatcher; each subcommand is measured separately. nproc's default counts the affinity mask, as GNU's does, so it follows a taskset pin; --all reports every configured processor. GNU's OMP_NUM_THREADS and OMP_THREAD_LIMIT overrides are deliberately not implemented. [source](../loadables/coreutils.c) |
| `cp` | A forced copy that cannot read its source keeps the existing destination; tests/cp-check.sh matches GNU. |
| `crypto` | A failed digest write now returns failure; tests/crypto-check.sh covers sha256 -x > /dev/full. |
| `csplit` | Repeated redirected stdin is fixed; tests/csplit-check.sh matches GNU piece files across three redirections. |
| `diff` | Minus operands are stdin, including `diff - -`. The timed case still measures identical files, not edit-script generation. |
| `dmesg` | On the BASHDMESG_DEV_KMSG_FILE path, bd_drain() reads into a fixed 8192-byte buffer and silently truncates or drops a record that straddles the boundary. |
| `dmsetup` | Some mutation verbs still return an explicit unimplemented-backend error. [source](../loadables/dmsetup.c) |
| `doas` | Current integration test rejects an invalid option before credential transition. |
| `du` | A failed size-report write now returns failure; tests/du-check.sh covers du -b file > /dev/full. |
| `expand` | Buffered output and per-invocation input are validated. Documented option/tab-stop differences and locale scope remain; tiny-input speedup is not established. [source](../docs/expand.md) |
| `fold` | Buffered ASCII processing is validated; the existing permissive UTF-8 decoder and short-input fread lookahead behavior remain. Unicode and appliance throughput are not established. [source](../docs/fold.md) |
| `free` | Measured against a pinned /proc via BASHOS_PROC_ROOT, self-timed: the live counters move between the reference call and the repeated batch, so a live ratio could only ever fail. tests/free-check.sh holds the GNU parity. [source](../tests/free-check.sh) |
| `fstrim` | `-I/--listed-in` reports, and would trim, any path in the list file that merely stat()s; util-linux cross-checks each entry against the live mount table and reports only mounted filesystems. This is why the case is self-timed: there is no output to compare against util-linux, which exits non-zero on the same input. |
| `gpu` | CPU/protocol, native driver and isolated Kilix checks exist. Static builds support CPU presentation; native shaders require dynamic linking. |
| `grep` | Default build disables -P; the separate pcre loadable supplies PCRE2 operations. See the source build switch. [source](../loadables/grep.c) |
| `head` | Repeated stdin is fixed. The stock Bash option subset remains; private streams restore seekable read-ahead and use unbuffered pipe input. [source](../docs/head-sed.md) |
| `hexdump` | Repeated redirected stdin is fixed; tests/hexdump-check.sh matches GNU on three fresh redirections. |
| `hostid` | Default is gethostid(3), matching hostid(1), including on this measured full binary. tests/hostid-check.sh covers override files and the machine-id fallback. [source](../docs/hostid.md) |
| `join` | Write-failure stop and GNU comparison are covered by tests/join-check.sh. |
| `ldap` | BER/filter fixtures and bounded fuzzing pass; live server/authentication throughput is unmeasured. |
| `lpr` | Submit copies into a spool and sleeps to simulate printing. No real printer throughput claim. [source](../loadables/lpr.c) |
| `lsattr` | The flag field is 14 columns where e2fsprogs prints 22 for the same file, so the two cannot be compared on exact bytes. |
| `mail` | Alias compilation/expansion fixtures exist; no SMTP delivery throughput measurement. |
| `mktemp` | `-u` does the filesystem work it is supposed to skip: sh_mktmpfd() runs unconditionally and -u is applied afterwards, so the builtin creates (O_CREAT&#124;O_EXCL) and then unlinks, while GNU and BusyBox only expand the template. The builtin therefore fails where both references succeed whenever the template's directory is not writable. |
| `mv` | Moving a file to itself now fails and preserves bytes; tests/mv-check.sh matches GNU. |
| `nano` | Editor selftests pass; justify, spell and completion still report unimplemented. [source](../loadables/nano.c) |
| `nl` | Repeated stdin, stale stream read-ahead and named-file descriptor ownership are fixed. BRE matching uses the host regex library; without REG_STARTEND, patterns cannot match past embedded NUL bytes. [source](../docs/nl.md) |
| `obj` | The getline(stdin) loops now clearerr(stdin) at the builtin entry: without it a second in-process `--batch-check`, `--batch`, `hash --stdin-paths` or `tree` emitted nothing while still exiting 0, because a builtin does not fork and the stream keeps its EOF flag. [source](../tests/repeat-input-check.sh) |
| `od` | Repeated redirected stdin is fixed; tests/od-check.sh matches GNU on three fresh redirections. |
| `passwd` | `list -l` misparses any record with an empty field: bpw_list_cmd splits with strtok_r(copy, ":", &save), and strtok_r collapses consecutive delimiters, so fields shift left from the first empty one. bpw_lookup_user uses the same pattern, so the lookup path shares the defect. The benchmark fixture keeps all seven fields populated and must stay that way for its reference to hold. |
| `payload` | Install/remove invoke a helper outside this repository; the current fixture only calls help. [source](../loadables/payload.c) |
| `pgrep` | Matching is substring-based unless exact matching is selected; not full procps regular-expression behavior. [source](../loadables/pgrep.c) |
| `pkill` | Shares pgrep matching and process traversal; validate signals only against owned child fixtures. [source](../loadables/pkill.c) |
| `pr` | Repeated stdin, paging and output failures are fixed for the tested subset. Numbered multi-column control bytes, merged unterminated records and several GNU options remain documented exclusions. [source](../docs/pr.md) |
| `rev` | Write-failure stop and GNU comparison are covered by tests/rev-check.sh. |
| `rsync` | For a non-existent single-file DEST the builtin creates the destination as a directory, while stock rsync treats DEST as a directory only when it already exists or ends in '/'. The measured case uses the trailing-slash form into a reset-recreated directory, where the two agree byte for byte. |
| `rtspcat` | No command-specific fixture is mapped in the current repository suite. |
| `scp` | Companion frontend to sftp; local-copy and failure fixtures do not establish full remote scp compatibility. |
| `screen` | Metadata/control fixtures pass; the live relay path needs separate sustained traffic measurements. |
| `sed` | Repeated stdin and final-newline preservation are fixed. Regex and per-file state differ from GNU; an evaluated dollar address before early pipe quit can consume one lookahead byte. [source](../docs/head-sed.md) |
| `sftp` | Local operation and failure fixtures exist; remote transfer behavior needs dedicated interop and throughput coverage. |
| `sort` | Write-failure stop and GNU comparison are covered by tests/sort-check.sh. sort-text remains a timed performance candidate. |
| `split` | Repeated redirected stdin is fixed; tests/split-check.sh matches GNU piece files across three redirections. |
| `ssh` | Host-key fixtures and loopback SSH interoperability pass; no transfer throughput measurements. |
| `sshd` | Loopback interoperability and malformed setup cases pass; no concurrent-session measurements. |
| `strings` | Repeated redirected stdin is fixed; tests/strings-check.sh matches GNU on three fresh redirections. |
| `su` | Current integration test rejects an invalid option before credential transition. |
| `sudo` | Current integration test rejects an invalid option before credential transition. |
| `tac` | Descriptor input and buffered literal-separator processing are validated. Whole-file memory use and the POSIX ERE regex subset remain limits; dedicated size and separator measurements are separate. [source](../docs/tac.md) |
| `tail` | Repeated small-input redirections and write-error stop are covered by tests/tail-check.sh. |
| `tee` | Closed-stdin and all-outputs-failed stop are covered by tests/tee-check.sh. Stock examples/loadables/tee.c is still the source. |
| `truncate` | Size arithmetic overflow is rejected and existing bytes are preserved; tests/truncate-check.sh matches GNU. |
| `ts` | Capture precedence takes the last matching pattern rather than the most specific: in span mode a JSON object key yields both string.special.key and string, and the renderer paints it with the later, less specific rule. |
| `uclampset` | Query subset; setting PID/system clamps and command mode are refused. [source](../loadables/uclampset.c) |
| `unexpand` | Write-failure stop and GNU comparison are covered by tests/unexpand-check.sh. |
| `vi` | After `dd` deletes the buffer's last line the cursor is left on a line that no longer exists, and every later `dd` is a silent no-op returning 0; nvim clamps the cursor and keeps deleting. The benchmark fixture deliberately omits `G` before its dd run: with it the case would have measured one edit instead of 250 while still validating. |
| `wc` | Requested word-count assertions are covered by tests/wc-check.sh and tests/wc-tail-parity.sh. |
| `zstd` | Default-level stdin compress/decompress is ahead of host zstd(1) on the catalog binary; frames are not byte-identical and validation is round-trip. BusyBox has no applet. Whole-file reads and one-shot ZSTD_compress remain. [source](../docs/zstd.md) |
<!-- END NOTES -->

## Individual benchmark cases

<!-- BEGIN CASES -->
| Case | Builtin command | External command | Input | Passes | BOS ms | BB ms | External ms | BOS / external | Samples |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| <a id="case-acme-jwk-thumbprint"></a>acme-jwk-thumbprint | `acme jwk-thumbprint -k 5a1c1f4b9e2d8a7c3f60b5d4e9a28c1706f3b8d5e4c2a19f8b7d6e5c4a3f2b19` | `acme jwk-thumbprint -k 5a1c1f4b9e2d8a7c3f60b5d4e9a28c1706f3b8d5e4c2a19f8b7d6e5c4a3f2b19` | No stdin; named fixtures / arguments | 28 | 66.960 | — | — | — | 7 |
| <a id="case-apropos"></a>apropos | `apropos alpha` | `apropos alpha` | No stdin; named fixtures / arguments | 41 | 62.856 | — | 355.389 | 0.18× | 7 |
| <a id="case-ar"></a>ar | `ar t tiny.a` | `ar t tiny.a` | No stdin; named fixtures / arguments | 100 | 4.196 | 76.195 | 103.790 | 0.04× | 7 |
| <a id="case-asort-index-numeric"></a>asort-index-numeric | `asort -n -i I A` | `asort -n -i I A` | No stdin; named fixtures / arguments | 3 | 176.690 | — | — | — | 7 |
| <a id="case-at-list"></a>at-list | `at -l` | `at -l` | No stdin; named fixtures / arguments | 32 | 66.285 | — | — | — | 7 |
| <a id="case-audit-decode-text"></a>audit-decode-text | `audit decode-text 1300 'audit(1757600000.123:4242): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd0a1b2c30 a1=7ffd0a1b2d40 a2=7ffd0a1b2e50 a3=7f2b1c0d8e60 items=2 ppid=1024 pid=2048 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="bash" exe="/usr/local/bin/bash-os" subj=unconfined key="exec-watch" cwd="/home/pleb/projects/bash-os" a0="/home/pleb/projects/bash-os/loadables/part00.c" a1="/home/pleb/projects/bash-os/loadables/part01.c" a2="/home/pleb/projects/bash-os/loadables/part02.c" a3="/home/pleb/projects/bash-os/loadables/part03.c" a4="/home/pleb/projects/bash-os/loadables/part04.c" a5="/home/pleb/projects/bash-os/loadables/part05.c" a6="/home/pleb/projects/bash-os/loadables/part06.c" a7="/home/pleb/projects/bash-os/loadables/part07.c" a8="/home/pleb/projects/bash-os/loadables/part08.c" a9="/home/pleb/projects/bash-os/loadables/part09.c" a10="/home/pleb/projects/bash-os/loadables/part10.c" a11="/home/pleb/projects/bash-os/loadables/part11.c" a12="/home/pleb/projects/bash-os/loadables/part12.c" a13="/home/pleb/projects/bash-os/loadables/part13.c" a14="/home/pleb/projects/bash-os/loadables/part14.c" a15="/home/pleb/projects/bash-os/loadables/part15.c" a16="/home/pleb/projects/bash-os/loadables/part16.c" a17="/home/pleb/projects/bash-os/loadables/part17.c" a18="/home/pleb/projects/bash-os/loadables/part18.c" a19="/home/pleb/projects/bash-os/loadables/part19.c" a20="/home/pleb/projects/bash-os/loadables/part20.c" a21="/home/pleb/projects/bash-os/loadables/part21.c" a22="/home/pleb/projects/bash-os/loadables/part22.c" a23="/home/pleb/projects/bash-os/loadables/part23.c" a24="/home/pleb/projects/bash-os/loadables/part24.c" a25="/home/pleb/projects/bash-os/loadables/part25.c" a26="/home/pleb/projects/bash-os/loadables/part26.c" a27="/home/pleb/projects/bash-os/loadables/part27.c" a28="/home/pleb/projects/bash-os/loadables/part28.c" a29="/home/pleb/projects/bash-os/loadables/part29.c" a30="/home/pleb/projects/bash-os/loadables/part30.c" a31="/home/pleb/projects/bash-os/loadables/part31.c" a32="/home/pleb/projects/bash-os/loadables/part32.c" a33="/home/pleb/projects/bash-os/loadables/part33.c" a34="/home/pleb/projects/bash-os/loadables/part34.c" a35="/home/pleb/projects/bash-os/loadables/part35.c" a36="/home/pleb/projects/bash-os/loadables/part36.c" a37="/home/pleb/projects/bash-os/loadables/part37.c" a38="/home/pleb/projects/bash-os/loadables/part38.c" a39="/home/pleb/projects/bash-os/loadables/part39.c" a40="/home/pleb/projects/bash-os/loadables/part40.c" a41="/home/pleb/projects/bash-os/loadables/part41.c" a42="/home/pleb/projects/bash-os/loadables/part42.c" a43="/home/pleb/projects/bash-os/loadables/part43.c" a44="/home/pleb/projects/bash-os/loadables/part44.c" a45="/home/pleb/projects/bash-os/loadables/part45.c" a46="/home/pleb/projects/bash-os/loadables/part46.c" a47="/home/pleb/projects/bash-os/loadables/part47.c" name="loadables/audit.c" inode=917531 dev=fe:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0' -o -` | `audit decode-text 1300 'audit(1757600000.123:4242): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd0a1b2c30 a1=7ffd0a1b2d40 a2=7ffd0a1b2e50 a3=7f2b1c0d8e60 items=2 ppid=1024 pid=2048 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="bash" exe="/usr/local/bin/bash-os" subj=unconfined key="exec-watch" cwd="/home/pleb/projects/bash-os" a0="/home/pleb/projects/bash-os/loadables/part00.c" a1="/home/pleb/projects/bash-os/loadables/part01.c" a2="/home/pleb/projects/bash-os/loadables/part02.c" a3="/home/pleb/projects/bash-os/loadables/part03.c" a4="/home/pleb/projects/bash-os/loadables/part04.c" a5="/home/pleb/projects/bash-os/loadables/part05.c" a6="/home/pleb/projects/bash-os/loadables/part06.c" a7="/home/pleb/projects/bash-os/loadables/part07.c" a8="/home/pleb/projects/bash-os/loadables/part08.c" a9="/home/pleb/projects/bash-os/loadables/part09.c" a10="/home/pleb/projects/bash-os/loadables/part10.c" a11="/home/pleb/projects/bash-os/loadables/part11.c" a12="/home/pleb/projects/bash-os/loadables/part12.c" a13="/home/pleb/projects/bash-os/loadables/part13.c" a14="/home/pleb/projects/bash-os/loadables/part14.c" a15="/home/pleb/projects/bash-os/loadables/part15.c" a16="/home/pleb/projects/bash-os/loadables/part16.c" a17="/home/pleb/projects/bash-os/loadables/part17.c" a18="/home/pleb/projects/bash-os/loadables/part18.c" a19="/home/pleb/projects/bash-os/loadables/part19.c" a20="/home/pleb/projects/bash-os/loadables/part20.c" a21="/home/pleb/projects/bash-os/loadables/part21.c" a22="/home/pleb/projects/bash-os/loadables/part22.c" a23="/home/pleb/projects/bash-os/loadables/part23.c" a24="/home/pleb/projects/bash-os/loadables/part24.c" a25="/home/pleb/projects/bash-os/loadables/part25.c" a26="/home/pleb/projects/bash-os/loadables/part26.c" a27="/home/pleb/projects/bash-os/loadables/part27.c" a28="/home/pleb/projects/bash-os/loadables/part28.c" a29="/home/pleb/projects/bash-os/loadables/part29.c" a30="/home/pleb/projects/bash-os/loadables/part30.c" a31="/home/pleb/projects/bash-os/loadables/part31.c" a32="/home/pleb/projects/bash-os/loadables/part32.c" a33="/home/pleb/projects/bash-os/loadables/part33.c" a34="/home/pleb/projects/bash-os/loadables/part34.c" a35="/home/pleb/projects/bash-os/loadables/part35.c" a36="/home/pleb/projects/bash-os/loadables/part36.c" a37="/home/pleb/projects/bash-os/loadables/part37.c" a38="/home/pleb/projects/bash-os/loadables/part38.c" a39="/home/pleb/projects/bash-os/loadables/part39.c" a40="/home/pleb/projects/bash-os/loadables/part40.c" a41="/home/pleb/projects/bash-os/loadables/part41.c" a42="/home/pleb/projects/bash-os/loadables/part42.c" a43="/home/pleb/projects/bash-os/loadables/part43.c" a44="/home/pleb/projects/bash-os/loadables/part44.c" a45="/home/pleb/projects/bash-os/loadables/part45.c" a46="/home/pleb/projects/bash-os/loadables/part46.c" a47="/home/pleb/projects/bash-os/loadables/part47.c" name="loadables/audit.c" inode=917531 dev=fe:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0' -o -` | No stdin; named fixtures / arguments | 127 | 8.634 | — | — | — | 7 |
| <a id="case-auth-policy-parse"></a>auth-policy-parse | `auth policy-parse auth.policy` | `auth policy-parse auth.policy` | No stdin; named fixtures / arguments | 11 | 61.420 | — | — | — | 7 |
| <a id="case-awk"></a>awk | `awk '{sum += $2} END {print sum}'` | `awk '{sum += $2} END {print sum}'` | records (162,830 stdin bytes) | 13 | 71.547 | 146.081 | 76.655 | 0.93× | 7 |
| <a id="case-basename"></a>basename | `basename /fixture/path/file.txt` | `basename /fixture/path/file.txt` | No stdin; named fixtures / arguments | 121 | 3.641 | 85.311 | 72.291 | 0.05× | 7 |
| <a id="case-bashbase64"></a>bashbase64 | `bashbase64 -w 0` | `base64 -w 0` | bytes (65,536 stdin bytes) | 80 | 9.783 | 68.918 | 54.979 | 0.18× | 7 |
| <a id="case-bashclock-sleep"></a>bashclock-sleep | `bashclock sleep 0.000000000` | `sleep 0.000000000` | No stdin; named fixtures / arguments | 126 | 11.268 | 101.577 | 86.586 | 0.13× | 7 |
| <a id="case-bashdhcp-parse-message"></a>bashdhcp-parse-message | `bashdhcp parse-message 020106003903f3260000800000000000c000020ac00002020000000002000000ab0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007078656c696e75782e3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604c0000201330400001c203a0400000e103b040000189c0104ffffff000304c00002010608c0000235c00002360f0f666978747572652e696e76616c69644214746674702e666978747572652e696e76616c6964430a7078656c696e75782e30ff` | `bashdhcp parse-message 020106003903f3260000800000000000c000020ac00002020000000002000000ab0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007078656c696e75782e3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604c0000201330400001c203a0400000e103b040000189c0104ffffff000304c00002010608c0000235c00002360f0f666978747572652e696e76616c69644214746674702e666978747572652e696e76616c6964430a7078656c696e75782e30ff` | No stdin; named fixtures / arguments | 126 | 5.662 | — | — | — | 7 |
| <a id="case-bashinotify-drain"></a>bashinotify-drain | `bashinotify wait -t 0` | `bashinotify wait -t 0` | No stdin; named fixtures / arguments | 123 | 11.727 | — | — | — | 7 |
| <a id="case-bashio-pread"></a>bashio-pread | `bashio pread 0 423000 0` | `dd bs=423000 count=1 status=none` | text (423,000 stdin bytes) | 80 | 6.155 | 74.020 | 67.495 | 0.09× | 7 |
| <a id="case-bashio-pread-hex"></a>bashio-pread-hex | `bashio pread -x 0 65536 0` | `xxd -p -c 65536` | bytes (65,536 stdin bytes) | 80 | 13.266 | 417.067 | 119.680 | 0.11× | 7 |
| <a id="case-bashjson"></a>bashjson | `bashjson get .answer` | `jq .answer` | object (39,133 stdin bytes) | 67 | 35.133 | — | 282.417 | 0.12× | 7 |
| <a id="case-bashkmod-aliases"></a>bashkmod-aliases | `bashkmod aliases pci:v00008086d00001000sv00000000sd00000000bc0Csc03i30` | `bashkmod aliases pci:v00008086d00001000sv00000000sd00000000bc0Csc03i30` | No stdin; named fixtures / arguments | 50 | 54.468 | — | — | — | 7 |
| <a id="case-bashmount-findmnt"></a>bashmount-findmnt | `bashmount --findmnt-table mountinfo` | `findmnt --tab-file mountinfo --raw --noheadings -o ID,PARENT,MAJ:MIN,FSROOT,TARGET,VFS-OPTIONS,FSTYPE,SOURCE` | No stdin; named fixtures / arguments | 42 | 63.388 | — | 461.233 | 0.14× | 7 |
| <a id="case-bashpoll-wait"></a>bashpoll-wait | `bashpoll wait -t 0 2:write 9:write 8:write 7:write 6:write 5:write 4:write 3:write` | `bashpoll wait -t 0 2:write 9:write 8:write 7:write 6:write 5:write 4:write 3:write` | No stdin; named fixtures / arguments | 130 | 6.634 | — | — | — | 7 |
| <a id="case-bashtermraw-stty-g"></a>bashtermraw-stty-g | `bashtermraw stty-g` | `bashtermraw stty-g` | ptmx (0 stdin bytes) | 122 | 7.277 | — | — | — | 7 |
| <a id="case-batch-queue"></a>batch-queue | `batch` | `batch` | left (120,000 stdin bytes) | 20 | 4.539 | — | — | — | 7 |
| <a id="case-bc"></a>bc | `bc` | `bc` | arithmetic (18 stdin bytes) | 80 | 5.573 | 70.617 | 70.232 | 0.08× | 7 |
| <a id="case-bignum"></a>bignum | `bignum add 999999999999999999 1` | `expr 999999999999999999 + 1` | No stdin; named fixtures / arguments | 124 | 4.415 | 87.242 | 81.727 | 0.05× | 7 |
| <a id="case-bignum-mul"></a>bignum-mul | `bignum mul 123 456` | `expr 123 '*' 456` | No stdin; named fixtures / arguments | 120 | 4.854 | 105.697 | 88.863 | 0.05× | 7 |
| <a id="case-binhex"></a>binhex | `binhex` | `hexdump -ve '/1 "%02x"'` | bytes (65,536 stdin bytes) | 70 | 7.748 | 416.453 | 456.427 | 0.02× | 7 |
| <a id="case-binhex-decode"></a>binhex-decode | `binhex -d` | `xxd -r -p` | hexbytes (131,072 stdin bytes) | 78 | 28.387 | 165.367 | 153.055 | 0.19× | 7 |
| <a id="case-blkid-label"></a>blkid-label | `blkid -s LABEL -o value disk.img` | `blkid -s LABEL -o value disk.img` | No stdin; named fixtures / arguments | 114 | 6.380 | INVALID | 193.145 | 0.03× | 7 |
| <a id="case-blkid-type"></a>blkid-type | `blkid -s TYPE -o value disk.img` | `blkid -s TYPE -o value disk.img` | No stdin; named fixtures / arguments | 90 | 5.483 | INVALID | 115.923 | 0.05× | 7 |
| <a id="case-bsdgames-primes"></a>bsdgames-primes | `bsdgames primes 1 200000` | `bsdgames primes 1 200000` | No stdin; named fixtures / arguments | 4 | 92.233 | — | — | — | 7 |
| <a id="case-bsdgames-rot13"></a>bsdgames-rot13 | `bsdgames rot13` | `tr A-Za-z N-ZA-Mn-za-m` | duplicates (1,680,000 stdin bytes) | 3 | 100.655 | 13.390 | 8.014 | 12.56× | 7 |
| <a id="case-buf-load"></a>buf-load | `buf load 0 text` | `buf load 0 text` | No stdin; named fixtures / arguments | 46 | 20.089 | — | — | — | 7 |
| <a id="case-buf-text"></a>buf-text | `buf text 0` | `cat text` | No stdin; named fixtures / arguments | 19 | 52.113 | 18.860 | 16.641 | 3.13× | 7 |
| <a id="case-cal"></a>cal | `cal 2 2024` | `cal 2 2024` | No stdin; named fixtures / arguments | 87 | 4.041 | 67.281 | — | — | 7 |
| <a id="case-caps-probe"></a>caps-probe | `caps probe` | `caps probe` | No stdin; named fixtures / arguments | 98 | 4.926 | — | — | — | 7 |
| <a id="case-cat"></a>cat | `cat` | `cat` | text (423,000 stdin bytes) | 80 | 7.979 | 58.076 | 57.517 | 0.14× | 7 |
| <a id="case-chattr"></a>chattr | `chattr -R +A attrtree` | `chattr -R +A attrtree` | No stdin; named fixtures / arguments | 23 | 72.971 | — | 136.683 | 0.53× | 7 |
| <a id="case-chgrp"></a>chgrp | `chgrp pleb text` | `chgrp pleb text` | No stdin; named fixtures / arguments | 113 | 6.706 | 96.560 | 96.715 | 0.07× | 7 |
| <a id="case-chmod"></a>chmod | `chmod 644 text` | `chmod 644 text` | No stdin; named fixtures / arguments | 112 | 4.131 | 94.122 | 72.522 | 0.06× | 7 |
| <a id="case-chown"></a>chown | `chown pleb text` | `chown pleb text` | No stdin; named fixtures / arguments | 139 | 6.185 | 116.742 | 100.327 | 0.06× | 7 |
| <a id="case-chrt"></a>chrt | `chrt -m` | `chrt -m` | No stdin; named fixtures / arguments | 102 | 4.512 | — | 66.058 | 0.07× | 7 |
| <a id="case-chrt-pid1"></a>chrt-pid1 | `chrt -p 1` | `chrt -p 1` | No stdin; named fixtures / arguments | 105 | 5.027 | — | 86.672 | 0.06× | 7 |
| <a id="case-cksum"></a>cksum | `cksum` | `cksum` | text (423,000 stdin bytes) | 47 | 51.604 | — | 87.076 | 0.59× | 7 |
| <a id="case-claude-parse-response"></a>claude-parse-response | `claude parse-response` | `claude parse-response` | sseresponse (3,153,699 stdin bytes) | 4 | 85.897 | — | — | — | 7 |
| <a id="case-claude-unescape"></a>claude-unescape | `claude unescape` | `jq -j .` | jsonstring (649,973 stdin bytes) | 11 | 73.361 | — | 99.722 | 0.74× | 7 |
| <a id="case-clip-text"></a>clip-text | `clip text 0` | `head -n 4000 text` | No stdin; named fixtures / arguments | 37 | 50.945 | 70.097 | 34.676 | 1.47× | 7 |
| <a id="case-cluster-members"></a>cluster-members | `cluster members` | `cat clusterstate/members` | No stdin; named fixtures / arguments | 40 | 19.949 | 33.839 | 37.845 | 0.53× | 7 |
| <a id="case-cmp"></a>cmp | `cmp text copy` | `cmp text copy` | No stdin; named fixtures / arguments | 53 | 34.083 | 175.192 | 44.558 | 0.76× | 7 |
| <a id="case-col"></a>col | `col -b` | `col -b` | left (120,000 stdin bytes) | 20 | 63.252 | — | 123.393 | 0.51× | 7 |
| <a id="case-col-text"></a>col-text | `col -b` | `col -b` | text (423,000 stdin bytes) | 14 | 80.994 | — | 217.275 | 0.37× | 7 |
| <a id="case-colrm"></a>colrm | `colrm 4` | `colrm 4` | text (423,000 stdin bytes) | 24 | 71.451 | — | 132.323 | 0.54× | 7 |
| <a id="case-column"></a>column | `column -t` | `column -t` | tabs (340,000 stdin bytes) | 7 | 91.162 | — | 370.905 | 0.25× | 7 |
| <a id="case-comm"></a>comm | `comm left right` | `comm left right` | No stdin; named fixtures / arguments | 61 | 47.510 | — | 94.195 | 0.50× | 7 |
| <a id="case-coreutils-factor"></a>coreutils-factor | `coreutils factor 1234567890 97` | `factor 1234567890 97` | No stdin; named fixtures / arguments | 128 | 6.384 | 97.667 | 81.562 | 0.08× | 7 |
| <a id="case-coreutils-factor-big"></a>coreutils-factor-big | `coreutils factor 111111111111` | `factor 111111111111` | No stdin; named fixtures / arguments | 70 | 3.698 | 53.190 | 48.510 | 0.08× | 7 |
| <a id="case-coreutils-fmt"></a>coreutils-fmt | `coreutils fmt -w 20 left` | `fmt -w 20 left` | No stdin; named fixtures / arguments | 18 | 67.498 | — | 36.003 | 1.87× | 7 |
| <a id="case-coreutils-groups"></a>coreutils-groups | `coreutils groups` | `groups` | No stdin; named fixtures / arguments | 116 | 14.833 | 111.995 | 89.799 | 0.17× | 7 |
| <a id="case-coreutils-install"></a>coreutils-install | `coreutils install -m 644 text installed` | `install -m 644 text installed` | No stdin; named fixtures / arguments | 80 | 17.119 | 80.451 | 101.197 | 0.17× | 7 |
| <a id="case-coreutils-numfmt"></a>coreutils-numfmt | `coreutils numfmt --to=iec 1024 4096` | `numfmt --to=iec 1024 4096` | No stdin; named fixtures / arguments | 108 | 4.492 | — | 67.612 | 0.07× | 7 |
| <a id="case-coreutils-tac"></a>coreutils-tac | `coreutils tac left` | `tac left` | No stdin; named fixtures / arguments | 30 | 70.476 | 142.003 | 24.170 | 2.92× | 7 |
| <a id="case-coreutils-tsort"></a>coreutils-tsort | `coreutils tsort chain` | `tsort chain` | No stdin; named fixtures / arguments | 103 | 4.172 | — | 59.237 | 0.07× | 7 |
| <a id="case-cp"></a>cp | `cp text copied` | `cp text copied` | No stdin; named fixtures / arguments | 80 | 14.260 | 76.472 | 90.361 | 0.16× | 7 |
| <a id="case-cred-status"></a>cred-status | `cred status` | `cred status` | No stdin; named fixtures / arguments | 140 | 4.779 | — | — | — | 7 |
| <a id="case-cron-next"></a>cron-next | `cron next --from 1700000000 30 4 29 2 '*'` | `cron next --from 1700000000 30 4 29 2 '*'` | No stdin; named fixtures / arguments | 7 | 85.678 | — | — | — | 7 |
| <a id="case-crontab-install"></a>crontab-install | `crontab crontab.txt` | `crontab crontab.txt` | No stdin; named fixtures / arguments | 67 | 29.185 | — | — | — | 7 |
| <a id="case-crypto"></a>crypto | `crypto sha256 -x` | `sha256sum` | blob (1,048,576 stdin bytes) | 11 | 74.628 | 69.599 | 49.871 | 1.50× | 7 |
| <a id="case-csplit"></a>csplit | `csplit text 10 20` | `csplit text 10 20` | No stdin; named fixtures / arguments | 40 | 38.202 | — | 49.438 | 0.77× | 7 |
| <a id="case-curl-loopback-body"></a>curl-loopback-body | `curl -s http://127.0.0.1:19080/fixture` | `curl -s http://127.0.0.1:19080/fixture` | No stdin; named fixtures / arguments | 23 | 75.538 | — | 237.534 | 0.32× | 7 |
| <a id="case-cut"></a>cut | `cut -d ' ' -f 1` | `cut -d ' ' -f 1` | text (423,000 stdin bytes) | 80 | 31.713 | 351.001 | 171.164 | 0.19× | 7 |
| <a id="case-date-year"></a>date-year | `date -u +%Y` | `date -u +%Y` | No stdin; named fixtures / arguments | 84 | 3.498 | 62.097 | 55.546 | 0.06× | 7 |
| <a id="case-date-ymd"></a>date-ymd | `date -u +%Y-%m-%d` | `date -u +%Y-%m-%d` | No stdin; named fixtures / arguments | 130 | 4.460 | 95.328 | 88.277 | 0.05× | 7 |
| <a id="case-dd"></a>dd | `dd if=text bs=64K status=none` | `dd if=text bs=64K status=none` | No stdin; named fixtures / arguments | 80 | 6.519 | 67.475 | 59.376 | 0.11× | 7 |
| <a id="case-df"></a>df | `df -P /dev` | `df -P /dev` | No stdin; named fixtures / arguments | 105 | 13.644 | 85.095 | 76.287 | 0.18× | 7 |
| <a id="case-dhcp6-parse"></a>dhcp6-parse | `dhcp6 parse 02abcdef0002000a000300010200000000990001000a000300010200000099990003002e000000070000070800000b400005001820010db800000001000000000000010000000e1000001c20000d000200000017002020010db800000000000000000000005320010db8000000000000000000000054` | `dhcp6 parse 02abcdef0002000a000300010200000000990001000a000300010200000099990003002e000000070000070800000b400005001820010db800000001000000000000010000000e1000001c20000d000200000017002020010db800000000000000000000005320010db8000000000000000000000054` | No stdin; named fixtures / arguments | 140 | 5.132 | — | — | — | 7 |
| <a id="case-dhcpd-respond"></a>dhcpd-respond | `dhcpd respond 010106003903f326000080000000000000000000000000000000000002000000ab0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013d070102000000ab010c07626173682d6f733c09505845436c69656e74370d0103060c0f1a1c2a33363a3b42ff -c dhcpd.conf -l dhcpd.leases` | `dhcpd respond 010106003903f326000080000000000000000000000000000000000002000000ab0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013d070102000000ab010c07626173682d6f733c09505845436c69656e74370d0103060c0f1a1c2a33363a3b42ff -c dhcpd.conf -l dhcpd.leases` | No stdin; named fixtures / arguments | 92 | 23.475 | — | — | — | 7 |
| <a id="case-dhcpd6-respond"></a>dhcpd6-respond | `dhcpd6 respond 01abcdef0001000a000300010200000099990008000200000003000c0000000700000000000000000006000400170018 -c dhcpd6.conf -l dhcpd6.leases` | `dhcpd6 respond 01abcdef0001000a000300010200000099990008000200000003000c0000000700000000000000000006000400170018 -c dhcpd6.conf -l dhcpd6.leases` | No stdin; named fixtures / arguments | 110 | 20.798 | — | — | — | 7 |
| <a id="case-dialog"></a>dialog | `dialog --output-fd 1 --separate-output --checklist pick 20 60 10 alpha A off beta B off gamma C off delta D off` | `dialog --output-fd 1 --separate-output --checklist pick 20 60 10 alpha A off beta B off gamma C off delta D off` | dialogtags (85,000 stdin bytes) | 4 | 101.396 | — | — | — | 7 |
| <a id="case-diff"></a>diff | `diff text copy` | `diff text copy` | No stdin; named fixtures / arguments | 24 | 53.559 | 45.836 | 30.127 | 1.78× | 7 |
| <a id="case-dirname"></a>dirname | `dirname /fixture/path/file.txt` | `dirname /fixture/path/file.txt` | No stdin; named fixtures / arguments | 118 | 4.278 | 89.054 | 80.979 | 0.05× | 7 |
| <a id="case-dmesg-kmsgfixture"></a>dmesg-kmsgfixture | `dmesg` | `dmesg` | No stdin; named fixtures / arguments | 21 | 67.456 | — | — | — | 7 |
| <a id="case-dns-checkzone"></a>dns-checkzone | `dns checkzone -o fixture.test. zone` | `dns checkzone -o fixture.test. zone` | No stdin; named fixtures / arguments | 3 | 202.979 | — | — | — | 7 |
| <a id="case-du-file"></a>du-file | `du -b text` | `du -b text` | No stdin; named fixtures / arguments | 80 | 3.581 | 60.712 | 54.112 | 0.07× | 7 |
| <a id="case-du-tree"></a>du-tree | `du -b tree` | `du -b tree` | No stdin; named fixtures / arguments | 80 | 21.473 | INVALID | 78.546 | 0.27× | 7 |
| <a id="case-ed"></a>ed | `ed -s left` | `ed -s left` | edscript (7 stdin bytes) | 54 | 50.030 | 94.375 | — | — | 7 |
| <a id="case-env"></a>env | `env -i FOO=bar /usr/bin/printenv FOO` | `env -i FOO=bar /usr/bin/printenv FOO` | No stdin; named fixtures / arguments | 72 | 41.177 | 82.037 | 66.746 | 0.62× | 7 |
| <a id="case-escdelay"></a>escdelay | `escdelay get --screen bench_screen_00_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_01_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_02_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_03_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_04_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_05_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_06_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_07_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | `escdelay get --screen bench_screen_00_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_01_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_02_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_03_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_04_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_05_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_06_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --screen bench_screen_07_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | No stdin; named fixtures / arguments | 117 | 4.538 | — | — | — | 7 |
| <a id="case-expand"></a>expand | `expand -t 8` | `expand -t 8` | tabs (340,000 stdin bytes) | 38 | 62.889 | 318.800 | 85.473 | 0.74× | 7 |
| <a id="case-expect"></a>expect | `expect expect 0 '^004999 left$'` | `expect expect 0 '^004999 left$'` | left (120,000 stdin bytes) | 3 | 144.904 | — | — | — | 7 |
| <a id="case-expr"></a>expr | `expr 123 '*' 456` | `expr 123 '*' 456` | No stdin; named fixtures / arguments | 99 | 3.517 | 74.861 | 66.925 | 0.05× | 7 |
| <a id="case-fail2ban-format-status"></a>fail2ban-format-status | `fail2ban format-status ban.db sshd` | `fail2ban format-status ban.db sshd` | No stdin; named fixtures / arguments | 22 | 67.854 | — | — | — | 7 |
| <a id="case-fdflags-scan"></a>fdflags-scan | `fdflags -v` | `fdflags -v` | No stdin; named fixtures / arguments | 3 | 175.166 | — | — | — | 7 |
| <a id="case-fdisk-list"></a>fdisk-list | `fdisk -l parts.img` | `fdisk -l parts.img` | No stdin; named fixtures / arguments | 99 | 22.054 | — | — | — | 7 |
| <a id="case-fdisk-verify"></a>fdisk-verify | `fdisk --verify parts.img` | `fdisk --verify parts.img` | No stdin; named fixtures / arguments | 125 | 11.164 | — | — | — | 7 |
| <a id="case-file"></a>file | `file text` | `file text` | No stdin; named fixtures / arguments | 103 | 4.226 | — | 930.774 | 0.00× | 7 |
| <a id="case-fincore"></a>fincore | `fincore -n text` | `fincore -n --bytes text` | No stdin; named fixtures / arguments | 131 | 6.363 | — | 95.140 | 0.07× | 7 |
| <a id="case-find"></a>find | `find tree -type f` | `find tree -type f` | No stdin; named fixtures / arguments | 80 | 23.972 | 91.591 | 84.618 | 0.28× | 7 |
| <a id="case-finfo"></a>finfo | `finfo -s text` | `stat -c %s text` | No stdin; named fixtures / arguments | 123 | 4.398 | 95.653 | 98.505 | 0.04× | 7 |
| <a id="case-finfo-mode"></a>finfo-mode | `finfo -o text` | `stat -c %a text` | No stdin; named fixtures / arguments | 106 | 4.192 | 78.260 | 86.951 | 0.05× | 7 |
| <a id="case-flock"></a>flock | `flock -n lockfile /bin/true` | `flock -n lockfile /bin/true` | No stdin; named fixtures / arguments | 77 | 41.694 | — | 76.570 | 0.54× | 7 |
| <a id="case-fltexpr"></a>fltexpr | `fltexpr -p '1+2*3'` | `awk 'BEGIN{print 1+2*3}'` | No stdin; named fixtures / arguments | 129 | 4.054 | 98.425 | 179.773 | 0.02× | 7 |
| <a id="case-fold"></a>fold | `fold -w 40` | `fold -w 40` | text (423,000 stdin bytes) | 36 | 40.912 | 152.660 | 94.866 | 0.43× | 7 |
| <a id="case-free-procfixture"></a>free-procfixture | `free -k` | `free -k` | No stdin; named fixtures / arguments | 141 | 4.362 | — | — | — | 7 |
| <a id="case-fsck"></a>fsck | `fsck -n disk.img` | `fsck -n disk.img` | No stdin; named fixtures / arguments | 135 | 4.728 | — | — | — | 7 |
| <a id="case-fstrim"></a>fstrim | `fstrim -n -I left` | `fstrim -n -I left` | No stdin; named fixtures / arguments | 6 | 60.860 | — | — | — | 7 |
| <a id="case-fw-batch-dryrun"></a>fw-batch-dryrun | `fw -B nft -n batch fw.batch` | `fw -B nft -n batch fw.batch` | No stdin; named fixtures / arguments | 11 | 85.912 | — | — | — | 7 |
| <a id="case-genl-ctrl-list"></a>genl-ctrl-list | `genl ctrl list` | `genl ctrl list` | No stdin; named fixtures / arguments | 80 | 34.018 | — | — | — | 7 |
| <a id="case-getconf"></a>getconf | `getconf PAGE_SIZE` | `getconf PAGE_SIZE` | No stdin; named fixtures / arguments | 132 | 4.359 | — | 78.629 | 0.06× | 7 |
| <a id="case-getconf-nproc"></a>getconf-nproc | `getconf _NPROCESSORS_ONLN` | `getconf _NPROCESSORS_ONLN` | No stdin; named fixtures / arguments | 133 | 4.346 | — | 79.218 | 0.05× | 7 |
| <a id="case-getfacl"></a>getfacl | `getfacl acls/f00 acls/f01 acls/f02 acls/f03 acls/f04 acls/f05 acls/f06 acls/f07 acls/f08 acls/f09 acls/f10 acls/f11 acls/f12 acls/f13 acls/f14 acls/f15 acls/f16 acls/f17 acls/f18 acls/f19 acls/f20 acls/f21 acls/f22 acls/f23 acls/f24 acls/f25 acls/f26 acls/f27 acls/f28 acls/f29 acls/f30 acls/f31` | `getfacl acls/f00 acls/f01 acls/f02 acls/f03 acls/f04 acls/f05 acls/f06 acls/f07 acls/f08 acls/f09 acls/f10 acls/f11 acls/f12 acls/f13 acls/f14 acls/f15 acls/f16 acls/f17 acls/f18 acls/f19 acls/f20 acls/f21 acls/f22 acls/f23 acls/f24 acls/f25 acls/f26 acls/f27 acls/f28 acls/f29 acls/f30 acls/f31` | No stdin; named fixtures / arguments | 54 | 54.144 | — | — | — | 7 |
| <a id="case-gpu"></a>gpu | `gpu save frame.ppm` | `gpu save frame.ppm` | No stdin; named fixtures / arguments | 30 | 58.201 | — | — | — | 7 |
| <a id="case-grep-count"></a>grep-count | `grep -c alpha` | `grep -c alpha` | text (423,000 stdin bytes) | 53 | 37.053 | 363.468 | 42.431 | 0.87× | 7 |
| <a id="case-grep-lines"></a>grep-lines | `grep alpha` | `grep alpha` | text (423,000 stdin bytes) | 57 | 55.156 | 400.840 | 48.656 | 1.13× | 7 |
| <a id="case-head"></a>head | `head -n 100` | `head -n 100` | text (423,000 stdin bytes) | 78 | 8.272 | 58.363 | 49.007 | 0.17× | 7 |
| <a id="case-hexdump"></a>hexdump | `hexdump -C` | `hexdump -C` | bytes (65,536 stdin bytes) | 11 | 73.849 | 90.759 | 132.514 | 0.56× | 7 |
| <a id="case-hl"></a>hl | `hl -L json` | `hl -L json` | object (39,133 stdin bytes) | 3 | 90.435 | — | — | — | 7 |
| <a id="case-hostid"></a>hostid | `hostid` | `hostid` | No stdin; named fixtures / arguments | 149 | 6.459 | 125.787 | 102.292 | 0.06× | 7 |
| <a id="case-hostname"></a>hostname | `hostname` | `hostname` | No stdin; named fixtures / arguments | 140 | 4.728 | 104.799 | 85.858 | 0.06× | 7 |
| <a id="case-hostname-s"></a>hostname-s | `hostname -s` | `hostname -s` | No stdin; named fixtures / arguments | 105 | 3.781 | 81.150 | 65.586 | 0.06× | 7 |
| <a id="case-http-response-body"></a>http-response-body | `http response-body httpresp -o bodyout` | `http response-body httpresp -o bodyout` | No stdin; named fixtures / arguments | 67 | 13.083 | — | — | — | 7 |
| <a id="case-httpd-part"></a>httpd-part | `httpd part multipart -b bashos0boundary0fixture -o partout -n field199` | `httpd part multipart -b bashos0boundary0fixture -o partout -n field199` | No stdin; named fixtures / arguments | 72 | 21.646 | — | — | — | 7 |
| <a id="case-id-group"></a>id-group | `id -gn` | `id -gn` | No stdin; named fixtures / arguments | 150 | 5.406 | 120.285 | 130.706 | 0.04× | 7 |
| <a id="case-id-uid"></a>id-uid | `id -u` | `id -u` | No stdin; named fixtures / arguments | 84 | 3.661 | 70.551 | 64.368 | 0.06× | 7 |
| <a id="case-id-user"></a>id-user | `id -un` | `id -un` | No stdin; named fixtures / arguments | 108 | 5.229 | 89.174 | 90.460 | 0.06× | 7 |
| <a id="case-index-read"></a>index-read | `index read indexrepo/.git/index` | `git -C indexrepo ls-files --stage` | No stdin; named fixtures / arguments | 5 | 78.713 | — | 40.886 | 1.93× | 7 |
| <a id="case-integrity-manifest"></a>integrity-manifest | `integrity emit-manifest --no-header --root . -- /blob /bytes /tree` | `integrity emit-manifest --no-header --root . -- /blob /bytes /tree` | No stdin; named fixtures / arguments | 8 | 87.463 | — | — | — | 7 |
| <a id="case-ionice"></a>ionice | `ionice -p 1` | `ionice -p 1` | No stdin; named fixtures / arguments | 129 | 4.929 | 97.557 | 78.169 | 0.06× | 7 |
| <a id="case-ip"></a>ip | `ip -br link show lo` | `ip -br link show lo` | No stdin; named fixtures / arguments | 129 | 7.474 | ERROR | 167.878 | 0.04× | 7 |
| <a id="case-join"></a>join | `join left right` | `join left right` | No stdin; named fixtures / arguments | 18 | 72.419 | — | 47.218 | 1.53× | 7 |
| <a id="case-jq"></a>jq | `jq -c '[.[] &#124; select(. > 50)]'` | `jq -c '[.[] &#124; select(. > 50)]'` | array (39,109 stdin bytes) | 12 | 76.858 | — | 110.380 | 0.70× | 7 |
| <a id="case-kgetch"></a>kgetch | `kgetch decode 1b5b393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939397e` | `kgetch decode 1b5b393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939397e` | No stdin; named fixtures / arguments | 127 | 4.173 | — | — | — | 7 |
| <a id="case-killall5-dryrun"></a>killall5-dryrun | `killall5 -n` | `killall5 -n` | No stdin; named fixtures / arguments | 24 | 75.938 | — | — | — | 7 |
| <a id="case-kitty"></a>kitty | `kitty --no-tmux -w 40 -H 20 image.png` | `kitty --no-tmux -w 40 -H 20 image.png` | No stdin; named fixtures / arguments | 37 | 57.415 | — | — | — | 7 |
| <a id="case-ldap-filter-test"></a>ldap-filter-test | `ldap filter-test '(&#124;(uid=bench0000)(uid=bench0001)(uid=bench0002)(uid=bench0003)(uid=bench0004)(uid=bench0005)(uid=bench0006)(uid=bench0007)(uid=bench0008)(uid=bench0009)(uid=bench0010)(uid=bench0011)(uid=bench0012)(uid=bench0013)(uid=bench0014)(uid=bench0015)(uid=bench0016)(uid=bench0017)(uid=bench0018)(uid=bench0019)(uid=bench0020)(uid=bench0021)(uid=bench0022)(uid=bench0023)(uid=bench0024)(uid=bench0025)(uid=bench0026)(uid=bench0027)(uid=bench0028)(uid=bench0029)(uid=bench0030)(uid=bench0031)(uid=bench0032)(uid=bench0033)(uid=bench0034)(uid=bench0035)(uid=bench0036)(uid=bench0037)(uid=bench0038)(uid=bench0039)(uid=bench0040)(uid=bench0041)(uid=bench0042)(uid=bench0043)(uid=bench0044)(uid=bench0045)(uid=bench0046)(uid=bench0047)(uid=bench0048)(uid=bench0049)(uid=bench0050)(uid=bench0051)(uid=bench0052)(uid=bench0053)(uid=bench0054)(uid=bench0055)(uid=bench0056)(uid=bench0057)(uid=bench0058)(uid=bench0059)(uid=bench0060)(uid=bench0061)(uid=bench0062)(uid=bench0063)(uid=bench0064)(uid=bench0065)(uid=bench0066)(uid=bench0067)(uid=bench0068)(uid=bench0069)(uid=bench0070)(uid=bench0071)(uid=bench0072)(uid=bench0073)(uid=bench0074)(uid=bench0075)(uid=bench0076)(uid=bench0077)(uid=bench0078)(uid=bench0079)(uid=bench0080)(uid=bench0081)(uid=bench0082)(uid=bench0083)(uid=bench0084)(uid=bench0085)(uid=bench0086)(uid=bench0087)(uid=bench0088)(uid=bench0089)(uid=bench0090)(uid=bench0091)(uid=bench0092)(uid=bench0093)(uid=bench0094)(uid=bench0095)(uid=bench0096)(uid=bench0097)(uid=bench0098)(uid=bench0099)(uid=bench0100)(uid=bench0101)(uid=bench0102)(uid=bench0103)(uid=bench0104)(uid=bench0105)(uid=bench0106)(uid=bench0107)(uid=bench0108)(uid=bench0109)(uid=bench0110)(uid=bench0111)(uid=bench0112)(uid=bench0113)(uid=bench0114)(uid=bench0115)(uid=bench0116)(uid=bench0117)(uid=bench0118)(uid=bench0119)(uid=bench0120)(uid=bench0121)(uid=bench0122)(uid=bench0123)(uid=bench0124)(uid=bench0125)(uid=bench0126)(uid=bench0127)(uid=bench0128)(uid=bench0129)(uid=bench0130)(uid=bench0131)(uid=bench0132)(uid=bench0133)(uid=bench0134)(uid=bench0135)(uid=bench0136)(uid=bench0137)(uid=bench0138)(uid=bench0139)(uid=bench0140)(uid=bench0141)(uid=bench0142)(uid=bench0143)(uid=bench0144)(uid=bench0145)(uid=bench0146)(uid=bench0147)(uid=bench0148)(uid=bench0149)(uid=bench0150)(uid=bench0151)(uid=bench0152)(uid=bench0153)(uid=bench0154)(uid=bench0155)(uid=bench0156)(uid=bench0157)(uid=bench0158)(uid=bench0159)(uid=bench0160)(uid=bench0161)(uid=bench0162)(uid=bench0163)(uid=bench0164)(uid=bench0165)(uid=bench0166)(uid=bench0167)(uid=bench0168)(uid=bench0169)(uid=bench0170)(uid=bench0171)(uid=bench0172)(uid=bench0173)(uid=bench0174)(uid=bench0175)(uid=bench0176)(uid=bench0177)(uid=bench0178)(uid=bench0179)(uid=bench0180)(uid=bench0181)(uid=bench0182)(uid=bench0183)(uid=bench0184)(uid=bench0185)(uid=bench0186)(uid=bench0187)(uid=bench0188)(uid=bench0189)(uid=bench0190)(uid=bench0191)(uid=bench0192)(uid=bench0193)(uid=bench0194)(uid=bench0195)(uid=bench0196)(uid=bench0197)(uid=bench0198)(uid=bench0199))'` | `ldap filter-test '(&#124;(uid=bench0000)(uid=bench0001)(uid=bench0002)(uid=bench0003)(uid=bench0004)(uid=bench0005)(uid=bench0006)(uid=bench0007)(uid=bench0008)(uid=bench0009)(uid=bench0010)(uid=bench0011)(uid=bench0012)(uid=bench0013)(uid=bench0014)(uid=bench0015)(uid=bench0016)(uid=bench0017)(uid=bench0018)(uid=bench0019)(uid=bench0020)(uid=bench0021)(uid=bench0022)(uid=bench0023)(uid=bench0024)(uid=bench0025)(uid=bench0026)(uid=bench0027)(uid=bench0028)(uid=bench0029)(uid=bench0030)(uid=bench0031)(uid=bench0032)(uid=bench0033)(uid=bench0034)(uid=bench0035)(uid=bench0036)(uid=bench0037)(uid=bench0038)(uid=bench0039)(uid=bench0040)(uid=bench0041)(uid=bench0042)(uid=bench0043)(uid=bench0044)(uid=bench0045)(uid=bench0046)(uid=bench0047)(uid=bench0048)(uid=bench0049)(uid=bench0050)(uid=bench0051)(uid=bench0052)(uid=bench0053)(uid=bench0054)(uid=bench0055)(uid=bench0056)(uid=bench0057)(uid=bench0058)(uid=bench0059)(uid=bench0060)(uid=bench0061)(uid=bench0062)(uid=bench0063)(uid=bench0064)(uid=bench0065)(uid=bench0066)(uid=bench0067)(uid=bench0068)(uid=bench0069)(uid=bench0070)(uid=bench0071)(uid=bench0072)(uid=bench0073)(uid=bench0074)(uid=bench0075)(uid=bench0076)(uid=bench0077)(uid=bench0078)(uid=bench0079)(uid=bench0080)(uid=bench0081)(uid=bench0082)(uid=bench0083)(uid=bench0084)(uid=bench0085)(uid=bench0086)(uid=bench0087)(uid=bench0088)(uid=bench0089)(uid=bench0090)(uid=bench0091)(uid=bench0092)(uid=bench0093)(uid=bench0094)(uid=bench0095)(uid=bench0096)(uid=bench0097)(uid=bench0098)(uid=bench0099)(uid=bench0100)(uid=bench0101)(uid=bench0102)(uid=bench0103)(uid=bench0104)(uid=bench0105)(uid=bench0106)(uid=bench0107)(uid=bench0108)(uid=bench0109)(uid=bench0110)(uid=bench0111)(uid=bench0112)(uid=bench0113)(uid=bench0114)(uid=bench0115)(uid=bench0116)(uid=bench0117)(uid=bench0118)(uid=bench0119)(uid=bench0120)(uid=bench0121)(uid=bench0122)(uid=bench0123)(uid=bench0124)(uid=bench0125)(uid=bench0126)(uid=bench0127)(uid=bench0128)(uid=bench0129)(uid=bench0130)(uid=bench0131)(uid=bench0132)(uid=bench0133)(uid=bench0134)(uid=bench0135)(uid=bench0136)(uid=bench0137)(uid=bench0138)(uid=bench0139)(uid=bench0140)(uid=bench0141)(uid=bench0142)(uid=bench0143)(uid=bench0144)(uid=bench0145)(uid=bench0146)(uid=bench0147)(uid=bench0148)(uid=bench0149)(uid=bench0150)(uid=bench0151)(uid=bench0152)(uid=bench0153)(uid=bench0154)(uid=bench0155)(uid=bench0156)(uid=bench0157)(uid=bench0158)(uid=bench0159)(uid=bench0160)(uid=bench0161)(uid=bench0162)(uid=bench0163)(uid=bench0164)(uid=bench0165)(uid=bench0166)(uid=bench0167)(uid=bench0168)(uid=bench0169)(uid=bench0170)(uid=bench0171)(uid=bench0172)(uid=bench0173)(uid=bench0174)(uid=bench0175)(uid=bench0176)(uid=bench0177)(uid=bench0178)(uid=bench0179)(uid=bench0180)(uid=bench0181)(uid=bench0182)(uid=bench0183)(uid=bench0184)(uid=bench0185)(uid=bench0186)(uid=bench0187)(uid=bench0188)(uid=bench0189)(uid=bench0190)(uid=bench0191)(uid=bench0192)(uid=bench0193)(uid=bench0194)(uid=bench0195)(uid=bench0196)(uid=bench0197)(uid=bench0198)(uid=bench0199))'` | No stdin; named fixtures / arguments | 99 | 12.463 | — | — | — | 7 |
| <a id="case-less"></a>less | `less text` | `less text` | No stdin; named fixtures / arguments | 29 | 65.529 | 21.682 | 128.587 | 0.51× | 7 |
| <a id="case-link"></a>link | `link text lnhard` | `link text lnhard` | No stdin; named fixtures / arguments | 116 | 4.270 | 88.007 | 72.466 | 0.06× | 7 |
| <a id="case-ln"></a>ln | `ln -f text lnout` | `ln -f text lnout` | No stdin; named fixtures / arguments | 121 | 4.655 | 88.537 | 82.347 | 0.06× | 7 |
| <a id="case-locale-current"></a>locale-current | `locale current` | `locale current` | No stdin; named fixtures / arguments | 133 | 5.965 | — | — | — | 7 |
| <a id="case-login-lookup"></a>login-lookup | `login lookup benchuser` | `awk -F: '$1=="benchuser"{print $3":"$4":"$6":"$7":"$5}' account.passwd` | No stdin; named fixtures / arguments | 81 | 31.149 | 328.381 | 213.816 | 0.15× | 7 |
| <a id="case-logname"></a>logname | `logname` | `logname` | No stdin; named fixtures / arguments | 138 | 5.657 | 109.838 | 93.747 | 0.06× | 7 |
| <a id="case-lpr-list"></a>lpr-list | `lpr list` | `find lprspool -name '*.lpr'` | No stdin; named fixtures / arguments | 25 | 52.958 | 156.186 | 87.841 | 0.60× | 7 |
| <a id="case-ls"></a>ls | `ls -1 tree` | `ls -1 tree` | No stdin; named fixtures / arguments | 80 | 16.738 | 91.091 | 80.018 | 0.21× | 7 |
| <a id="case-lsattr"></a>lsattr | `lsattr tree` | `lsattr tree` | No stdin; named fixtures / arguments | 73 | 41.320 | — | — | — | 7 |
| <a id="case-lsblk"></a>lsblk | `lsblk -d -n -o NAME` | `lsblk -d -n -o NAME` | No stdin; named fixtures / arguments | 61 | 44.954 | — | 99.149 | 0.45× | 7 |
| <a id="case-lsof-walk"></a>lsof-walk | `lsof -u fixture-no-such-user` | `lsof -u fixture-no-such-user` | No stdin; named fixtures / arguments | 14 | 80.041 | — | — | — | 7 |
| <a id="case-mail-newaliases"></a>mail-newaliases | `mail newaliases --aliases aliases.txt --db aliasdb` | `mail newaliases --aliases aliases.txt --db aliasdb` | No stdin; named fixtures / arguments | 32 | 74.488 | — | — | — | 7 |
| <a id="case-man"></a>man | `man -w ls` | `man -w ls` | No stdin; named fixtures / arguments | 93 | 4.080 | — | 1280.398 | 0.00× | 7 |
| <a id="case-mkdir"></a>mkdir | `mkdir -p mdir` | `mkdir -p mdir` | No stdin; named fixtures / arguments | 144 | 5.097 | 125.204 | 138.417 | 0.04× | 7 |
| <a id="case-mkfifo"></a>mkfifo | `mkfifo fifo0` | `mkfifo fifo0` | No stdin; named fixtures / arguments | 133 | 5.558 | 100.869 | 102.612 | 0.05× | 7 |
| <a id="case-mkswap"></a>mkswap | `mkswap -U deadbeef-0000-4000-8000-000000000001 -L fixture swapdest.img` | `mkswap -U deadbeef-0000-4000-8000-000000000001 -L fixture swapdest.img` | No stdin; named fixtures / arguments | 136 | 8.386 | ERROR | 226.295 | 0.04× | 7 |
| <a id="case-mktemp"></a>mktemp | `mktemp -q 'mktmp-fixture mktmp.XXXXXX'` | `mktemp -q 'mktmp-fixture mktmp.XXXXXX'` | No stdin; named fixtures / arguments | 115 | 10.779 | 127.203 | 104.423 | 0.10× | 7 |
| <a id="case-mlock-trylock"></a>mlock-trylock | `mlock try-lock 1048576` | `mlock try-lock 1048576` | No stdin; named fixtures / arguments | 95 | 25.498 | — | — | — | 7 |
| <a id="case-more"></a>more | `more -n 100 text copy` | `more -n 100 text copy` | No stdin; named fixtures / arguments | 12 | 44.587 | — | 13.423 | 3.32× | 7 |
| <a id="case-mouse"></a>mouse | `mouse decode 1b5b3c33353b3939393939393b3939393939394d` | `mouse decode 1b5b3c33353b3939393939393b3939393939394d` | No stdin; named fixtures / arguments | 141 | 4.716 | — | — | — | 7 |
| <a id="case-mv"></a>mv | `mv mvsrc00 mvsrc01 mvsrc02 mvsrc03 mvsrc04 mvsrc05 mvsrc06 mvsrc07 mvsrc08 mvsrc09 mvsrc10 mvsrc11 mvsrc12 mvsrc13 mvsrc14 mvsrc15 moved` | `mv mvsrc00 mvsrc01 mvsrc02 mvsrc03 mvsrc04 mvsrc05 mvsrc06 mvsrc07 mvsrc08 mvsrc09 mvsrc10 mvsrc11 mvsrc12 mvsrc13 mvsrc14 mvsrc15 moved` | No stdin; named fixtures / arguments | 93 | 23.831 | 93.961 | 107.932 | 0.22× | 7 |
| <a id="case-nano"></a>nano | `nano selftest` | `nano selftest` | No stdin; named fixtures / arguments | 12 | 58.070 | — | — | — | 7 |
| <a id="case-nano2"></a>nano2 | `nano2 selftest` | `nano2 selftest` | No stdin; named fixtures / arguments | 22 | 32.194 | — | — | — | 7 |
| <a id="case-nc-loopback-stream"></a>nc-loopback-stream | `nc connect 127.0.0.1 19080 -w 3` | `nc 127.0.0.1 19080` | No stdin; named fixtures / arguments | 24 | 76.105 | 93.394 | 90.063 | 0.85× | 7 |
| <a id="case-ncdu-print"></a>ncdu-print | `ncdu -a -p tree` | `du --apparent-size --block-size=1 tree` | No stdin; named fixtures / arguments | 92 | 24.306 | ERROR | 84.469 | 0.29× | 7 |
| <a id="case-netids-compile"></a>netids-compile | `netids compile -S netids.rules` | `netids compile -S netids.rules` | No stdin; named fixtures / arguments | 67 | 34.975 | — | — | — | 7 |
| <a id="case-netids-scan"></a>netids-scan | `netids scan -r netids.pcap -S netids.rules` | `netids scan -r netids.pcap -S netids.rules` | No stdin; named fixtures / arguments | 4 | 69.165 | — | — | — | 7 |
| <a id="case-nice"></a>nice | `nice -n 0 /bin/true` | `nice -n 0 /bin/true` | No stdin; named fixtures / arguments | 52 | 27.693 | — | 43.905 | 0.63× | 7 |
| <a id="case-nl"></a>nl | `nl -ba` | `nl -ba` | text (423,000 stdin bytes) | 48 | 44.415 | 208.982 | 116.079 | 0.38× | 7 |
| <a id="case-nohup"></a>nohup | `nohup /bin/true` | `nohup /bin/true` | No stdin; named fixtures / arguments | 66 | 35.808 | — | 57.743 | 0.62× | 7 |
| <a id="case-notify"></a>notify | `notify send notify.sock 'READY=1 STATUS=bench fixture MAINPID=1'` | `notify send notify.sock 'READY=1 STATUS=bench fixture MAINPID=1'` | No stdin; named fixtures / arguments | 112 | 5.690 | — | — | — | 7 |
| <a id="case-ns-list"></a>ns-list | `ns list-ns` | `ns list-ns` | No stdin; named fixtures / arguments | 132 | 6.677 | — | — | — | 7 |
| <a id="case-ns-spawn-user"></a>ns-spawn-user | `ns spawn user /bin/true` | `unshare --user /bin/true` | No stdin; named fixtures / arguments | 66 | 36.275 | 69.345 | 54.335 | 0.67× | 7 |
| <a id="case-ntp-nts-selftest"></a>ntp-nts-selftest | `ntp nts-selftest` | `ntp nts-selftest` | No stdin; named fixtures / arguments | 111 | 4.275 | — | — | — | 7 |
| <a id="case-obj-batch-check"></a>obj-batch-check | `obj --batch-check -r gitloose` | `git -C gitloose cat-file --batch-check` | gitshalist (123,000 stdin bytes) | 3 | 93.039 | — | 113.102 | 0.82× | 7 |
| <a id="case-obj-hash"></a>obj-hash | `obj hash --stdin` | `git hash-object --stdin` | blob (1,048,576 stdin bytes) | 18 | 61.760 | — | 78.172 | 0.79× | 7 |
| <a id="case-od"></a>od | `od -An -tx1` | `od -An -tx1` | bytes (65,536 stdin bytes) | 13 | 76.907 | 63.034 | 139.173 | 0.55× | 7 |
| <a id="case-opt"></a>opt | `opt -o ab: -- -a -b x` | `getopt -o ab: -- -a -b x` | No stdin; named fixtures / arguments | 125 | 4.021 | 91.234 | 73.572 | 0.05× | 7 |
| <a id="case-pack-cat"></a>pack-cat | `pack cat packrepo/.git/objects/pack/pack-fixture.pack packrepo/.git/objects/pack/pack-fixture.idx 882badb336048d3cb6451ea86563e470d8f98f4d` | `git -C packrepo cat-file blob 882badb336048d3cb6451ea86563e470d8f98f4d` | No stdin; named fixtures / arguments | 7 | 85.684 | — | 85.170 | 1.01× | 7 |
| <a id="case-passwd-list"></a>passwd-list | `passwd list -l` | `awk -F: '{print $1":"$3":"$4":"$6":"$7}' account.passwd` | No stdin; named fixtures / arguments | 26 | 71.498 | 346.203 | 112.850 | 0.63× | 7 |
| <a id="case-passwd-verify-fd"></a>passwd-verify-fd | `passwd verify-fd benchuser 0` | `passwd verify-fd benchuser 0` | password (14 stdin bytes) | 3 | 118.098 | — | — | — | 7 |
| <a id="case-paste"></a>paste | `paste duplicates duplicates` | `paste duplicates duplicates` | No stdin; named fixtures / arguments | 9 | 68.804 | 367.963 | 68.106 | 1.01× | 7 |
| <a id="case-pathchk"></a>pathchk | `pathchk text` | `pathchk text` | No stdin; named fixtures / arguments | 158 | 3.741 | — | 91.079 | 0.04× | 7 |
| <a id="case-pax"></a>pax | `pax -f tiny.tar` | `tar tf tiny.tar` | No stdin; named fixtures / arguments | 80 | 4.052 | 60.076 | 87.453 | 0.05× | 7 |
| <a id="case-payload-list"></a>payload-list | `payload list` | `payload list` | No stdin; named fixtures / arguments | 3 | 139.990 | — | — | — | 7 |
| <a id="case-pcap-info"></a>pcap-info | `pcap info capture.pcap` | `pcap info capture.pcap` | No stdin; named fixtures / arguments | 4 | 82.602 | — | — | — | 7 |
| <a id="case-pcre"></a>pcre | `pcre grep alpha text` | `grep -P alpha text` | No stdin; named fixtures / arguments | 14 | 66.335 | ERROR | 15.711 | 4.22× | 7 |
| <a id="case-pgrep-kthreadd"></a>pgrep-kthreadd | `pgrep -x kthreadd` | `pgrep -x kthreadd` | No stdin; named fixtures / arguments | 34 | 55.789 | — | 536.619 | 0.10× | 7 |
| <a id="case-pidof-kthreadd"></a>pidof-kthreadd | `pidof kthreadd` | `pidof kthreadd` | No stdin; named fixtures / arguments | 26 | 70.167 | 145.782 | 188.382 | 0.37× | 7 |
| <a id="case-pkg-search"></a>pkg-search | `pkg search alpha --root pkgroot` | `pkg search alpha --root pkgroot` | No stdin; named fixtures / arguments | 10 | 71.074 | — | — | — | 7 |
| <a id="case-pkt-refs"></a>pkt-refs | `pkt refs pktrefs` | `pkt refs pktrefs` | No stdin; named fixtures / arguments | 10 | 73.685 | — | — | — | 7 |
| <a id="case-pkt-sideband"></a>pkt-sideband | `pkt sideband pktband -o packout` | `pkt sideband pktband -o packout` | No stdin; named fixtures / arguments | 80 | 22.141 | — | — | — | 7 |
| <a id="case-pr"></a>pr | `pr -t` | `pr -t` | text (423,000 stdin bytes) | 77 | 24.161 | — | 367.248 | 0.07× | 7 |
| <a id="case-printenv-lcall"></a>printenv-lcall | `printenv LC_ALL` | `printenv LC_ALL` | No stdin; named fixtures / arguments | 149 | 3.833 | — | 88.990 | 0.04× | 7 |
| <a id="case-prlimit"></a>prlimit | `prlimit --nofile` | `prlimit -o RESOURCE,SOFT,HARD --noheadings --nofile` | No stdin; named fixtures / arguments | 138 | 4.120 | — | 101.407 | 0.04× | 7 |
| <a id="case-prlimit-cpu"></a>prlimit-cpu | `prlimit --cpu` | `prlimit -o RESOURCE,SOFT,HARD --noheadings --cpu` | No stdin; named fixtures / arguments | 120 | 3.905 | — | 81.730 | 0.05× | 7 |
| <a id="case-procstat-pidstat"></a>procstat-pidstat | `procstat pidstat` | `procstat pidstat` | No stdin; named fixtures / arguments | 21 | 69.377 | — | — | — | 7 |
| <a id="case-procstat-pmap"></a>procstat-pmap | `procstat pmap 100` | `procstat pmap 100` | No stdin; named fixtures / arguments | 30 | 64.696 | — | — | — | 7 |
| <a id="case-ps-procfixture"></a>ps-procfixture | `ps -ef` | `ps -ef` | No stdin; named fixtures / arguments | 10 | 77.492 | — | — | — | 7 |
| <a id="case-pty-spawn"></a>pty-spawn | `pty spawn F P true` | `pty spawn F P true` | No stdin; named fixtures / arguments | 55 | 35.534 | — | — | — | 7 |
| <a id="case-readlink"></a>readlink | `readlink link` | `readlink link` | No stdin; named fixtures / arguments | 114 | 4.081 | 86.580 | 67.526 | 0.06× | 7 |
| <a id="case-realpath"></a>realpath | `realpath link` | `realpath link` | No stdin; named fixtures / arguments | 139 | 4.497 | 105.446 | 86.555 | 0.05× | 7 |
| <a id="case-rev"></a>rev | `rev` | `rev` | text (423,000 stdin bytes) | 16 | 75.272 | 40.518 | 142.930 | 0.53× | 7 |
| <a id="case-rm"></a>rm | `rm -f nosuch` | `rm -f nosuch` | No stdin; named fixtures / arguments | 146 | 4.760 | 96.093 | 84.547 | 0.06× | 7 |
| <a id="case-rmdir"></a>rmdir | `rmdir victimdir` | `rmdir victimdir` | No stdin; named fixtures / arguments | 113 | 5.591 | 108.131 | 90.280 | 0.06× | 7 |
| <a id="case-rsync-rsh-shim"></a>rsync-rsh-shim | `rsync -a -e ./rshshim text :rdest/` | `rsync -a -e ./rshshim text :rdest/` | No stdin; named fixtures / arguments | 11 | 83.694 | — | 510.283 | 0.16× | 7 |
| <a id="case-scm-recv-fd"></a>scm-recv-fd | `scm recv-fd 4 --token tok --fd-socket` | `scm recv-fd 4 --token tok --fd-socket` | No stdin; named fixtures / arguments | 140 | 7.274 | — | — | — | 7 |
| <a id="case-scp-openssh-get"></a>scp-openssh-get | `scp --openssh example.test:remote copyout` | `scp --openssh example.test:remote copyout` | No stdin; named fixtures / arguments | 11 | 79.594 | — | — | — | 7 |
| <a id="case-screen"></a>screen | `screen remote-frame decode` | `screen remote-frame decode` | screenframe (423,010 stdin bytes) | 35 | 48.750 | — | — | — | 7 |
| <a id="case-script"></a>script | `script replay scripttiming scriptlog` | `scriptreplay -t scripttiming -O scriptlog` | No stdin; named fixtures / arguments | 121 | 15.221 | — | 96.830 | 0.16× | 7 |
| <a id="case-scrub"></a>scrub | `scrub scrub-current history` | `scrub scrub-current history` | No stdin; named fixtures / arguments | 14 | 70.278 | — | — | — | 7 |
| <a id="case-sed"></a>sed | `sed s/alpha/OMEGA/g` | `sed s/alpha/OMEGA/g` | text (423,000 stdin bytes) | 8 | 60.450 | 72.189 | 50.711 | 1.19× | 7 |
| <a id="case-seq"></a>seq | `seq 100000` | `seq 100000` | No stdin; named fixtures / arguments | 42 | 58.058 | 1453.282 | 58.236 | 1.00× | 7 |
| <a id="case-setfacl"></a>setfacl | `setfacl -m u:1000:rwx,g:1000:r-x aclset/f00 aclset/f01 aclset/f02 aclset/f03 aclset/f04 aclset/f05 aclset/f06 aclset/f07 aclset/f08 aclset/f09 aclset/f10 aclset/f11 aclset/f12 aclset/f13 aclset/f14 aclset/f15 aclset/f16 aclset/f17 aclset/f18 aclset/f19 aclset/f20 aclset/f21 aclset/f22 aclset/f23 aclset/f24 aclset/f25 aclset/f26 aclset/f27 aclset/f28 aclset/f29 aclset/f30 aclset/f31` | `setfacl -m u:1000:rwx,g:1000:r-x aclset/f00 aclset/f01 aclset/f02 aclset/f03 aclset/f04 aclset/f05 aclset/f06 aclset/f07 aclset/f08 aclset/f09 aclset/f10 aclset/f11 aclset/f12 aclset/f13 aclset/f14 aclset/f15 aclset/f16 aclset/f17 aclset/f18 aclset/f19 aclset/f20 aclset/f21 aclset/f22 aclset/f23 aclset/f24 aclset/f25 aclset/f26 aclset/f27 aclset/f28 aclset/f29 aclset/f30 aclset/f31` | No stdin; named fixtures / arguments | 106 | 16.312 | — | — | — | 7 |
| <a id="case-setsid"></a>setsid | `setsid /bin/true` | `setsid /bin/true` | No stdin; named fixtures / arguments | 76 | 41.821 | 78.786 | 66.349 | 0.63× | 7 |
| <a id="case-sftp-openssh-get"></a>sftp-openssh-get | `sftp --openssh example.test` | `sftp --openssh example.test` | sftpbatch (19 stdin bytes) | 10 | 71.368 | — | — | — | 7 |
| <a id="case-signal"></a>signal | `signal -n TERM` | `kill -l TERM` | No stdin; named fixtures / arguments | 123 | 4.125 | 93.663 | 75.454 | 0.05× | 7 |
| <a id="case-signal-name"></a>signal-name | `signal -s 15` | `kill -l 15` | No stdin; named fixtures / arguments | 129 | 3.843 | 91.881 | 70.773 | 0.05× | 7 |
| <a id="case-sixel"></a>sixel | `sixel -w 200 -H 200 image.png` | `sixel -w 200 -H 200 image.png` | No stdin; named fixtures / arguments | 17 | 66.926 | — | — | — | 7 |
| <a id="case-slabtop-procfixture"></a>slabtop-procfixture | `slabtop -o` | `slabtop -o` | No stdin; named fixtures / arguments | 43 | 45.530 | — | — | — | 7 |
| <a id="case-sleep"></a>sleep | `sleep 0` | `sleep 0` | No stdin; named fixtures / arguments | 73 | 7.296 | 57.680 | 50.605 | 0.14× | 7 |
| <a id="case-sort-numeric"></a>sort-numeric | `sort -n` | `sort -n` | numbers (369,296 stdin bytes) | 6 | 80.123 | 629.639 | 159.788 | 0.50× | 7 |
| <a id="case-sort-text"></a>sort-text | `sort` | `sort` | text (423,000 stdin bytes) | 24 | 65.850 | 159.089 | 72.353 | 0.91× | 7 |
| <a id="case-split"></a>split | `split -l 1000 text` | `split -l 1000 text` | No stdin; named fixtures / arguments | 75 | 39.089 | — | 79.789 | 0.49× | 7 |
| <a id="case-sqlite-step-aggregate"></a>sqlite-step-aggregate | `sqlite step T0g2` | `sqlite step T0g2` | No stdin; named fixtures / arguments | 8 | 71.464 | — | — | — | 7 |
| <a id="case-ssh-known-hosts-list"></a>ssh-known-hosts-list | `ssh known-hosts list needle.fixture.test` | `ssh-keygen -q -F needle.fixture.test -f knownhosts` | No stdin; named fixtures / arguments | 3 | 85.527 | — | 157.368 | 0.54× | 7 |
| <a id="case-sshd-sessions"></a>sshd-sessions | `sshd sessions` | `sshd sessions` | No stdin; named fixtures / arguments | 22 | 48.869 | — | — | — | 7 |
| <a id="case-stat"></a>stat | `stat -c %s text` | `stat -c %s text` | No stdin; named fixtures / arguments | 111 | 3.734 | 84.927 | 88.969 | 0.04× | 7 |
| <a id="case-strace-summary"></a>strace-summary | `strace -c -o strace.out -- /bin/true` | `strace -c -o strace.out -- /bin/true` | No stdin; named fixtures / arguments | 20 | 21.439 | — | — | — | 7 |
| <a id="case-strftime"></a>strftime | `strftime %Y-%m-%d 0` | `date -u -d @0 +%Y-%m-%d` | No stdin; named fixtures / arguments | 127 | 3.884 | 95.763 | 77.586 | 0.05× | 7 |
| <a id="case-strings"></a>strings | `strings -n 4` | `strings -n 4` | bytes (65,536 stdin bytes) | 80 | 31.086 | 89.794 | 135.007 | 0.23× | 7 |
| <a id="case-strptime"></a>strptime | `strptime '1970-01-01 00:00:00' '%Y-%m-%d %H:%M:%S'` | `date -u -d '1970-01-01 00:00:00' +%s` | No stdin; named fixtures / arguments | 99 | 6.371 | 100.038 | 81.646 | 0.08× | 7 |
| <a id="case-sv-log"></a>sv-log | `sv log fixture -n 200` | `tail -n 200 svlog/fixture` | No stdin; named fixtures / arguments | 29 | 70.040 | 170.369 | 20.870 | 3.36× | 7 |
| <a id="case-swapon"></a>swapon | `swapon -s` | `swapon -s` | No stdin; named fixtures / arguments | 133 | 4.965 | ERROR | 158.530 | 0.03× | 7 |
| <a id="case-sync"></a>sync | `sync` | `sync` | No stdin; named fixtures / arguments | 20 | 6.060 | 26.317 | 19.704 | 0.31× | 7 |
| <a id="case-sysctl"></a>sysctl | `sysctl -n kernel.osrelease` | `sysctl -n kernel.osrelease` | No stdin; named fixtures / arguments | 132 | 5.243 | 104.840 | 82.706 | 0.06× | 7 |
| <a id="case-tac"></a>tac | `tac` | `tac` | text (423,000 stdin bytes) | 63 | 12.658 | 297.716 | 62.572 | 0.20× | 7 |
| <a id="case-tail"></a>tail | `tail -n 100` | `tail -n 100` | text (423,000 stdin bytes) | 80 | 5.086 | 130.316 | 48.358 | 0.11× | 7 |
| <a id="case-taskset"></a>taskset | `taskset -p 1` | `taskset -p 1` | No stdin; named fixtures / arguments | 112 | 3.885 | 81.463 | 68.646 | 0.06× | 7 |
| <a id="case-tee"></a>tee | `tee` | `tee` | text (423,000 stdin bytes) | 80 | 9.377 | 109.351 | 71.588 | 0.13× | 7 |
| <a id="case-termpixel"></a>termpixel | `termpixel render-demo -w 400 -H 200` | `termpixel render-demo -w 400 -H 200` | No stdin; named fixtures / arguments | 40 | 14.138 | — | — | — | 7 |
| <a id="case-termpixel_pong"></a>termpixel_pong | `termpixel_pong --dump-frame` | `termpixel_pong --dump-frame` | No stdin; named fixtures / arguments | 128 | 9.831 | — | — | — | 7 |
| <a id="case-timeout"></a>timeout | `timeout 1 /bin/true` | `timeout 1 /bin/true` | No stdin; named fixtures / arguments | 71 | 42.515 | 96.238 | 77.952 | 0.55× | 7 |
| <a id="case-tinfo"></a>tinfo | `tinfo getnum cols` | `tput cols` | No stdin; named fixtures / arguments | 149 | 4.743 | — | 115.249 | 0.04× | 7 |
| <a id="case-tiv"></a>tiv | `tiv -w 100 -H 50 -m rgb image.png` | `tiv -w 100 -H 50 -m rgb image.png` | No stdin; named fixtures / arguments | 22 | 64.860 | — | — | — | 7 |
| <a id="case-tiv-oct256"></a>tiv-oct256 | `tiv -w 100 -H 50 -m 256 -g oct image.png` | `tiv -w 100 -H 50 -m 256 -g oct image.png` | No stdin; named fixtures / arguments | 18 | 72.159 | — | — | — | 7 |
| <a id="case-toml-emit"></a>toml-emit | `toml emit config.toml` | `toml emit config.toml` | No stdin; named fixtures / arguments | 8 | 75.296 | — | — | — | 7 |
| <a id="case-totp-generate"></a>totp-generate | `totp generate -k GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ -t 1234567890 -d 8 -a sha512` | `totp generate -k GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ -t 1234567890 -d 8 -a sha512` | No stdin; named fixtures / arguments | 28 | 69.106 | — | — | — | 7 |
| <a id="case-touch"></a>touch | `touch touched` | `touch touched` | No stdin; named fixtures / arguments | 141 | 3.790 | 106.752 | 85.989 | 0.04× | 7 |
| <a id="case-tput"></a>tput | `tput cols` | `tput cols` | No stdin; named fixtures / arguments | 87 | 3.828 | — | 72.676 | 0.05× | 7 |
| <a id="case-tput-lines"></a>tput-lines | `tput lines` | `tput lines` | No stdin; named fixtures / arguments | 135 | 4.574 | — | 106.256 | 0.04× | 7 |
| <a id="case-tr"></a>tr | `tr a-z A-Z` | `tr a-z A-Z` | text (423,000 stdin bytes) | 65 | 51.589 | 96.332 | 56.872 | 0.91× | 7 |
| <a id="case-truncate"></a>truncate | `truncate -s 4096 truncout` | `truncate -s 4096 truncout` | No stdin; named fixtures / arguments | 113 | 4.111 | 79.522 | 70.703 | 0.06× | 7 |
| <a id="case-ts-parse"></a>ts-parse | `ts parse -L json` | `ts parse -L json` | array (39,109 stdin bytes) | 5 | 92.345 | — | — | — | 7 |
| <a id="case-ts-query"></a>ts-query | `ts query -L json -q '(pair key: (_) @key) (number) @num (string) @str'` | `ts query -L json -q '(pair key: (_) @key) (number) @num (string) @str'` | object (39,133 stdin bytes) | 3 | 103.014 | — | — | — | 7 |
| <a id="case-tty"></a>tty | `tty` | `tty` | ptmx (0 stdin bytes) | 104 | 7.886 | 108.412 | 89.124 | 0.09× | 7 |
| <a id="case-tz"></a>tz | `tz convert 0 -z UTC` | `date -u -d @0 '+%Y-%m-%d %H:%M:%S UTC +0000'` | No stdin; named fixtures / arguments | 127 | 3.934 | 97.291 | 76.610 | 0.05× | 7 |
| <a id="case-uclampset"></a>uclampset | `uclampset -p 1` | `uclampset -p 1` | No stdin; named fixtures / arguments | 136 | 4.706 | — | 83.286 | 0.06× | 7 |
| <a id="case-uname"></a>uname | `uname` | `uname` | No stdin; named fixtures / arguments | 128 | 4.114 | 97.679 | 74.580 | 0.06× | 7 |
| <a id="case-uname-s"></a>uname-s | `uname -s` | `uname -s` | No stdin; named fixtures / arguments | 120 | 4.157 | 84.628 | 71.632 | 0.06× | 7 |
| <a id="case-undo-composite-group"></a>undo-composite-group | `undo undo 0` | `undo undo 0` | No stdin; named fixtures / arguments | 4 | 93.490 | — | — | — | 7 |
| <a id="case-unexpand"></a>unexpand | `unexpand -a` | `unexpand -a` | spaces (440,000 stdin bytes) | 9 | 77.234 | 98.328 | 38.787 | 1.99× | 7 |
| <a id="case-uniq"></a>uniq | `uniq` | `uniq` | duplicates (1,680,000 stdin bytes) | 19 | 75.157 | 430.537 | 88.138 | 0.85× | 7 |
| <a id="case-unlink"></a>unlink | `unlink victim` | `unlink victim` | No stdin; named fixtures / arguments | 120 | 6.687 | 115.302 | 98.092 | 0.07× | 7 |
| <a id="case-uptime"></a>uptime | `uptime -s` | `uptime -s` | No stdin; named fixtures / arguments | 108 | 8.099 | INVALID | 123.802 | 0.07× | 7 |
| <a id="case-userdb-lookup"></a>userdb-lookup | `userdb lookup benchuser -V REC` | `userdb lookup benchuser -V REC` | No stdin; named fixtures / arguments | 58 | 43.921 | — | — | — | 7 |
| <a id="case-utf8-length-grapheme"></a>utf8-length-grapheme | `utf8 length 'Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 ' -T grapheme` | `utf8 length 'Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 ' -T grapheme` | No stdin; named fixtures / arguments | 128 | 10.202 | — | — | — | 7 |
| <a id="case-utf8-normalize-nfd"></a>utf8-normalize-nfd | `utf8 normalize NFD 'Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 '` | `utf8 normalize NFD 'Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 '` | No stdin; named fixtures / arguments | 117 | 11.483 | — | — | — | 7 |
| <a id="case-utmp-dump"></a>utmp-dump | `utmp dump utmpfix` | `utmp dump utmpfix` | No stdin; named fixtures / arguments | 10 | 66.585 | — | — | — | 7 |
| <a id="case-uudecode"></a>uudecode | `uudecode -o -` | `uudecode -o -` | uuencoded (90,320 stdin bytes) | 59 | 36.842 | 100.351 | — | — | 7 |
| <a id="case-uuencode"></a>uuencode | `uuencode bytes` | `uuencode bytes` | bytes (65,536 stdin bytes) | 51 | 52.132 | 101.080 | — | — | 7 |
| <a id="case-uuencode-base64"></a>uuencode-base64 | `uuencode -m bytes` | `uuencode -m bytes` | bytes (65,536 stdin bytes) | 48 | 48.366 | 90.296 | — | — | 7 |
| <a id="case-uuidgen-v3-md5"></a>uuidgen-v3-md5 | `uuidgen -m -n @dns -N example.com -C 20000` | `uuidgen -m -n @dns -N example.com -C 20000` | No stdin; named fixtures / arguments | 4 | 80.899 | — | — | — | 7 |
| <a id="case-uuidgen-v5-sha1"></a>uuidgen-v5-sha1 | `uuidgen -s -n @dns -N example.com -C 20000` | `uuidgen -s -n @dns -N example.com -C 20000` | No stdin; named fixtures / arguments | 4 | 85.078 | — | — | — | 7 |
| <a id="case-vec-dot"></a>vec-dot | `vec dot 0 0` | `vec dot 0 0` | No stdin; named fixtures / arguments | 8 | 65.339 | — | — | — | 7 |
| <a id="case-vec-sum"></a>vec-sum | `vec sum 0` | `vec sum 0` | No stdin; named fixtures / arguments | 48 | 41.506 | — | — | — | 7 |
| <a id="case-vi-keys"></a>vi-keys | `vi --keys vikeys left` | `vi --keys vikeys left` | No stdin; named fixtures / arguments | 3 | 351.232 | — | — | — | 7 |
| <a id="case-vi-write"></a>vi-write | `vi -c 'w viout' -c 'q!' duplicates` | `vi -u NONE -i NONE -n --headless -c 'w! viout' -c 'q!' duplicates` | No stdin; named fixtures / arguments | 19 | 72.150 | — | 364.084 | 0.20× | 7 |
| <a id="case-vmstat-diskstats"></a>vmstat-diskstats | `vmstat -d` | `vmstat -d` | No stdin; named fixtures / arguments | 79 | 37.667 | — | — | — | 7 |
| <a id="case-vt"></a>vt | `vt render 0 -A` | `vt render 0 -A` | No stdin; named fixtures / arguments | 6 | 97.209 | — | — | — | 7 |
| <a id="case-w-utmpfixture"></a>w-utmpfixture | `w utmpfix` | `w utmpfix` | No stdin; named fixtures / arguments | 5 | 73.105 | — | — | — | 7 |
| <a id="case-wall"></a>wall | `wall` | `wall` | bytes (65,536 stdin bytes) | 10 | 74.486 | — | — | — | 7 |
| <a id="case-watch"></a>watch | `watch -n 0.001 -g -d 'cat left; printf X >> wmark; cat wmark'` | `watch -n 0.001 -g -d 'cat left; printf X >> wmark; cat wmark'` | No stdin; named fixtures / arguments | 3 | 122.955 | — | — | — | 7 |
| <a id="case-wc-characters"></a>wc-characters | `wc -m` | `wc -m` | text (423,000 stdin bytes) | 42 | 50.015 | 130.113 | 31.315 | 1.60× | 7 |
| <a id="case-wc-counts"></a>wc-counts | `wc -lwc` | `wc -lwc` | text (423,000 stdin bytes) | 39 | 54.895 | 122.821 | 70.415 | 0.78× | 7 |
| <a id="case-wc-width"></a>wc-width | `wc -L` | `wc -L` | text (423,000 stdin bytes) | 48 | 57.367 | 149.467 | 90.261 | 0.64× | 7 |
| <a id="case-wg-pubkey"></a>wg-pubkey | `wg pubkey` | `wg pubkey` | wgkey (45 stdin bytes) | 178 | 13.683 | — | — | — | 7 |
| <a id="case-wg-setconf-dryrun"></a>wg-setconf-dryrun | `wg setconf wg0 wgconf` | `wg setconf wg0 wgconf` | No stdin; named fixtures / arguments | 96 | 15.820 | — | — | — | 7 |
| <a id="case-wget_wch"></a>wget_wch | `wget_wch decode 65cc80cc81cc82cc83cc84cc85cc86cc87cc88cc89cc8acc8bcc8ccc8dcc8e` | `wget_wch decode 65cc80cc81cc82cc83cc84cc85cc86cc87cc88cc89cc8acc8bcc8ccc8dcc8e` | No stdin; named fixtures / arguments | 114 | 5.059 | — | — | — | 7 |
| <a id="case-wgetch"></a>wgetch | `wgetch read 0` | `wgetch read 0` | keyseq (12,288 stdin bytes) | 200 | 5.935 | — | — | — | 7 |
| <a id="case-whatis"></a>whatis | `whatis tool00001 tool02500 tool05000 tool07500 tool10000 tool12500 tool15000 tool19999` | `whatis tool00001 tool02500 tool05000 tool07500 tool10000 tool12500 tool15000 tool19999` | No stdin; named fixtures / arguments | 8 | 69.855 | — | 318.006 | 0.22× | 7 |
| <a id="case-whiptail"></a>whiptail | `whiptail --output-fd 1 --notags --checklist pick 20 60 10 alpha Apple off beta Banana off gamma Grape off delta Damson off` | `whiptail --output-fd 1 --notags --checklist pick 20 60 10 alpha Apple off beta Banana off gamma Grape off delta Damson off` | dialogtags (85,000 stdin bytes) | 3 | 78.187 | — | — | — | 7 |
| <a id="case-who-quick"></a>who-quick | `who -q utmpfix` | `who -q utmpfix` | No stdin; named fixtures / arguments | 37 | 64.049 | ERROR | 363.221 | 0.18× | 7 |
| <a id="case-whoami"></a>whoami | `whoami` | `whoami` | No stdin; named fixtures / arguments | 130 | 4.025 | 102.466 | 86.040 | 0.05× | 7 |
| <a id="case-wipefs"></a>wipefs | `wipefs -n swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img` | `wipefs -n -O OFFSET,TYPE,DEVICE -i swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img swapsig.img` | No stdin; named fixtures / arguments | 99 | 21.150 | — | 1379.523 | 0.02× | 7 |
| <a id="case-write"></a>write | `write tty0` | `write tty0` | bytes (65,536 stdin bytes) | 25 | 50.224 | — | — | — | 7 |
| <a id="case-xargs"></a>xargs | `xargs -n 10 /bin/echo` | `xargs -n 10 /bin/echo` | left (120,000 stdin bytes) | 3 | 2991.690 | 1954.000 | 2684.932 | 1.11× | 7 |
| <a id="case-xattr-list"></a>xattr-list | `xattr list xattrs` | `xattr list xattrs` | No stdin; named fixtures / arguments | 141 | 6.451 | — | — | — | 7 |
| <a id="case-xattr-read"></a>xattr-read | `xattr read xattrs user.big` | `xattr read xattrs user.big` | No stdin; named fixtures / arguments | 119 | 4.691 | — | — | — | 7 |
| <a id="case-zcat"></a>zcat | `zcat text.gz` | `zcat text.gz` | No stdin; named fixtures / arguments | 52 | 56.812 | 171.397 | ERROR | — | 7 |
| <a id="case-zlib"></a>zlib | `zlib -f gzip text.gz` | `gzip -dc text.gz` | No stdin; named fixtures / arguments | 39 | 38.935 | 120.232 | 94.252 | 0.41× | 7 |
| <a id="case-zlib-bzip2"></a>zlib-bzip2 | `zlib -f bzip2 text.bz2` | `bzip2 -dc text.bz2` | No stdin; named fixtures / arguments | 7 | 88.246 | 101.960 | 94.144 | 0.94× | 7 |
| <a id="case-zlib-xz"></a>zlib-xz | `zlib -f xz text.xz` | `xz -dc text.xz` | No stdin; named fixtures / arguments | 25 | 44.667 | 117.806 | 66.567 | 0.67× | 7 |
| <a id="case-zstd-decompress"></a>zstd-decompress | `zstd -d -c text.zst` | `zstd -d -c text.zst` | No stdin; named fixtures / arguments | 56 | 50.259 | — | 123.087 | 0.41× | 7 |
| <a id="case-zstdcat"></a>zstdcat | `zstdcat text.zst` | `zstdcat text.zst` | No stdin; named fixtures / arguments | 56 | 52.119 | — | 121.452 | 0.43× | 7 |
<!-- END CASES -->

## Method and limits

<!-- BEGIN METHOD -->
The command measurements use the native dynamic full `out/bash` at the source above, SHA-256 `94608b7f130d5bf76b1ddab3dc992bf1529a9a712d9587abd76cc3ecb07402ff`. Host: Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz, x86_64 Linux 6.12.96+deb13-amd64; pinned CPUs: 11. Reference versions and fixture hashes are recorded in the measurement JSON. These are host measurements; no per-command RISC-V or appliance performance is claimed.

Every case uses 7 timed samples after output validation and warm-up. The one-minute host load was 4.2 at the start and 4.4 at the end. A shared lock serialized participating benchmarks; builds and other host activity could still contend. Use the recorded ranges for prioritization and repeat on the intended device before claiming small performance differences.
<!-- END METHOD -->

[The harness](../bench/loadables.py) runs all variants from the **same bash-os
shell** with startup files disabled, `LC_ALL=C`, `TZ=UTC` and an empty `PATH`.
The builtin uses its name; external programs and BusyBox use absolute paths.
Each invocation reopens the fixture on stdin. Timings include one shell startup,
the loop, redirections and external fork/exec costs. They are deployment costs
for this calling pattern, not pure algorithm throughput. The separate
[whole-script benchmarks](../bench/README.md) also vary the shell; their totals
cannot be assigned to an individual loadable.

Each variant must match a successful reference once and over a complete batch
before it is timed. Most comparisons are byte-for-byte. `find` sorts output
lines, `wc-counts` compares whitespace-separated fields, and `crypto` compares
digest fields without filenames. Those normalizations intentionally do not
establish identical formatting. `cp` checks destination bytes as well as exit
status. Exit status must remain successful during timed runs; successful timing
does not cover error handling, signals, every CLI option or all shell state.

Implementation order rotates and reverses across samples; output goes to
`/dev/null`. Pass counts calibrate toward a roughly 75 ms batch, subject to a
cap, and are identical across implementations within each case. Every row
comes from the current integrated build. Before/after studies in the dedicated
command documents use their own matched fixtures and fixed pass counts.

Fixtures use seed `20260908`. `text` is 423,000 bytes of ASCII words, truncated
without a final newline; `numbers` has 50,000 signed integers; `duplicates` has
120,000 records in groups of three. `left` and `right` have 10,000 and 5,000 sorted
keys; `tabs` and `spaces` have 20,000 lines each. `bytes` contains 65,536 bytes
cycling through 0–255; `blob` is 1 MiB. The tree has 256 small files. JSON and awk
fixtures contain 10,000 and 20,000 entries respectively. The arithmetic fixture
is `scale=20; sqrt(2)`. Exact generation and fixture hashes are recorded in the
harness and JSON. `cp` overwrites a temporary copy, `diff`/`cmp` compare identical
files, and `ls`/`find` scan the temporary tree: none establishes all filesystem
behavior or cold-storage performance.

## Graphics metrics

`gpu` has no equivalent BusyBox applet. This separate measurement uses
[bench/gpu.py](../bench/gpu.py), a private Python protocol peer, a 640×360 canvas
and 30 updates. Five runs per mode were taken on the historical native binary identified
below; these runs were not pinned to a CPU. Byte counts exclude the initial presentation.
They can vary slightly with protocol identifiers; the JSON records their ranges.

<!-- BEGIN GPU -->
Historical graphics measurement source: `af3c8c488d6b4d81025a5feab4d04f8ee5e402f5`; binary SHA-256 `ade3e597987655c3831ab00870bae58c49c4137e993b636d6c5776625380c650`. These transport timings were not rerun with the current command measurements.

| Transport / change | Median TTY bytes / 30 updates | Median TTY bytes / update | Median seconds | Min–max seconds |
| --- | --- | --- | --- | --- |
| inline / full | 36,984,690 | 1,232,823 | 0.300 | 0.267–0.331 |
| shm / full | 5,430 | 181 | 0.064 | 0.051–0.093 |
| inline / patch | 2,520 | 84 | 0.046 | 0.034–0.054 |
| shm / scroll | 235,380 | 7,846 | 0.069 | 0.065–0.077 |
<!-- END GPU -->

Shared-memory TTY counts omit pixel bytes written to shared memory. The small
patch case changes one pixel per update, while the full cases replace the whole
canvas: their workloads differ. Wall time includes startup, setup and the Python
peer. It is not display latency, GPU shader throughput or a BusyBox speedup.
Next graphics work should measure a real application's frame latency, memory
traffic and driver behavior on the intended device. See [graphics](gpu.md) for
CPU/static, driver and transport support.

## Refreshing the table

```bash
python3 bench/loadables.py --binary out/bash --runs 7 --output /tmp/loadables.json
python3 bench/loadables.py --only fold --passes 9 --runs 7 --output /tmp/fold.json
python3 bench/catalog.py
python3 bench/catalog.py --check
```

Choose an allowed CPU with `--cpu N` when comparing new results. Keep raw run
logs outside Git. Review changed coverage in [loadables-review.json](loadables-review.json)
and copy only sanitized summary fields into
[data/loadable-benchmarks-current.json](data/loadable-benchmarks-current.json).
Keep the original snapshot and graphics provenance unchanged. Record the actual
binary hash, source commit, fixture hashes, reference versions, case arguments,
pass counts, sample counts, validation status and timing ranges. Never copy a
failed validation's timing into a passing result. Update this date and method
when changing the measurement, then regenerate the Markdown and CSV together.

Record separate correctness probes in [loadable-untimed-findings.json](data/loadable-untimed-findings.json). Keep their binary hash matched to the measured build; clear a finding only after the integrated implementation passes its regression.

The generator checks exact catalog membership, source coverage, profiles,
evidence paths and measurement consistency. It does not run the benchmark or
prove that a reviewed fixture covers all paths. Adding a new loadable requires
refreshing the reviewed catalog hash; the check deliberately fails until that
snapshot is reviewed.
