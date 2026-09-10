# Loadable status and benchmark work queue

The [PTY broker and live-pane changes](ptybroker.md) have dedicated lifecycle
and binary-I/O regression suites. The measurements and classifications in
this earlier review snapshot predate those changes.

The repeated-input fixes for `head`, `sed`, `bc`, `nl` and `pr` are integrated
with the `fold`, `expand` and `tac` improvements. The remaining confirmed input
failures lead the queue below. Completed worker changes stay marked as pending
integration until they are included in the measured build.

This is the **2026-09-08** review of the complete
[build catalog](../config/bash-loadables.list). The
[CSV](loadables-status.csv) has one row per loadable for filtering by profile,
status, priority, counterpart and measurement. The
[current measurement summary](data/loadable-benchmarks-current.json) retains
fixture hashes, sample counts and timing ranges. The
[original snapshot](data/loadable-benchmarks.json) remains available for
historical comparison; its batch sizes and host conditions differ.

Dedicated scope, regression and benchmark reports cover
[head and sed](head-sed.md), [fold](fold.md), [expand](expand.md), [bc](bc.md),
[nl](nl.md), [pr](pr.md), [tac](tac.md) and [zstd](zstd.md). A corrected invalid baseline is not
reported as a speedup. Raw run logs stay outside the repository.

The seven-reader integration (`column`, `colrm`, `col`, `strings`, `od`,
`hexdump` and `comm`) has completed review at `c3c8e0e48e38`: 8,664 native
and 8,660 static parity checks passed, along with all seven native sanitizer
suites. The coordinator independently verified 162 native and 141 static
reader-state checks. This series is prepared on the combined review branch;
publication and measurements await the remaining integration groups.

The second seven-command integration remains in review: its loader/primer
checks and old-reference word-count comparisons need correction, and `join`
must stop reading after a write failure. The crypto/diff/tee candidate fixes
the three earlier diff integration defects; 173 native and 173 static regression
checks passed independently. Review found two further contracts to fix:
`diff - -` must compare the same input correctly, and `tee` must stop reading
when every output has failed.

In the next batch, `du` and `mv` have passed review. `tail` needs allocation-failure and
output-error fixes; `ar` needs extraction cleanup, archive-link handling and
test corrections. These candidate findings are separate from the older
measured-build findings below. `truncate` now leads new work after an untimed
check showed that a size overflow can empty an existing file. `cp` is also
assigned: a forced copy can delete the old destination when its source cannot
be read.

<!-- BEGIN SUMMARY -->
Catalog: **279 loadables** (248 local sources, 31 stock Bash sources). Command benchmark: **55 cases covering 51 loadables**; 46 loadables passed the selected output checks, 5 have confirmed correctness findings. The other 228 have no individual command timings here; GPU transport measurements are reported separately.

Separate [untimed checks](#additional-correctness-checks) record 12 further correctness findings.

| Profile | Included loadables |
| --- | --- |
| shell | 0 |
| pure | 28 |
| core | 89 |
| device | 160 |
| server | 214 |
| desktop | 155 |
| full | 279 |

Command measurement source: `97284d62efcf57067557540861b6a81577b841c6`. The integrated tests/run.sh passed all 69 groups, including native dynamic/static builds and seven focused ASan/UBSan suites. An additional 156 mixed-input and descriptor-ownership checks passed on native dynamic, native static and RISC-V musl static builds. The local RISC-V selection was core plus bc (90 loadables); broader new-option and Unicode cross parity is not claimed.

[CI at 5fde494](https://github.com/itsmygithubacct/bash-os/actions/runs/34214029478) passed all nine jobs, including 70 native test groups. The nl suite passed all 1,556 reference and contract checks against GNU 9.4 on native, static and ASan/UBSan paths; the six benchmark-producer regressions passed too. This CI covers the published implementation before the pending integration batch.

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
| P1 | ar | A truncated member header is incorrectly accepted as a valid archive. Untimed check. | Fix extraction descriptor cleanup and archive-link update behavior; complete the bounds and test follow-up before next-batch integration. Assigned to bash-os-4 (review follow-up). |
| P1 | col | Only the first invocation emits input. Untimed check. | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| P1 | colrm | Repeated redirected input fails output validation. | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| P1 | column | Repeated redirected input fails output validation. | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| P1 | cp | An unreadable source causes forced copy to delete the existing destination before failing. Untimed check. | Preserve the existing destination when a forced copy cannot read its source; establish dedicated copy, link, metadata and failure-recovery coverage. Assigned to bash-os-3. |
| P1 | crypto | A failed digest write is incorrectly reported as successful. Untimed check. | Complete the three-command integration review, then validate the combined build; investigate backend cost separately. Assigned to bash-os-2 (review follow-up). |
| P1 | csplit | Later invocations create empty pieces after the first call exhausts shared stdin. Untimed check. | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| P1 | diff | Files differing only in the final newline are incorrectly reported equal. Untimed check. | Fix comparison of two stdin operands, then complete the integration and combined-build validation. Assigned to bash-os-2 (review follow-up). |
| P1 | du | A failed size-report write is incorrectly reported as successful. Untimed check. | Integrate the reviewed traversal, allocation and output-error fixes in the next batch, then validate and remeasure. Assigned to coordinator (next batch). |
| P1 | hexdump | Repeated redirected input fails output validation. | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| P1 | mv | Moving a file to itself incorrectly reports success. Untimed check. | Integrate the reviewed same-file and staged cross-device fixes in the next batch, then validate and remeasure. Assigned to coordinator (next batch). |
| P1 | od | Repeated redirected input fails output validation. | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| P1 | split | Only the first invocation creates output files. Untimed check. | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| P1 | strings | Repeated redirected input fails output validation. | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| P1 | tail | Only the first small-input invocation emits its last line; the larger timed fixture passes. Untimed check. | Fix the reviewed candidate's allocation-failure use-after-free and output-error hang; require valid native/static test boundaries before integration. Assigned to bash-os-6 (review follow-up). |
| P1 | tee | A read from closed stdin reports an error but incorrectly returns success. Untimed check. | Stop reading when every output has failed, preserving healthy destinations and interrupt cleanup; then validate the combined build. Assigned to bash-os-2 (review follow-up). |
| P1 | truncate | An overflowing size extension incorrectly succeeds and empties the existing file. Untimed check. | Reject size arithmetic overflow while preserving existing data; establish dedicated size, reference, I/O-error and recovery coverage before timing. Assigned to bash-os-1. |
| P2 | [comm](#case-comm) | 1.82× external time; output checks pass, seven samples. | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| P2 | [sort-text](#case-sort-text) | 1.70× external time; 1.01× BusyBox time; output checks pass, seven samples. | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| P3 | join | Completed worker result; current timings still describe the earlier implementation. | Stop on write failure before reading more input; complete bounds and cleanup review, then validate the combined build. Assigned to bash-os-5 (review follow-up). |
| P3 | rev | Completed worker result; current timings still describe the earlier implementation. | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| P3 | unexpand | Completed worker result; current timings still describe the earlier implementation. | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| P3 | wc | Completed worker result; current timings still describe the earlier implementation. | Keep every requested word-count assertion across GNU versions, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
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
- `*` marks a stock source from Bash's `examples/loadables/`; other names link
  to local sources. See [provenance](PROVENANCE.md). Helpers, aliases and
  dispatcher subcommands are not additional catalog entries.

## All loadables

<!-- BEGIN CATALOG -->
| Loadable | Profiles | Status / evidence | Targets: BB; external | Batch ms: BOS / BB / external | Work | Next work |
| --- | --- | --- | --- | --- | --- | --- |
| [`acme`](../loadables/acme.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; certbot / acme.sh | N/M | P3 | Add a matched workload and timing. |
| [`apropos`](../loadables/apropos.c) | T F | [Contract](../tests/misc-smoke.py) | —; apropos | N/M | P3 | Add a matched workload and timing. |
| [`ar`](../loadables/ar.c) | C D S T F | [Correctness bug](#additional-correctness-checks) | ar; ar | N/M | P1 | Fix extraction descriptor cleanup and archive-link update behavior; complete the bounds and test follow-up before next-batch integration. Assigned to bash-os-4 (review follow-up). |
| `asort`* | F | [Contract](../tests/misc-smoke.py) | —; gawk asort() | N/M | P3 | Add a matched workload and timing. |
| [`at`](../loadables/at.c) | S F | [Contract](../tests/misc-smoke.py) | —; at (missing) | N/M | P3 | Add a matched workload and timing. |
| [`audit`](../loadables/audit.c) | S F | [Contract](../tests/network-smoke.py) | —; auditctl / ausearch | N/M | P3 | Add a matched workload and timing. |
| [`auth`](../loadables/auth.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`awk`](../loadables/awk.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | awk; awk | 81.469 / 156.228 / 87.363; [awk](#case-awk), 7 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `basename`* | P C D S T F | [Contract](../tests/host-smoke.sh) | basename; basename | 5.845 / 102.123 / 103.101; [basename](#case-basename), 61 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashbase64`](../loadables/bashbase64.c) | D S F | [Bench checked](#case-bashbase64) | base64; base64 | 16.357 / 199.209 / 160.052; [bashbase64](#case-bashbase64), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashclock`](../loadables/bashclock.c) | D S F | Build/help | —; Bash EPOCHREALTIME / Python time | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashdhcp`](../loadables/bashdhcp.c) | D S F | Build/help | udhcpc; dhclient / udhcpc | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashinotify`](../loadables/bashinotify.c) | D S F | Build/help | inotifyd (not in build); inotifywait (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashio`](../loadables/bashio.c) | D S F | Build/help | —; Python os.pread/os.pwrite | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashjson`](../loadables/bashjson.c) | D S F | [Bench checked](#case-bashjson) | —; jq | 41.327 / — / 318.365; [bashjson](#case-bashjson), 34 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashkmod`](../loadables/bashkmod.c) | D S F | Build/help | modprobe; modprobe / insmod / rmmod | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashlogger`](../loadables/bashlogger.c) | D S F | Build/help | logger; logger | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashmount`](../loadables/bashmount.c) | D S F | Build/help | mount; mount / umount / findmnt | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashpoll`](../loadables/bashpoll.c) | D S T F | Build/help | —; Python selectors / socket | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashsyslogd`](../loadables/bashsyslogd.c) | D S F | Build/help | syslogd; rsyslogd / syslogd | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashtermraw`](../loadables/bashtermraw.c) | D S F | Build/help | stty; stty | N/M | P3 | Add behavioral fixtures, then timing. |
| [`batch`](../loadables/batch.c) | S F | [Contract](../tests/misc-smoke.py) | —; batch (missing) | N/M | P3 | Add a matched workload and timing. |
| [`bc`](../loadables/bc.c) | S T F | [Parity](../tests/bc-parity.py); [limited](#scope-notes); [S](../tests/bc-sanitize.sh) | bc; bc | 10.359 / 111.760 / 121.628; [bc](#case-bc), 48 passes | P3 | Decide required option scope; see limitations. |
| [`bignum`](../loadables/bignum.c) | T F | [Contract](../tests/misc-smoke.py) | bc; Python int / bc | N/M | P3 | Add a matched workload and timing. |
| [`binhex`](../loadables/binhex.c) | D S F | Build/help | xxd; xxd | N/M | P3 | Add behavioral fixtures, then timing. |
| [`blkid`](../loadables/blkid.c) | D S F | Build/help | blkid; blkid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`blockdev`](../loadables/blockdev.c) | D S F | Build/help | blockdev; blockdev | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bsdgames`](../loadables/bsdgames.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; bsdgames (missing) | N/M | P3 | Add a matched workload and timing. |
| [`buf`](../loadables/buf.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cal`](../loadables/cal.c) | T F | [Contract](../tests/misc-smoke.py) | cal; cal (missing) | N/M | P3 | Add a matched workload and timing. |
| [`caps`](../loadables/caps.c) | S F | [Smoke](../tests/system-smoke.sh) | —; capsh / setpriv | N/M | P3 | Add behavioral fixtures, then timing. |
| `cat`* | P C D S T F | [Contract](../tests/host-smoke.sh) | cat; cat | 12.687 / 129.153 / 142.050; [cat](#case-cat), 68 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chattr`](../loadables/chattr.c) | D S F | Build/help | —; chattr | N/M | P3 | Add behavioral fixtures, then timing. |
| [`chgrp`](../loadables/chgrp.c) | C D S T F | Build/help | chgrp; chgrp | N/M | P3 | Add behavioral fixtures, then timing. |
| `chmod`* | P C D S T F | Build/help | chmod; chmod | N/M | P3 | Add behavioral fixtures, then timing. |
| [`chown`](../loadables/chown.c) | C D S T F | Build/help | chown; chown | N/M | P3 | Add behavioral fixtures, then timing. |
| [`chrt`](../loadables/chrt.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | —; chrt | N/M | P3 | Add a matched workload and timing. |
| [`cksum`](../loadables/cksum.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; cksum | 58.118 / — / 126.292; [cksum](#case-cksum), 30 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`claude`](../loadables/claude.c) | F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`clip`](../loadables/clip.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cluster`](../loadables/cluster.c) | F | [Smoke](../tests/misc-smoke.py) | —; API fixture | N/M | P3 | Add peer membership, timeout and disconnect fixtures. |
| [`cmp`](../loadables/cmp.c) | C D S T F | [Bench checked](#case-cmp) | cmp; cmp | 39.013 / 170.186 / 59.701; [cmp](#case-cmp), 27 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`col`](../loadables/col.c) | C D S T F | [Repeat-input bug](#additional-correctness-checks) | —; col | N/M | P1 | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| [`colrm`](../loadables/colrm.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | —; colrm | INVALID / — / 266.510; [colrm](#case-colrm), 22 passes | P1 | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| [`column`](../loadables/column.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | —; column | INVALID / — / 1106.052; [column](#case-column), 10 passes | P1 | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| [`comm`](../loadables/comm.c) | C D S T F | [Bench checked](#case-comm) | —; comm | 80.052 / — / 43.888; [comm](#case-comm), 10 passes | P2 | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| [`coreutils`](../loadables/coreutils.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; Individual coreutils programs | N/M | P3 | Add a matched workload and timing. |
| [`cp`](../loadables/cp.c) | C D S T F | [Correctness bug](#additional-correctness-checks) | cp; cp | 21.224 / 127.327 / 144.062; [cp](#case-cp), 54 passes | P1 | Preserve the existing destination when a forced copy cannot read its source; establish dedicated copy, link, metadata and failure-recovery coverage. Assigned to bash-os-3. |
| [`cred`](../loadables/cred.c) | S F | [Smoke](../tests/system-smoke.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cron`](../loadables/cron.c) | S F | [Contract](../tests/large-smoke.py) | crond; cron / crond | N/M | P3 | Add a matched workload and timing. |
| [`crontab`](../loadables/crontab.c) | S F | [Contract](../tests/misc-smoke.py) | crontab; crontab | N/M | P3 | Add a matched workload and timing. |
| [`crypto`](../loadables/crypto.c) | S F | [Correctness bug](#additional-correctness-checks); [S](../tests/final-sanitize.sh) | sha256sum; sha256sum / openssl | 86.600 / 86.511 / 59.482; [crypto](#case-crypto), 6 passes | P1 | Complete the three-command integration review, then validate the combined build; investigate backend cost separately. Assigned to bash-os-2 (review follow-up). |
| [`csplit`](../loadables/csplit.c) | C D S T F | [Repeat-input bug](#additional-correctness-checks) | —; csplit | N/M | P1 | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| [`curl`](../loadables/curl.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; curl | N/M | P3 | Add a matched workload and timing. |
| [`cut`](../loadables/cut.c) | P C D S T F | [Parity](../tests/cut-parity.sh) | cut; cut | 28.551 / 280.054 / 142.033; [cut](#case-cut), 35 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`date`](../loadables/date.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | date; date | N/M | P3 | Add a matched workload and timing. |
| [`dd`](../loadables/dd.c) | C D S T F | [Bench checked](#case-dd) | dd; dd | 8.805 / 112.337 / 84.026; [dd](#case-dd), 50 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`df`](../loadables/df.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | df; df | N/M | P3 | Add a matched workload and timing. |
| [`dhcp6`](../loadables/dhcp6.c) | S F | [Contract](../tests/network-smoke.py) | udhcpc6; dhclient -6 | N/M | P3 | Add a matched workload and timing. |
| [`dhcpd`](../loadables/dhcpd.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | udhcpd; dnsmasq / dhcpd | N/M | P3 | Add a matched workload and timing. |
| [`dhcpd6`](../loadables/dhcpd6.c) | S F | [Contract](../tests/network-smoke.py) | —; kea-dhcp6 (missing) | N/M | P3 | Add a matched workload and timing. |
| [`dialog`](../loadables/dialog.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; dialog (missing) | N/M | P3 | Add a matched workload and timing. |
| [`diff`](../loadables/diff.c) | C D S T F | [Correctness bug](#additional-correctness-checks) | diff; diff | 89.585 / 88.450 / 78.184; [diff](#case-diff), 21 passes | P1 | Fix comparison of two stdin operands, then complete the integration and combined-build validation. Assigned to bash-os-2 (review follow-up). |
| `dirname`* | P C D S T F | [Bench checked](#case-dirname) | dirname; dirname | 5.454 / 146.953 / 134.315; [dirname](#case-dirname), 106 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dmesg`](../loadables/dmesg.c) | D S F | Build/help | dmesg; dmesg | N/M | P3 | Add behavioral fixtures, then timing. |
| [`dmsetup`](../loadables/dmsetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; dmsetup | N/M | P3 | Define required mapper mutation verbs and add isolated device fixtures. |
| [`dns`](../loadables/dns.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | nslookup; dig / drill | N/M | P3 | Add a matched workload and timing. |
| [`doas`](../loadables/doas.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; doas (missing) | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`du`](../loadables/du.c) | C D S T F | [Correctness bug](#additional-correctness-checks) | du; du | N/M | P1 | Integrate the reviewed traversal, allocation and output-error fixes in the next batch, then validate and remeasure. Assigned to coordinator (next batch). |
| [`ed`](../loadables/ed.c) | C D S T F | Build/help | ed; ed (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`env`](../loadables/env.c) | C D S T F | [Contract](../tests/regressions.py) | env; env | N/M | P3 | Add a matched workload and timing. |
| [`escdelay`](../loadables/escdelay.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`expand`](../loadables/expand.c) | C D S T F | [Parity](../tests/expand-parity.py); [limited](#scope-notes); [S](../tests/expand-sanitize.sh) | expand; expand | 78.072 / 333.488 / 108.563; [expand](#case-expand), 20 passes | P3 | Decide required option scope; see limitations. |
| [`expect`](../loadables/expect.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; expect (missing) | N/M | P3 | Add a matched workload and timing. |
| [`expr`](../loadables/expr.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | expr; expr | 7.161 / 152.531 / 83.593; [expr](#case-expr), 67 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`fail2ban`](../loadables/fail2ban.c) | S F | [Contract](../tests/network-smoke.py) | —; fail2ban-client (missing) | N/M | P3 | Add a matched workload and timing. |
| `fdflags`* | D S F | Build/help | —; Python fcntl | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fdisk`](../loadables/fdisk.c) | D S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | fdisk; fdisk | N/M | P3 | Add a matched workload and timing. |
| [`fifo`](../loadables/fifo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`file`](../loadables/file.c) | T F | [Contract](../tests/misc-smoke.py) | —; file | N/M | P3 | Add a matched workload and timing. |
| [`fincore`](../loadables/fincore.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; fincore | N/M | P3 | Add behavioral fixtures, then timing. |
| [`find`](../loadables/find.c) | C D S T F | [Contract](../tests/regressions.py) | find; find | 32.276 / 138.756 / 142.607; [find](#case-find), 53 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `finfo`* | D S F | Build/help | stat; stat | N/M | P3 | Add behavioral fixtures, then timing. |
| [`flock`](../loadables/flock.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | —; flock | N/M | P3 | Add behavioral fixtures, then timing. |
| `fltexpr`* | D S F | Build/help | awk; awk / bc | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fold`](../loadables/fold.c) | C D S T F | [Parity](../tests/fold-parity.py); [limited](#scope-notes); [S](../tests/fold-sanitize.sh) | fold; fold | 40.649 / 132.239 / 99.830; [fold](#case-fold), 16 passes | P3 | Decide required option scope; see limitations. |
| [`free`](../loadables/free.c) | C D S T F | Build/help | free; free | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fsck`](../loadables/fsck.c) | D S F | [Contract](../tests/misc-smoke.py) | —; fsck | N/M | P3 | Add a matched workload and timing. |
| [`fsfreeze`](../loadables/fsfreeze.c) | D S F | Build/help | fsfreeze; fsfreeze | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fstrim`](../loadables/fstrim.c) | D S F | Build/help | fstrim; fstrim | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fw`](../loadables/fw.c) | S F | [Contract](../tests/large-smoke.py) | —; nft / iptables | N/M | P3 | Add a matched workload and timing. |
| [`genl`](../loadables/genl.c) | D S F | Build/help | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| `getconf`* | D S F | Build/help | —; getconf | N/M | P3 | Add behavioral fixtures, then timing. |
| [`getfacl`](../loadables/getfacl.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; getfacl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`gpu`](../loadables/gpu.c) | T F | [Contract](../tests/gpu-smoke.py); [S](../tests/gpu-sanitize.sh) | —; API fixture | [Transport data](#graphics-metrics); no applet ratio | P3 | Measure application frame latency and driver behavior on the intended device. |
| [`grep`](../loadables/grep.c) | C D S T F | [Parity](../tests/grep-parity.sh); [limited](#scope-notes); [S](../tests/grep-host.c) | grep; grep | 45.471 / 347.407 / 64.404; [grep-lines](#case-grep-lines), 25 passes; 2 cases total | P3 | Decide required option scope; see limitations. |
| [`halt`](../loadables/halt.c) | D S F | Build/help | halt; halt | N/M | P3 | Add behavioral fixtures, then timing. |
| `head`* | P C D S T F | [Parity](../tests/head-sed-parity.py); [limited](#scope-notes); [S](../tests/head-sed-sanitize.sh) | head; head | 13.814 / 131.198 / 112.680; [head](#case-head), 67 passes | P3 | Decide required option scope; see limitations. |
| [`hexdump`](../loadables/hexdump.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | hexdump; hexdump | INVALID / 316.349 / 465.534; [hexdump](#case-hexdump), 18 passes | P1 | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| [`hl`](../loadables/hl.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; highlight (missing) | N/M | P3 | Add a matched workload and timing. |
| [`hostid`](../loadables/hostid.c) | D S F | Build/help | hostid; hostid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`hostname`](../loadables/hostname.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | hostname; hostname | 5.933 / 119.174 / 96.275; [hostname](#case-hostname), 89 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`http`](../loadables/http.c) | D S F | [Contract](../tests/network-smoke.py) | wget; curl | N/M | P3 | Add a matched workload and timing. |
| [`httpd`](../loadables/httpd.c) | S F | [Contract](../tests/httpd-host.c); [S](../tests/run.sh) | httpd; HTTP server fixture | N/M | P3 | Add a matched workload and timing. |
| [`hwclock`](../loadables/hwclock.c) | D S F | Build/help | hwclock; hwclock | N/M | P3 | Add behavioral fixtures, then timing. |
| `id`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | id; id | 4.553 / 89.266 / 77.098; [id-uid](#case-id-uid), 60 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`index`](../loadables/index.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git update-index | N/M | P3 | Add a matched workload and timing. |
| [`integrity`](../loadables/integrity.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`ionice`](../loadables/ionice.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | ionice; ionice | N/M | P3 | Add a matched workload and timing. |
| [`ip`](../loadables/ip.c) | D S F | Build/help | ip; ip | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ipcctl`](../loadables/ipcctl.c) | D S F | Build/help | ipcs (not in build); ipcs / ipcrm | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ipcmk`](../loadables/ipcmk.c) | D S F | Build/help | —; ipcmk | N/M | P3 | Add behavioral fixtures, then timing. |
| [`join`](../loadables/join.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; join | 74.481 / — / 62.679; [join](#case-join), 9 passes | P3 | Stop on write failure before reading more input; complete bounds and cleanup review, then validate the combined build. Assigned to bash-os-5 (review follow-up). |
| [`jq`](../loadables/jq.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; jq | 78.267 / — / 145.329; [jq](#case-jq), 7 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`keyctl`](../loadables/keyctl.c) | S F | Build/help | —; keyctl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`kgetch`](../loadables/kgetch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`killall`](../loadables/killall.c) | C D S T F | Build/help | killall; killall (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`killall5`](../loadables/killall5.c) | F | Build/help | —; killall5 | N/M | P3 | Add behavioral fixtures, then timing. |
| [`kitty`](../loadables/kitty.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; kitten icat | N/M | P3 | Add a matched workload and timing. |
| [`ldap`](../loadables/ldap.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-ldap.c) | —; ldapsearch (missing) | N/M | P3 | Add a matched workload and timing. |
| [`less`](../loadables/less.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | less; less | N/M | P3 | Add a matched workload and timing. |
| [`link`](../loadables/link.c) | C D S T F | Build/help | link; link | N/M | P3 | Add behavioral fixtures, then timing. |
| `ln`* | P C D S T F | Build/help | ln; ln | N/M | P3 | Add behavioral fixtures, then timing. |
| [`locale`](../loadables/locale.c) | T F | [Contract](../tests/misc-smoke.py) | —; locale / Python locale | N/M | P3 | Add a matched workload and timing. |
| [`login`](../loadables/login.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | login; login | N/M | P3 | Add a matched workload and timing. |
| `logname`* | P C D S T F | [Bench checked](#case-logname) | logname; logname | 18.051 / 142.710 / 125.831; [logname](#case-logname), 94 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`losetup`](../loadables/losetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | losetup; losetup | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lpr`](../loadables/lpr.c) | F | [Smoke](../tests/misc-smoke.py); [limited](#scope-notes) | lpr (not in build); lpr (missing) | N/M | P3 | Decide whether real print delivery belongs in this loadable. |
| [`ls`](../loadables/ls.c) | C D S T F | [Bench checked](#case-ls) | ls; ls | 19.562 / 141.513 / 123.565; [ls](#case-ls), 51 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`lsattr`](../loadables/lsattr.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; lsattr | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lsblk`](../loadables/lsblk.c) | D S F | Build/help | —; lsblk | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lsof`](../loadables/lsof.c) | D S T F | [Smoke](../tests/system-smoke.sh) | —; lsof | N/M | P3 | Add behavioral fixtures, then timing. |
| [`mail`](../loadables/mail.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | sendmail (not in build); sendmail / mailq | N/M | P3 | Add a controlled submission/delivery benchmark. |
| [`man`](../loadables/man.c) | T F | [Contract](../tests/misc-smoke.py) | —; man | N/M | P3 | Add a matched workload and timing. |
| `mkdir`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | mkdir; mkdir | N/M | P3 | Add a matched workload and timing. |
| `mkfifo`* | P C D S T F | Build/help | mkfifo; mkfifo | N/M | P3 | Add behavioral fixtures, then timing. |
| [`mkfs`](../loadables/mkfs.c) | D S F | [Contract](../tests/misc-smoke.py) | —; mkfs | N/M | P3 | Add a matched workload and timing. |
| [`mkswap`](../loadables/mkswap.c) | D S F | Build/help | mkswap; mkswap | N/M | P3 | Add behavioral fixtures, then timing. |
| `mktemp`* | P C D S T F | Build/help | mktemp; mktemp | N/M | P3 | Add behavioral fixtures, then timing. |
| [`mlock`](../loadables/mlock.c) | D S F | [Smoke](../tests/system-smoke.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`more`](../loadables/more.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | more; more | N/M | P3 | Add a matched workload and timing. |
| [`mouse`](../loadables/mouse.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`mv`](../loadables/mv.c) | C D S T F | [Correctness bug](#additional-correctness-checks) | mv; mv | N/M | P1 | Integrate the reviewed same-file and staged cross-device fixes in the next batch, then validate and remeasure. Assigned to coordinator (next batch). |
| [`nano`](../loadables/nano.c) | T F | [Contract](../tests/final-smoke.py); [limited](#scope-notes); [S](../tests/final-sanitize.sh) | —; nano | N/M | P3 | Decide required option scope; see limitations. |
| [`nano2`](../loadables/nano2.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; nano | N/M | P3 | Add a matched workload and timing. |
| [`nc`](../loadables/nc.c) | D S F | [Contract](../tests/network-smoke.py) | nc; nc | N/M | P3 | Add a matched workload and timing. |
| [`ncdu`](../loadables/ncdu.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; ncdu | N/M | P3 | Add a matched workload and timing. |
| [`netids`](../loadables/netids.c) | S F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; suricata (missing) | N/M | P3 | Add a matched workload and timing. |
| [`netstat`](../loadables/netstat.c) | D S F | Build/help | netstat; netstat (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`nice`](../loadables/nice.c) | C D S T F | [Contract](../tests/regressions.py) | —; nice | N/M | P3 | Add a matched workload and timing. |
| [`nl`](../loadables/nl.c) | C D S T F | [Parity](../tests/nl-parity.py); [limited](#scope-notes); [S](../tests/nl-sanitize.sh) | nl; nl | 62.440 / 292.162 / 186.691; [nl](#case-nl), 40 passes | P3 | Decide required option scope; see limitations. |
| [`nohup`](../loadables/nohup.c) | C D S T F | [Contract](../tests/regressions.py) | —; nohup | N/M | P3 | Add a matched workload and timing. |
| [`notify`](../loadables/notify.c) | T F | [Contract](../tests/misc-smoke.py) | —; systemd-notify | N/M | P3 | Add a matched workload and timing. |
| [`ns`](../loadables/ns.c) | S F | [Smoke](../tests/system-smoke.sh) | unshare; unshare / nsenter | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ntp`](../loadables/ntp.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | ntpd (not in build); chronyc / ntpd | N/M | P3 | Add a matched workload and timing. |
| [`obj`](../loadables/obj.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git hash-object / cat-file | N/M | P3 | Add a matched workload and timing. |
| [`od`](../loadables/od.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | od; od | INVALID / 206.415 / 410.833; [od](#case-od), 19 passes | P1 | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| [`opt`](../loadables/opt.c) | T F | [Contract](../tests/misc-smoke.py) | getopt; getopt | N/M | P3 | Add a matched workload and timing. |
| [`pack`](../loadables/pack.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git pack-objects / index-pack | N/M | P3 | Add a matched workload and timing. |
| [`passwd`](../loadables/passwd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | passwd; passwd | N/M | P3 | Add a matched workload and timing. |
| [`paste`](../loadables/paste.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | paste; paste | 98.727 / 514.843 / 91.571; [paste](#case-paste), 8 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `pathchk`* | P C D S T F | Build/help | —; pathchk | N/M | P3 | Add behavioral fixtures, then timing. |
| [`pax`](../loadables/pax.c) | C D S T F | [Contract](../tests/host-smoke.sh) | —; pax (missing) | N/M | P3 | Add a matched workload and timing. |
| [`payload`](../loadables/payload.c) | F | [Smoke](../tests/misc-smoke.py); [limited](#scope-notes) | —; API fixture | N/M | P3 | Add an installer-boundary fixture and document the external helper. |
| [`pcap`](../loadables/pcap.c) | D S F | [Contract](../tests/network-smoke.py) | —; tcpdump (missing) | N/M | P3 | Add a matched workload and timing. |
| [`pcre`](../loadables/pcre.c) | S F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; pcre2grep / grep -P | N/M | P3 | Add a matched workload and timing. |
| [`pgrep`](../loadables/pgrep.c) | C D S T F | Build/help; [limited](#scope-notes) | —; pgrep | N/M | P3 | Decide required option scope; see limitations. |
| [`pidof`](../loadables/pidof.c) | C D S T F | Build/help | pidof; pidof | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ping`](../loadables/ping.c) | D S F | Build/help | ping; ping | N/M | P3 | Add behavioral fixtures, then timing. |
| [`pkg`](../loadables/pkg.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`pkill`](../loadables/pkill.c) | C D S T F | Build/help; [limited](#scope-notes) | —; pkill | N/M | P3 | Decide required option scope; see limitations. |
| [`pkt`](../loadables/pkt.c) | D S F | [Contract](../tests/network-smoke.py) | —; scapy (missing) | N/M | P3 | Add a matched workload and timing. |
| [`poweroff`](../loadables/poweroff.c) | D S F | Build/help | poweroff; poweroff | N/M | P3 | Add behavioral fixtures, then timing. |
| [`pr`](../loadables/pr.c) | C D S T F | [Parity](../tests/pr-parity.py); [limited](#scope-notes); [S](../tests/pr-sanitize.sh) | —; pr | 33.805 / — / 449.002; [pr](#case-pr), 43 passes | P3 | Decide required option scope; see limitations. |
| `printenv`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | —; printenv | 5.166 / — / 105.212; [printenv-lcall](#case-printenv-lcall), 91 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`prlimit`](../loadables/prlimit.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; prlimit | N/M | P3 | Add behavioral fixtures, then timing. |
| [`procstat`](../loadables/procstat.c) | D S T F | [Contract](../tests/procstat-smoke.py); [S](../tests/procstat-sanitize.sh) | —; iostat / mpstat / sar / pidstat / pmap / pldd | N/M | P3 | Add a matched workload and timing. |
| [`ps`](../loadables/ps.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | ps; ps | N/M | P3 | Add a matched workload and timing. |
| [`pty`](../loadables/pty.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; Python pty | N/M | P3 | Add a matched workload and timing. |
| [`ptybroker`](../loadables/ptybroker.c) | T F | Build/help | —; ptybroker (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`readlink`](../loadables/readlink.c) | C D S T F | [Bench checked](#case-readlink) | readlink; readlink | 6.165 / 73.257 / 62.119; [readlink](#case-readlink), 49 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `realpath`* | P C D S T F | [Bench checked](#case-realpath) | realpath; realpath | 6.021 / 67.748 / 56.307; [realpath](#case-realpath), 44 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`reboot`](../loadables/reboot.c) | D S F | Build/help | reboot; reboot | N/M | P3 | Add behavioral fixtures, then timing. |
| [`renice`](../loadables/renice.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | renice; renice | N/M | P3 | Add behavioral fixtures, then timing. |
| [`rev`](../loadables/rev.c) | C D S T F | [Bench checked](#case-rev) | rev; rev | 74.139 / 56.947 / 156.231; [rev](#case-rev), 9 passes | P3 | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| `rm`* | P C D S T F | Build/help | rm; rm | N/M | P3 | Add behavioral fixtures, then timing. |
| `rmdir`* | P C D S T F | Build/help | rmdir; rmdir | N/M | P3 | Add behavioral fixtures, then timing. |
| [`rngseed`](../loadables/rngseed.c) | D S F | [Contract](../tests/rngseed-host.c); [S](../tests/run.sh) | seedrng (not in build); systemd-random-seed (missing) | N/M | P3 | Add a matched workload and timing. |
| [`rsync`](../loadables/rsync.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; rsync | N/M | P3 | Add a matched workload and timing. |
| [`rtspcat`](../loadables/rtspcat.c) | F | Build/help | —; ffmpeg / openRTSP | N/M | P3 | Add a controlled RTSP/RTP stream with loss, reordering and framing checks. |
| [`scm`](../loadables/scm.c) | F | [Contract](../tests/misc-smoke.py) | —; Python socket SCM_RIGHTS | N/M | P3 | Add a matched workload and timing. |
| [`scp`](../loadables/scp.c) | S F | [Contract](../tests/network-smoke.py) | —; scp | N/M | P3 | Add a matched workload and timing. |
| [`screen`](../loadables/screen.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; screen (missing) | N/M | P3 | Measure live PTY relay, backpressure and cleanup. |
| [`script`](../loadables/script.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; script | N/M | P3 | Add a matched workload and timing. |
| [`scrub`](../loadables/scrub.c) | F | [Contract](../tests/misc-smoke.py) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`sed`](../loadables/sed.c) | C D S T F | [Parity](../tests/head-sed-parity.py); [limited](#scope-notes); [S](../tests/head-sed-sanitize.sh) | sed; sed | 79.527 / 92.227 / 66.245; [sed](#case-sed), 6 passes | P3 | Decide required option scope; see limitations. |
| [`seq`](../loadables/seq.c) | P C D S T F | [Parity](../tests/seq-parity.sh) | seq; seq | 53.875 / 1265.578 / 81.544; [seq](#case-seq), 21 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`setfacl`](../loadables/setfacl.c) | D S F | Build/help | —; setfacl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| `setpgid`* | D S F | Build/help | —; Python os.setpgid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`setsid`](../loadables/setsid.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | setsid; setsid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`sftp`](../loadables/sftp.c) | S F | [Contract](../tests/network-smoke.py) | —; sftp | N/M | P3 | Add a matched workload and timing. |
| [`signal`](../loadables/signal.c) | D S F | [Contract](../tests/system-smoke.sh) | kill; kill -l / Bash kill | N/M | P3 | Add a matched workload and timing. |
| [`sixel`](../loadables/sixel.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; img2sixel (missing) | N/M | P3 | Add a matched workload and timing. |
| [`slabtop`](../loadables/slabtop.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; slabtop | N/M | P3 | Add a matched workload and timing. |
| `sleep`* | P C D S T F | Build/help | sleep; sleep | N/M | P3 | Add behavioral fixtures, then timing. |
| [`sort`](../loadables/sort.c) | C D S T F | [Parity](../tests/sort-parity.sh) | sort; sort | 72.043 / 71.119 / 42.286; [sort-text](#case-sort-text), 7 passes; 2 cases total | P2 | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| [`split`](../loadables/split.c) | C D S T F | [Repeat-input bug](#additional-correctness-checks) | —; split | N/M | P1 | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| [`sqlite`](../loadables/sqlite.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; sqlite3 / Python sqlite3 | N/M | P3 | Add a matched workload and timing. |
| [`ss`](../loadables/ss.c) | D S F | Build/help | —; ss | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ssh`](../loadables/ssh.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; ssh | N/M | P3 | Add a matched workload and timing. |
| [`sshd`](../loadables/sshd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sshd | N/M | P3 | Add a matched workload and timing. |
| [`stat`](../loadables/stat.c) | P C D S T F | [Parity](../tests/stat-parity.sh) | stat; stat | 7.082 / 120.170 / 125.461; [stat](#case-stat), 86 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`strace`](../loadables/strace.c) | F | [Contract](../tests/large-smoke.py) | —; strace (missing) | N/M | P3 | Add a matched workload and timing. |
| `strftime`* | P C D S T F | Build/help | date; date / Bash printf | N/M | P3 | Add behavioral fixtures, then timing. |
| [`strings`](../loadables/strings.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | strings; strings | INVALID / 127.122 / 174.345; [strings](#case-strings), 43 passes | P1 | Combine the reviewed integration with the remaining batch, run full CI and remeasure. Assigned to coordinator (combined validation). |
| `strptime`* | P C D S T F | Build/help | —; Python datetime.strptime | N/M | P3 | Add behavioral fixtures, then timing. |
| [`su`](../loadables/su.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | su; su | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sudo`](../loadables/sudo.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sudo | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sv`](../loadables/sv.c) | S F | [Contract](../tests/large-smoke.py) | —; runit sv | N/M | P3 | Add a matched workload and timing. |
| [`swapoff`](../loadables/swapoff.c) | D S F | Build/help | swapoff; swapoff | N/M | P3 | Add behavioral fixtures, then timing. |
| [`swapon`](../loadables/swapon.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | swapon; swapon | N/M | P3 | Add behavioral fixtures, then timing. |
| `sync`* | P C D S T F | Build/help | sync; sync | N/M | P3 | Add behavioral fixtures, then timing. |
| [`sysctl`](../loadables/sysctl.c) | D S F | [Contract](../tests/system-smoke.sh) | sysctl; sysctl | N/M | P3 | Add a matched workload and timing. |
| [`tac`](../loadables/tac.c) | C D S T F | [Parity](../tests/tac-parity.py); [limited](#scope-notes); [S](../tests/tac-sanitize.sh) | tac; tac | 23.403 / 512.412 / 161.792; [tac](#case-tac), 53 passes | P3 | Decide bounded-memory input and GNU regex scope; see the tac follow-up. |
| [`tail`](../loadables/tail.c) | C D S T F | [Repeat-input bug](#additional-correctness-checks) | tail; tail | 7.483 / 158.041 / 91.356; [tail](#case-tail), 49 passes | P1 | Fix the reviewed candidate's allocation-failure use-after-free and output-error hang; require valid native/static test boundaries before integration. Assigned to bash-os-6 (review follow-up). |
| [`taskset`](../loadables/taskset.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | taskset; taskset | N/M | P3 | Add a matched workload and timing. |
| `tee`* | P C D S T F | [Correctness bug](#additional-correctness-checks) | tee; tee | N/M | P1 | Stop reading when every output has failed, preserving healthy destinations and interrupt cleanup; then validate the combined build. Assigned to bash-os-2 (review follow-up). |
| [`termpixel`](../loadables/termpixel.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`termpixel_pong`](../loadables/termpixel_pong.c) | F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`timeout`](../loadables/timeout.c) | C D S T F | [Contract](../tests/system-smoke.sh) | timeout; timeout | N/M | P3 | Add a matched workload and timing. |
| [`tinfo`](../loadables/tinfo.c) | T F | Build/help | —; infocmp / tput | N/M | P3 | Add behavioral fixtures, then timing. |
| [`tiv`](../loadables/tiv.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; chafa (missing) | N/M | P3 | Add a matched workload and timing. |
| [`toml`](../loadables/toml.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh); [Fz](../tests/fuzz-toml.c) | —; Python tomllib | N/M | P3 | Add a matched workload and timing. |
| [`top`](../loadables/top.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | top; top | N/M | P3 | Add a matched workload and timing. |
| [`totp`](../loadables/totp.c) | F | [Contract](../tests/misc-smoke.py) | —; oathtool (missing) | N/M | P3 | Add a matched workload and timing. |
| [`touch`](../loadables/touch.c) | C D S T F | Build/help | touch; touch | N/M | P3 | Add behavioral fixtures, then timing. |
| [`tput`](../loadables/tput.c) | T F | Build/help | —; tput | N/M | P3 | Add behavioral fixtures, then timing. |
| [`tr`](../loadables/tr.c) | C D S T F | [Bench checked](#case-tr) | tr; tr | 38.204 / 87.345 / 62.239; [tr](#case-tr), 27 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`truncate`](../loadables/truncate.c) | C D S T F | [Correctness bug](#additional-correctness-checks) | truncate; truncate | N/M | P1 | Reject size arithmetic overflow while preserving existing data; establish dedicated size, reference, I/O-error and recovery coverage before timing. Assigned to bash-os-1. |
| [`ts`](../loadables/ts.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; tree-sitter (missing) | N/M | P3 | Add a matched workload and timing. |
| `tty`* | P C D S T F | Build/help | tty; tty | N/M | P3 | Add behavioral fixtures, then timing. |
| [`tui`](../loadables/tui.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`tz`](../loadables/tz.c) | T F | [Contract](../tests/misc-smoke.py) | date; date / Python zoneinfo | N/M | P3 | Add a matched workload and timing. |
| [`uclampset`](../loadables/uclampset.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; uclampset | N/M | P3 | Decide whether to implement the missing setter surface. |
| `uname`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | uname; uname | 6.187 / 136.027 / 121.701; [uname](#case-uname), 87 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`undo`](../loadables/undo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`unexpand`](../loadables/unexpand.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | unexpand; unexpand | 92.155 / 131.420 / 50.734; [unexpand](#case-unexpand), 6 passes | P3 | Complete the integration review follow-up, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| [`uniq`](../loadables/uniq.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | uniq; uniq | 84.954 / 468.766 / 115.611; [uniq](#case-uniq), 12 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `unlink`* | P C D S T F | Build/help | unlink; unlink | N/M | P3 | Add behavioral fixtures, then timing. |
| [`uptime`](../loadables/uptime.c) | D S T F | [Smoke](../tests/system-smoke.sh) | uptime; uptime | N/M | P3 | Add behavioral fixtures, then timing. |
| [`userdb`](../loadables/userdb.c) | S F | [Contract](../tests/system-smoke.sh) | —; getent | N/M | P3 | Add a matched workload and timing. |
| [`utf8`](../loadables/utf8.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; Python Unicode / grapheme library | N/M | P3 | Add a matched workload and timing. |
| [`utmp`](../loadables/utmp.c) | D S F | [Contract](../tests/system-smoke.sh) | who; utmpdump / who | N/M | P3 | Add a matched workload and timing. |
| [`uudecode`](../loadables/uudecode.c) | C D S T F | Build/help | uudecode; uudecode (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`uuencode`](../loadables/uuencode.c) | C D S T F | Build/help | uuencode; uuencode (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`uuidgen`](../loadables/uuidgen.c) | F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; uuidgen (missing) | N/M | P3 | Add a matched workload and timing. |
| [`vec`](../loadables/vec.c) | T F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; NumPy | N/M | P3 | Add a matched workload and timing. |
| [`vi`](../loadables/vi.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | vi; vi | N/M | P3 | Add a matched workload and timing. |
| [`vmstat`](../loadables/vmstat.c) | D S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; vmstat | N/M | P3 | Add a matched workload and timing. |
| [`vt`](../loadables/vt.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`w`](../loadables/w.c) | D S T F | [Smoke](../tests/system-smoke.sh) | w; w | N/M | P3 | Add behavioral fixtures, then timing. |
| [`wall`](../loadables/wall.c) | T F | [Negative checks](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; wall | N/M | P3 | Add behavioral fixtures, then timing. |
| [`watch`](../loadables/watch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | watch; watch | N/M | P3 | Add a matched workload and timing. |
| [`wc`](../loadables/wc.c) | C D S T F | [Parity](../tests/wc-tail-parity.sh) | wc; wc | 55.659 / 150.397 / 67.310; [wc-characters](#case-wc-characters), 28 passes; 3 cases total | P3 | Keep every requested word-count assertion across GNU versions, then validate the combined build and remeasure. Assigned to bash-os-5 (review follow-up). |
| [`wg`](../loadables/wg.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; wg (missing) | N/M | P3 | Add a matched workload and timing. |
| [`wget_wch`](../loadables/wget_wch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`wgetch`](../loadables/wgetch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`whatis`](../loadables/whatis.c) | T F | [Contract](../tests/misc-smoke.py) | —; whatis | N/M | P3 | Add a matched workload and timing. |
| [`whiptail`](../loadables/whiptail.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; whiptail | N/M | P3 | Add a matched workload and timing. |
| [`who`](../loadables/who.c) | D S T F | [Smoke](../tests/system-smoke.sh) | who; who | N/M | P3 | Add behavioral fixtures, then timing. |
| `whoami`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | whoami; whoami | 5.338 / 153.589 / 137.057; [whoami](#case-whoami), 94 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`wipefs`](../loadables/wipefs.c) | D S F | Build/help | —; wipefs | N/M | P3 | Add behavioral fixtures, then timing. |
| [`write`](../loadables/write.c) | T F | [Negative checks](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; write (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`xargs`](../loadables/xargs.c) | C D S T F | [Contract](../tests/regressions.py) | xargs; xargs | N/M | P3 | Add a matched workload and timing. |
| [`xattr`](../loadables/xattr.c) | S F | [Contract](../tests/system-smoke.sh) | —; getfattr / setfattr | N/M | P3 | Add a matched workload and timing. |
| [`zcat`](../loadables/zcat.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | zcat; zcat | N/M | P3 | Add a matched workload and timing. |
| [`zlib`](../loadables/zlib.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | gzip; gzip / xz / zstd / bzip2 | N/M | P3 | Add a matched workload and timing. |
| [`zstd`](../loadables/zstd.c) | S T F | [Parity](../tests/zstd-check.sh); [S](../tests/zstd-host.c) | —; zstd | N/M | P3 | See the dedicated zstd report; extend sizes and levels if a slower case appears. |
| [`zstdcat`](../loadables/zstdcat.c) | S T F | [Parity](../tests/zstd-check.sh) | —; zstdcat | N/M | P3 | Add a matched workload and timing. |
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
These checks used source `7b287fab0b35d607dc9c2e231c5592dea227335d` and the same binary as the command measurements. The [evidence JSON](data/loadable-untimed-findings.json) records fixtures, references, exit statuses, output and created files. These cases have no timing measurements.

| Loadable | Invocation | Finding |
| --- | --- | --- |
| `ar` | `ar t partial.a` | A truncated member header is incorrectly accepted as a valid archive. |
| `col` | `col -b < input (three fresh redirections)` | Only the first invocation emits input. |
| `cp` | `cp -f source target (source mode 000)` | An unreadable source causes forced copy to delete the existing destination before failing. |
| `crypto` | `crypto sha256 -x < input > /dev/full` | A failed digest write is incorrectly reported as successful. |
| `csplit` | `csplit -s -f "pieces/$i-" - 2 < input (three fresh redirections)` | Later invocations create empty pieces after the first call exhausts shared stdin. |
| `diff` | `diff input input-newline` | Files differing only in the final newline are incorrectly reported equal. |
| `du` | `du -b file > /dev/full` | A failed size-report write is incorrectly reported as successful. |
| `mv` | `mv file file` | Moving a file to itself incorrectly reports success. |
| `split` | `split -l 2 - "pieces/$i-" < input (three fresh redirections)` | Only the first invocation creates output files. |
| `tail` | `tail -n 1 < input (three fresh redirections)` | Only the first small-input invocation emits its last line; the larger timed fixture passes. |
| `tee` | `tee <&- > /dev/null` | A read from closed stdin reports an error but incorrectly returns success. |
| `truncate` | `truncate -s +9223372036854775807 file` | An overflowing size extension incorrectly succeeds and empties the existing file. |
<!-- END UNTIMED -->

## Scope notes

These are specific reviewed limits or gaps, not an exhaustive option audit.
Source comments alone were not treated as proof of an unimplemented feature.

<!-- BEGIN NOTES -->
| Loadable | Scope / limitation |
| --- | --- |
| `ar` | Candidate 03deb15bcc44 rejects truncated headers and preserves ordinary archives during failed updates. Review found descriptor leaks after failed extraction and successful updates that break symlink/hard-link relationships; it is not yet accepted. Extraction and sanitizer/recovery tests also need correction. |
| `bc` | Repeated stdin is fixed. User functions, output-base printing, control flow, comments and file operands remain outside the supported language subset. [source](../docs/bc.md) |
| `cluster` | Only a version smoke check is mapped here. |
| `col` | Seven-reader integration c3c8e0e48e38 passed native/static parity and native sanitizers. Prepared on the combined review branch; published measurements still describe the earlier implementation. |
| `colrm` | Seven-reader integration c3c8e0e48e38 passed native/static parity and native sanitizers. Prepared on the combined review branch; published measurements still describe the earlier implementation. |
| `column` | Seven-reader integration c3c8e0e48e38 passed native/static parity and native sanitizers. Prepared on the combined review branch; published measurements still describe the earlier implementation. |
| `comm` | Seven-reader integration c3c8e0e48e38 passed native/static parity and native sanitizers. Prepared on the combined review branch; published measurements still describe the earlier implementation. |
| `crypto` | SHA-256 I/O fixes are included in integration candidate 036215f2a625; current measurements still describe the earlier implementation. No backend throughput improvement is claimed. The benchmark harness already validated every digest record before this work. |
| `csplit` | Integration candidate 9f8997f915fc requires corrected test setup, native/static primer boundaries, complete word-count assertions and join error handling before acceptance. Existing measurements remain unchanged. |
| `diff` | Integration candidate 036215f2a625 fixes the raw-binary, write-status and FIFO-reopening defects; the coordinator independently passed 173 native and 173 static regression checks. Review found that two minus operands compare stdin against an exhausted second read. The current timed case still measures the earlier identical-file path, not edit-script generation. |
| `dmsetup` | Some mutation verbs still return an explicit unimplemented-backend error. [source](../loadables/dmsetup.c) |
| `doas` | Current integration test rejects an invalid option before credential transition. |
| `du` | Reviewed worker result 94f501a4f54c: 274 native/static/sanitizer parity checks per run and 940 fault checks. Coordinator also passed 274 checks on each native/static binary against GNU 9.4; published measurement still uses the earlier source. |
| `expand` | Buffered output and per-invocation input are validated. Documented option/tab-stop differences and locale scope remain; tiny-input speedup is not established. [source](../docs/expand.md) |
| `fold` | Buffered ASCII processing is validated; the existing permissive UTF-8 decoder and short-input fread lookahead behavior remain. Unicode and appliance throughput are not established. [source](../docs/fold.md) |
| `gpu` | CPU/protocol, native driver and isolated Kilix checks exist. Static builds support CPU presentation; native shaders require dynamic linking. |
| `grep` | Default build disables -P; the separate pcre loadable supplies PCRE2 operations. See the source build switch. [source](../loadables/grep.c) |
| `head` | Repeated stdin is fixed. The stock Bash option subset remains; private streams restore seekable read-ahead and use unbuffered pipe input. [source](../docs/head-sed.md) |
| `hexdump` | Seven-reader integration c3c8e0e48e38 passed native/static parity and native sanitizers. Prepared on the combined review branch; published measurements still describe the earlier implementation. |
| `join` | Integration candidate 9f8997f915fc requires corrected test setup, native/static primer boundaries, complete word-count assertions and join error handling before acceptance. Existing measurements remain unchanged. |
| `ldap` | BER/filter fixtures and bounded fuzzing pass; live server/authentication throughput is unmeasured. |
| `lpr` | Submit copies into a spool and sleeps to simulate printing. No real printer throughput claim. [source](../loadables/lpr.c) |
| `mail` | Alias compilation/expansion fixtures exist; no SMTP delivery throughput measurement. |
| `mv` | Candidate 06f04fdaf41f passed review, including independent 158 ASan/UBSan/LSan fault cases and 186 static cases with 480 reference comparisons. Cross-device failures before publication preserve source and destination; later source-removal failure may leave a partial source tree with a complete destination. Copied-tree hard links, ACLs/xattrs and crash durability remain outside scope. |
| `nano` | Editor selftests pass; justify, spell and completion still report unimplemented. [source](../loadables/nano.c) |
| `nl` | Repeated stdin, stale stream read-ahead and named-file descriptor ownership are fixed. BRE matching uses the host regex library; without REG_STARTEND, patterns cannot match past embedded NUL bytes. [source](../docs/nl.md) |
| `od` | Seven-reader integration c3c8e0e48e38 passed native/static parity and native sanitizers. Prepared on the combined review branch; published measurements still describe the earlier implementation. |
| `payload` | Install/remove invoke a helper outside this repository; the current fixture only calls help. [source](../loadables/payload.c) |
| `pgrep` | Matching is substring-based unless exact matching is selected; not full procps regular-expression behavior. [source](../loadables/pgrep.c) |
| `pkill` | Shares pgrep matching and process traversal; validate signals only against owned child fixtures. [source](../loadables/pkill.c) |
| `pr` | Repeated stdin, paging and output failures are fixed for the tested subset. Numbered multi-column control bytes, merged unterminated records and several GNU options remain documented exclusions. [source](../docs/pr.md) |
| `rev` | Integration candidate 9f8997f915fc requires corrected test setup, native/static primer boundaries, complete word-count assertions and join error handling before acceptance. Existing measurements remain unchanged. |
| `rtspcat` | No command-specific fixture is mapped in the current repository suite. |
| `scp` | Companion frontend to sftp; local-copy and failure fixtures do not establish full remote scp compatibility. |
| `screen` | Metadata/control fixtures pass; the live relay path needs separate sustained traffic measurements. |
| `sed` | Repeated stdin and final-newline preservation are fixed. Regex and per-file state differ from GNU; an evaluated dollar address before early pipe quit can consume one lookahead byte. [source](../docs/head-sed.md) |
| `sftp` | Local operation and failure fixtures exist; remote transfer behavior needs dedicated interop and throughput coverage. |
| `sort` | Integration candidate 9f8997f915fc requires corrected test setup, native/static primer boundaries, complete word-count assertions and join error handling before acceptance. Existing measurements remain unchanged. |
| `split` | Integration candidate 9f8997f915fc requires corrected test setup, native/static primer boundaries, complete word-count assertions and join error handling before acceptance. Existing measurements remain unchanged. |
| `ssh` | Host-key fixtures and loopback SSH interoperability pass; no transfer throughput measurements. |
| `sshd` | Loopback interoperability and malformed setup cases pass; no concurrent-session measurements. |
| `strings` | Seven-reader integration c3c8e0e48e38 passed native/static parity and native sanitizers. Prepared on the combined review branch; published measurements still describe the earlier implementation. |
| `su` | Current integration test rejects an invalid option before credential transition. |
| `sudo` | Current integration test rejects an invalid option before credential transition. |
| `tac` | Descriptor input and buffered literal-separator processing are validated. Whole-file memory use and the POSIX ERE regex subset remain limits; dedicated size and separator measurements are separate. [source](../docs/tac.md) |
| `tail` | Candidate 7a32aec034f9 fixes the repeated-input finding but coordinator fault/stream probes found additional failures. Review follow-up is active; the frozen 17-command batch excludes tail. |
| `tee` | Integration candidate 036215f2a625 includes the stock-source patch, interrupt cleanup and closed-stdout correction. Review found that it waits on an open input pipe after all outputs fail. The buffer is unchanged and contended timing ranges do not establish a throughput improvement. |
| `truncate` | Confirmed on a disposable three-byte file; GNU rejects the extension and preserves its bytes. |
| `uclampset` | Query subset; setting PID/system clamps and command mode are refused. [source](../loadables/uclampset.c) |
| `unexpand` | Integration candidate 9f8997f915fc requires corrected test setup, native/static primer boundaries, complete word-count assertions and join error handling before acceptance. Existing measurements remain unchanged. |
| `wc` | Integration candidate 9f8997f915fc requires corrected test setup, native/static primer boundaries, complete word-count assertions and join error handling before acceptance. Existing measurements remain unchanged. |
| `zstd` | Default-level stdin compress/decompress is ahead of host zstd(1) on the catalog binary; frames are not byte-identical and validation is round-trip. BusyBox has no applet. Whole-file reads and one-shot ZSTD_compress remain. [source](../docs/zstd.md) |
<!-- END NOTES -->

## Individual benchmark cases

<!-- BEGIN CASES -->
| Case | Builtin command | External command | Input | Passes | BOS ms | BB ms | External ms | BOS / external | Samples |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| <a id="case-cat"></a>cat | `cat` | `cat` | text (423,000 stdin bytes) | 68 | 12.687 | 129.153 | 142.050 | 0.09× | 7 |
| <a id="case-head"></a>head | `head -n 100` | `head -n 100` | text (423,000 stdin bytes) | 67 | 13.814 | 131.198 | 112.680 | 0.12× | 7 |
| <a id="case-tail"></a>tail | `tail -n 100` | `tail -n 100` | text (423,000 stdin bytes) | 49 | 7.483 | 158.041 | 91.356 | 0.08× | 7 |
| <a id="case-wc-counts"></a>wc-counts | `wc -lwc` | `wc -lwc` | text (423,000 stdin bytes) | 25 | 52.281 | 127.582 | 98.355 | 0.53× | 7 |
| <a id="case-wc-characters"></a>wc-characters | `wc -m` | `wc -m` | text (423,000 stdin bytes) | 28 | 55.659 | 150.397 | 67.310 | 0.83× | 7 |
| <a id="case-wc-width"></a>wc-width | `wc -L` | `wc -L` | text (423,000 stdin bytes) | 19 | 51.222 | 127.550 | 92.517 | 0.55× | 7 |
| <a id="case-cut"></a>cut | `cut -d ' ' -f 1` | `cut -d ' ' -f 1` | text (423,000 stdin bytes) | 35 | 28.551 | 280.054 | 142.033 | 0.20× | 7 |
| <a id="case-grep-count"></a>grep-count | `grep -c alpha` | `grep -c alpha` | text (423,000 stdin bytes) | 38 | 49.080 | 516.053 | 95.986 | 0.51× | 7 |
| <a id="case-grep-lines"></a>grep-lines | `grep alpha` | `grep alpha` | text (423,000 stdin bytes) | 25 | 45.471 | 347.407 | 64.404 | 0.71× | 7 |
| <a id="case-sed"></a>sed | `sed s/alpha/OMEGA/g` | `sed s/alpha/OMEGA/g` | text (423,000 stdin bytes) | 6 | 79.527 | 92.227 | 66.245 | 1.20× | 7 |
| <a id="case-sort-numeric"></a>sort-numeric | `sort -n` | `sort -n` | numbers (369,296 stdin bytes) | 5 | 95.502 | 797.345 | 189.435 | 0.50× | 7 |
| <a id="case-sort-text"></a>sort-text | `sort` | `sort` | text (423,000 stdin bytes) | 7 | 72.043 | 71.119 | 42.286 | 1.70× | 7 |
| <a id="case-seq"></a>seq | `seq 100000` | `seq 100000` | No stdin; named fixtures / arguments | 21 | 53.875 | 1265.578 | 81.544 | 0.66× | 7 |
| <a id="case-tr"></a>tr | `tr a-z A-Z` | `tr a-z A-Z` | text (423,000 stdin bytes) | 27 | 38.204 | 87.345 | 62.239 | 0.61× | 7 |
| <a id="case-uniq"></a>uniq | `uniq` | `uniq` | duplicates (1,680,000 stdin bytes) | 12 | 84.954 | 468.766 | 115.611 | 0.73× | 7 |
| <a id="case-paste"></a>paste | `paste duplicates duplicates` | `paste duplicates duplicates` | No stdin; named fixtures / arguments | 8 | 98.727 | 514.843 | 91.571 | 1.08× | 7 |
| <a id="case-nl"></a>nl | `nl -ba` | `nl -ba` | text (423,000 stdin bytes) | 40 | 62.440 | 292.162 | 186.691 | 0.33× | 7 |
| <a id="case-rev"></a>rev | `rev` | `rev` | text (423,000 stdin bytes) | 9 | 74.139 | 56.947 | 156.231 | 0.47× | 7 |
| <a id="case-fold"></a>fold | `fold -w 40` | `fold -w 40` | text (423,000 stdin bytes) | 16 | 40.649 | 132.239 | 99.830 | 0.41× | 7 |
| <a id="case-tac"></a>tac | `tac` | `tac` | text (423,000 stdin bytes) | 53 | 23.403 | 512.412 | 161.792 | 0.14× | 7 |
| <a id="case-comm"></a>comm | `comm left right` | `comm left right` | No stdin; named fixtures / arguments | 10 | 80.052 | — | 43.888 | 1.82× | 7 |
| <a id="case-join"></a>join | `join left right` | `join left right` | No stdin; named fixtures / arguments | 9 | 74.481 | — | 62.679 | 1.19× | 7 |
| <a id="case-expand"></a>expand | `expand -t 8` | `expand -t 8` | tabs (340,000 stdin bytes) | 20 | 78.072 | 333.488 | 108.563 | 0.72× | 7 |
| <a id="case-unexpand"></a>unexpand | `unexpand -a` | `unexpand -a` | spaces (440,000 stdin bytes) | 6 | 92.155 | 131.420 | 50.734 | 1.82× | 7 |
| <a id="case-pr"></a>pr | `pr -t` | `pr -t` | text (423,000 stdin bytes) | 43 | 33.805 | — | 449.002 | 0.08× | 7 |
| <a id="case-colrm"></a>colrm | `colrm 4` | `colrm 4` | text (423,000 stdin bytes) | 22 | INVALID | — | 266.510 | — | 7 |
| <a id="case-column"></a>column | `column -t` | `column -t` | tabs (340,000 stdin bytes) | 10 | INVALID | — | 1106.052 | — | 7 |
| <a id="case-strings"></a>strings | `strings -n 4` | `strings -n 4` | bytes (65,536 stdin bytes) | 43 | INVALID | 127.122 | 174.345 | — | 7 |
| <a id="case-od"></a>od | `od -An -tx1` | `od -An -tx1` | bytes (65,536 stdin bytes) | 19 | INVALID | 206.415 | 410.833 | — | 7 |
| <a id="case-hexdump"></a>hexdump | `hexdump -C` | `hexdump -C` | bytes (65,536 stdin bytes) | 18 | INVALID | 316.349 | 465.534 | — | 7 |
| <a id="case-basename"></a>basename | `basename /fixture/path/file.txt` | `basename /fixture/path/file.txt` | No stdin; named fixtures / arguments | 61 | 5.845 | 102.123 | 103.101 | 0.06× | 7 |
| <a id="case-dirname"></a>dirname | `dirname /fixture/path/file.txt` | `dirname /fixture/path/file.txt` | No stdin; named fixtures / arguments | 106 | 5.454 | 146.953 | 134.315 | 0.04× | 7 |
| <a id="case-readlink"></a>readlink | `readlink link` | `readlink link` | No stdin; named fixtures / arguments | 49 | 6.165 | 73.257 | 62.119 | 0.10× | 7 |
| <a id="case-realpath"></a>realpath | `realpath link` | `realpath link` | No stdin; named fixtures / arguments | 44 | 6.021 | 67.748 | 56.307 | 0.11× | 7 |
| <a id="case-stat"></a>stat | `stat -c %s text` | `stat -c %s text` | No stdin; named fixtures / arguments | 86 | 7.082 | 120.170 | 125.461 | 0.06× | 7 |
| <a id="case-ls"></a>ls | `ls -1 tree` | `ls -1 tree` | No stdin; named fixtures / arguments | 51 | 19.562 | 141.513 | 123.565 | 0.16× | 7 |
| <a id="case-find"></a>find | `find tree -type f` | `find tree -type f` | No stdin; named fixtures / arguments | 53 | 32.276 | 138.756 | 142.607 | 0.23× | 7 |
| <a id="case-cmp"></a>cmp | `cmp text copy` | `cmp text copy` | No stdin; named fixtures / arguments | 27 | 39.013 | 170.186 | 59.701 | 0.65× | 7 |
| <a id="case-diff"></a>diff | `diff text copy` | `diff text copy` | No stdin; named fixtures / arguments | 21 | 89.585 | 88.450 | 78.184 | 1.15× | 7 |
| <a id="case-dd"></a>dd | `dd if=text bs=64K status=none` | `dd if=text bs=64K status=none` | No stdin; named fixtures / arguments | 50 | 8.805 | 112.337 | 84.026 | 0.10× | 7 |
| <a id="case-cp"></a>cp | `cp text copied` | `cp text copied` | No stdin; named fixtures / arguments | 54 | 21.224 | 127.327 | 144.062 | 0.15× | 7 |
| <a id="case-cksum"></a>cksum | `cksum` | `cksum` | text (423,000 stdin bytes) | 30 | 58.118 | — | 126.292 | 0.46× | 7 |
| <a id="case-bashbase64"></a>bashbase64 | `bashbase64 -w 0` | `base64 -w 0` | bytes (65,536 stdin bytes) | 80 | 16.357 | 199.209 | 160.052 | 0.10× | 7 |
| <a id="case-bashjson"></a>bashjson | `bashjson get .answer` | `jq .answer` | object (39,133 stdin bytes) | 34 | 41.327 | — | 318.365 | 0.13× | 7 |
| <a id="case-awk"></a>awk | `awk '{sum += $2} END {print sum}'` | `awk '{sum += $2} END {print sum}'` | records (162,830 stdin bytes) | 7 | 81.469 | 156.228 | 87.363 | 0.93× | 7 |
| <a id="case-jq"></a>jq | `jq -c '[.[] &#124; select(. > 50)]'` | `jq -c '[.[] &#124; select(. > 50)]'` | array (39,109 stdin bytes) | 7 | 78.267 | — | 145.329 | 0.54× | 7 |
| <a id="case-bc"></a>bc | `bc` | `bc` | arithmetic (18 stdin bytes) | 48 | 10.359 | 111.760 | 121.628 | 0.09× | 7 |
| <a id="case-expr"></a>expr | `expr 123 '*' 456` | `expr 123 '*' 456` | No stdin; named fixtures / arguments | 67 | 7.161 | 152.531 | 83.593 | 0.09× | 7 |
| <a id="case-crypto"></a>crypto | `crypto sha256 -x` | `sha256sum` | blob (1,048,576 stdin bytes) | 6 | 86.600 | 86.511 | 59.482 | 1.46× | 7 |
| <a id="case-uname"></a>uname | `uname` | `uname` | No stdin; named fixtures / arguments | 87 | 6.187 | 136.027 | 121.701 | 0.05× | 7 |
| <a id="case-whoami"></a>whoami | `whoami` | `whoami` | No stdin; named fixtures / arguments | 94 | 5.338 | 153.589 | 137.057 | 0.04× | 7 |
| <a id="case-logname"></a>logname | `logname` | `logname` | No stdin; named fixtures / arguments | 94 | 18.051 | 142.710 | 125.831 | 0.14× | 7 |
| <a id="case-hostname"></a>hostname | `hostname` | `hostname` | No stdin; named fixtures / arguments | 89 | 5.933 | 119.174 | 96.275 | 0.06× | 7 |
| <a id="case-id-uid"></a>id-uid | `id -u` | `id -u` | No stdin; named fixtures / arguments | 60 | 4.553 | 89.266 | 77.098 | 0.06× | 7 |
| <a id="case-printenv-lcall"></a>printenv-lcall | `printenv LC_ALL` | `printenv LC_ALL` | No stdin; named fixtures / arguments | 91 | 5.166 | — | 105.212 | 0.05× | 7 |
<!-- END CASES -->

## Method and limits

<!-- BEGIN METHOD -->
The command measurements use the native dynamic full `out/bash` at the source above, SHA-256 `9b2c69c9b8dc1c8cb437904afeacc51919fc4db31fc676d0c41137a2c8caad73`. Host: Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz, x86_64 Linux 6.12.96+deb13-amd64; pinned CPUs: 11. Reference versions and fixture hashes are recorded in the measurement JSON. These are host measurements; no per-command RISC-V or appliance performance is claimed.

Every case uses 7 timed samples after output validation and warm-up. The one-minute host load was 14.2 at the start and 18.5 at the end. A shared lock serialized participating benchmarks; builds and other host activity could still contend. Use the recorded ranges for prioritization and repeat on the intended device before claiming small performance differences.
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
