# Loadable status and benchmark work queue

The [PTY broker and live-pane changes](ptybroker.md) have dedicated lifecycle
and binary-I/O regression suites.

Repeated-input, overflow and write-error fixtures named in the 2026-09-08
queue are in this measured full build: `head`, `sed`, `bc`, `nl`, `pr`,
`fold`, `expand`, `tac`, `col`, `colrm`, `column`, `strings`, `od`,
`hexdump`, `split`, `csplit`, `tail`, `tee` (closed stdin), `crypto`, `du`,
`mv`, `truncate`, `cp`, `join`, `comm`, `unexpand`, `rev`, `sort` and `wc`.

This is the **2026-09-11** review of the complete
[build catalog](../config/bash-loadables.list) at `db921ad`. The
[CSV](loadables-status.csv) has one row per loadable for filtering by profile,
status, priority, counterpart and measurement. The
[current measurement summary](data/loadable-benchmarks-current.json) retains
fixture hashes, sample counts and timing ranges. The
[original snapshot](data/loadable-benchmarks.json) remains available for
historical comparison; its batch sizes and host conditions differ.

Dedicated scope, regression and benchmark reports cover
[head and sed](head-sed.md), [fold](fold.md), [expand](expand.md), [bc](bc.md),
[nl](nl.md), [pr](pr.md), [tac](tac.md), [zstd](zstd.md) and
[hostid](hostid.md). A corrected invalid baseline is not reported as a
speedup. Raw run logs stay outside the repository.

Leftover follow-ups on this binary, assigned to grok-bash-2/3/4: `diff - -`
must compare the same stdin bytes, and `tee` must stop reading when every
output has failed. `ar` truncated-header rejection is landed; extraction
write-error cleanup is still under review. Live `free -k` timings are not
published because counters move between invocations.

<!-- BEGIN SUMMARY -->
Catalog: **279 loadables** (248 local sources, 31 stock Bash sources). Command benchmark: **83 cases covering 73 loadables**; 73 loadables passed the selected output checks, 0 have confirmed correctness findings. The other 206 have no individual command timings here; GPU transport measurements are reported separately.

Separate [untimed checks](#additional-correctness-checks) record 2 further correctness findings.

| Profile | Included loadables |
| --- | --- |
| shell | 0 |
| pure | 28 |
| core | 89 |
| device | 160 |
| server | 214 |
| desktop | 155 |
| full | 279 |

Command measurement source: `db921ad9d9d73177d37cf5288e23a598620f7da7`. The measured full binary passed the dedicated empty-PATH contract checks for the previously named P1/P2/P3 fixtures (ar, tee, diff, col, colrm, column, strings, od, hexdump, split, csplit, crypto, du, mv, truncate, cp, tail, join, comm, unexpand, rev, sort, wc, hostid, free, timeout, uptime). tests/run.sh was not re-run in full for this refresh. Live `free -k` timings are omitted because counters move between invocations; tests/free-check.sh still matches GNU on a private meminfo.

Historical [CI at 5fde494](https://github.com/itsmygithubacct/bash-os/actions/runs/34214029478) passed all nine jobs on the pre-integration tree. This measurement is `db921ad` after those named fixtures landed.

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
| P1 | diff | A minus operand is opened as a file named '-'; two minus operands therefore fail instead of comparing the same stdin bytes. Untimed check. | Treat "-" as stdin and compare two minus operands using the same input bytes, then remeasure. Assigned to grok-bash-4. |
| P1 | tee | After every output has failed the builtin keeps reading stdin until timeout 124; GNU tee returns 1 promptly. Untimed check. | Stop reading when every output has failed, preserving healthy destinations; then remeasure. Assigned to grok-bash-3. |
| P2 | [comm](#case-comm) | 2.52× external time; output checks pass, seven samples. | Profile input/output and allocation costs on the comm fixture, then measure the proposed change. |
| P2 | [sort-text](#case-sort-text) | 2.33× external time; 1.02× BusyBox time; output checks pass, seven samples. | Profile input/output and allocation costs on the sort-text fixture, then measure the proposed change. |
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
| [`ar`](../loadables/ar.c) | C D S T F | Build/help | ar; ar | N/M | P3 | Finish extraction write-error cleanup versus GNU without changing behaviors that already match. Assigned to grok-bash-2. |
| `asort`* | F | [Contract](../tests/misc-smoke.py) | —; gawk asort() | N/M | P3 | Add a matched workload and timing. |
| [`at`](../loadables/at.c) | S F | [Contract](../tests/misc-smoke.py) | —; at (missing) | N/M | P3 | Add a matched workload and timing. |
| [`audit`](../loadables/audit.c) | S F | [Contract](../tests/network-smoke.py) | —; auditctl / ausearch | N/M | P3 | Add a matched workload and timing. |
| [`auth`](../loadables/auth.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`awk`](../loadables/awk.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | awk; awk | 62.731 / 127.772 / 66.181; [awk](#case-awk), 12 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `basename`* | P C D S T F | [Contract](../tests/host-smoke.sh) | basename; basename | 3.890 / 89.303 / 73.538; [basename](#case-basename), 119 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashbase64`](../loadables/bashbase64.c) | D S F | [Bench checked](#case-bashbase64) | base64; base64 | 9.732 / 69.070 / 58.131; [bashbase64](#case-bashbase64), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashclock`](../loadables/bashclock.c) | D S F | Build/help | —; Bash EPOCHREALTIME / Python time | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashdhcp`](../loadables/bashdhcp.c) | D S F | Build/help | udhcpc; dhclient / udhcpc | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashinotify`](../loadables/bashinotify.c) | D S F | Build/help | inotifyd (not in build); inotifywait (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashio`](../loadables/bashio.c) | D S F | Build/help | —; Python os.pread/os.pwrite | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashjson`](../loadables/bashjson.c) | D S F | [Bench checked](#case-bashjson) | —; jq | 35.666 / — / 280.212; [bashjson](#case-bashjson), 74 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashkmod`](../loadables/bashkmod.c) | D S F | Build/help | modprobe; modprobe / insmod / rmmod | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashlogger`](../loadables/bashlogger.c) | D S F | Build/help | logger; logger | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashmount`](../loadables/bashmount.c) | D S F | Build/help | mount; mount / umount / findmnt | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashpoll`](../loadables/bashpoll.c) | D S T F | Build/help | —; Python selectors / socket | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashsyslogd`](../loadables/bashsyslogd.c) | D S F | Build/help | syslogd; rsyslogd / syslogd | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashtermraw`](../loadables/bashtermraw.c) | D S F | Build/help | stty; stty | N/M | P3 | Add behavioral fixtures, then timing. |
| [`batch`](../loadables/batch.c) | S F | [Contract](../tests/misc-smoke.py) | —; batch (missing) | N/M | P3 | Add a matched workload and timing. |
| [`bc`](../loadables/bc.c) | S T F | [Parity](../tests/bc-parity.py); [limited](#scope-notes); [S](../tests/bc-sanitize.sh) | bc; bc | 4.848 / 64.443 / 63.779; [bc](#case-bc), 80 passes | P3 | Decide required option scope; see limitations. |
| [`bignum`](../loadables/bignum.c) | T F | [Contract](../tests/misc-smoke.py) | bc; Python int / bc | N/M | P3 | Add a matched workload and timing. |
| [`binhex`](../loadables/binhex.c) | D S F | Build/help | xxd; xxd | N/M | P3 | Add behavioral fixtures, then timing. |
| [`blkid`](../loadables/blkid.c) | D S F | Build/help | blkid; blkid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`blockdev`](../loadables/blockdev.c) | D S F | Build/help | blockdev; blockdev | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bsdgames`](../loadables/bsdgames.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; bsdgames (missing) | N/M | P3 | Add a matched workload and timing. |
| [`buf`](../loadables/buf.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cal`](../loadables/cal.c) | T F | [Contract](../tests/misc-smoke.py) | cal; cal (missing) | N/M | P3 | Add a matched workload and timing. |
| [`caps`](../loadables/caps.c) | S F | [Smoke](../tests/system-smoke.sh) | —; capsh / setpriv | N/M | P3 | Add behavioral fixtures, then timing. |
| `cat`* | P C D S T F | [Contract](../tests/host-smoke.sh) | cat; cat | 8.371 / 63.602 / 64.670; [cat](#case-cat), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chattr`](../loadables/chattr.c) | D S F | Build/help | —; chattr | N/M | P3 | Add behavioral fixtures, then timing. |
| [`chgrp`](../loadables/chgrp.c) | C D S T F | [Bench checked](#case-chgrp) | chgrp; chgrp | 5.511 / 111.758 / 92.705; [chgrp](#case-chgrp), 150 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `chmod`* | P C D S T F | [Bench checked](#case-chmod) | chmod; chmod | 4.041 / 89.295 / 72.428; [chmod](#case-chmod), 119 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chown`](../loadables/chown.c) | C D S T F | [Bench checked](#case-chown) | chown; chown | 4.760 / 90.487 / 75.419; [chown](#case-chown), 118 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chrt`](../loadables/chrt.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | —; chrt | N/M | P3 | Add a matched workload and timing. |
| [`cksum`](../loadables/cksum.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; cksum | 53.171 / — / 80.170; [cksum](#case-cksum), 47 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`claude`](../loadables/claude.c) | F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`clip`](../loadables/clip.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cluster`](../loadables/cluster.c) | F | [Smoke](../tests/misc-smoke.py) | —; API fixture | N/M | P3 | Add peer membership, timeout and disconnect fixtures. |
| [`cmp`](../loadables/cmp.c) | C D S T F | [Bench checked](#case-cmp) | cmp; cmp | 37.250 / 223.320 / 48.530; [cmp](#case-cmp), 55 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`col`](../loadables/col.c) | C D S T F | Build/help | —; col | N/M | P3 | Add behavioral fixtures, then timing. |
| [`colrm`](../loadables/colrm.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; colrm | 67.889 / — / 122.633; [colrm](#case-colrm), 23 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`column`](../loadables/column.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; column | 88.266 / — / 360.430; [column](#case-column), 7 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`comm`](../loadables/comm.c) | C D S T F | [Bench checked](#case-comm) | —; comm | 66.232 / — / 26.309; [comm](#case-comm), 16 passes | P2 | Profile input/output and allocation costs on the comm fixture, then measure the proposed change. |
| [`coreutils`](../loadables/coreutils.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; Individual coreutils programs | N/M | P3 | Add a matched workload and timing. |
| [`cp`](../loadables/cp.c) | C D S T F | [Contract](../tests/host-smoke.sh) | cp; cp | 13.928 / 71.240 / 83.254; [cp](#case-cp), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`cred`](../loadables/cred.c) | S F | [Smoke](../tests/system-smoke.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cron`](../loadables/cron.c) | S F | [Contract](../tests/large-smoke.py) | crond; cron / crond | N/M | P3 | Add a matched workload and timing. |
| [`crontab`](../loadables/crontab.c) | S F | [Contract](../tests/misc-smoke.py) | crontab; crontab | N/M | P3 | Add a matched workload and timing. |
| [`crypto`](../loadables/crypto.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | sha256sum; sha256sum / openssl | 83.783 / 81.154 / 55.084; [crypto](#case-crypto), 12 passes | P3 | Confirm crypto (1.52× external time), then profile. |
| [`csplit`](../loadables/csplit.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; csplit | N/M | P3 | Add a matched workload and timing. |
| [`curl`](../loadables/curl.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; curl | N/M | P3 | Add a matched workload and timing. |
| [`cut`](../loadables/cut.c) | P C D S T F | [Parity](../tests/cut-parity.sh) | cut; cut | 24.896 / 267.905 / 130.581; [cut](#case-cut), 59 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`date`](../loadables/date.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | date; date | 4.185 / 73.782 / 62.543; [date-ymd](#case-date-ymd), 107 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dd`](../loadables/dd.c) | C D S T F | [Bench checked](#case-dd) | dd; dd | 5.781 / 62.028 / 53.996; [dd](#case-dd), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`df`](../loadables/df.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | df; df | 18.652 / 107.771 / 99.389; [df](#case-df), 109 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dhcp6`](../loadables/dhcp6.c) | S F | [Contract](../tests/network-smoke.py) | udhcpc6; dhclient -6 | N/M | P3 | Add a matched workload and timing. |
| [`dhcpd`](../loadables/dhcpd.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | udhcpd; dnsmasq / dhcpd | N/M | P3 | Add a matched workload and timing. |
| [`dhcpd6`](../loadables/dhcpd6.c) | S F | [Contract](../tests/network-smoke.py) | —; kea-dhcp6 (missing) | N/M | P3 | Add a matched workload and timing. |
| [`dialog`](../loadables/dialog.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; dialog (missing) | N/M | P3 | Add a matched workload and timing. |
| [`diff`](../loadables/diff.c) | C D S T F | [Correctness bug](#additional-correctness-checks) | diff; diff | 70.291 / 66.840 / 44.839; [diff](#case-diff), 35 passes | P1 | Treat "-" as stdin and compare two minus operands using the same input bytes, then remeasure. Assigned to grok-bash-4. |
| `dirname`* | P C D S T F | [Bench checked](#case-dirname) | dirname; dirname | 4.341 / 92.567 / 76.056; [dirname](#case-dirname), 129 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dmesg`](../loadables/dmesg.c) | D S F | Build/help | dmesg; dmesg | N/M | P3 | Add behavioral fixtures, then timing. |
| [`dmsetup`](../loadables/dmsetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; dmsetup | N/M | P3 | Define required mapper mutation verbs and add isolated device fixtures. |
| [`dns`](../loadables/dns.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | nslookup; dig / drill | N/M | P3 | Add a matched workload and timing. |
| [`doas`](../loadables/doas.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; doas (missing) | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`du`](../loadables/du.c) | C D S T F | Build/help | du; du | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ed`](../loadables/ed.c) | C D S T F | Build/help | ed; ed (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`env`](../loadables/env.c) | C D S T F | [Contract](../tests/regressions.py) | env; env | 38.598 / 69.160 / 60.351; [env](#case-env), 70 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`escdelay`](../loadables/escdelay.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`expand`](../loadables/expand.c) | C D S T F | [Parity](../tests/expand-parity.py); [limited](#scope-notes); [S](../tests/expand-sanitize.sh) | expand; expand | 57.677 / 258.313 / 66.695; [expand](#case-expand), 34 passes | P3 | Decide required option scope; see limitations. |
| [`expect`](../loadables/expect.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; expect (missing) | N/M | P3 | Add a matched workload and timing. |
| [`expr`](../loadables/expr.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | expr; expr | 4.065 / 103.137 / 89.712; [expr](#case-expr), 146 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`fail2ban`](../loadables/fail2ban.c) | S F | [Contract](../tests/network-smoke.py) | —; fail2ban-client (missing) | N/M | P3 | Add a matched workload and timing. |
| `fdflags`* | D S F | Build/help | —; Python fcntl | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fdisk`](../loadables/fdisk.c) | D S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | fdisk; fdisk | N/M | P3 | Add a matched workload and timing. |
| [`fifo`](../loadables/fifo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`file`](../loadables/file.c) | T F | [Contract](../tests/misc-smoke.py) | —; file | N/M | P3 | Add a matched workload and timing. |
| [`fincore`](../loadables/fincore.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; fincore | N/M | P3 | Add behavioral fixtures, then timing. |
| [`find`](../loadables/find.c) | C D S T F | [Contract](../tests/regressions.py) | find; find | 25.817 / 91.764 / 83.396; [find](#case-find), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `finfo`* | D S F | Build/help | stat; stat | N/M | P3 | Add behavioral fixtures, then timing. |
| [`flock`](../loadables/flock.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | —; flock | 41.078 / — / 80.069; [flock](#case-flock), 83 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `fltexpr`* | D S F | Build/help | awk; awk / bc | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fold`](../loadables/fold.c) | C D S T F | [Parity](../tests/fold-parity.py); [limited](#scope-notes); [S](../tests/fold-sanitize.sh) | fold; fold | 53.248 / 207.353 / 126.044; [fold](#case-fold), 50 passes | P3 | Decide required option scope; see limitations. |
| [`free`](../loadables/free.c) | C D S T F | Build/help | free; free | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fsck`](../loadables/fsck.c) | D S F | [Contract](../tests/misc-smoke.py) | —; fsck | N/M | P3 | Add a matched workload and timing. |
| [`fsfreeze`](../loadables/fsfreeze.c) | D S F | Build/help | fsfreeze; fsfreeze | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fstrim`](../loadables/fstrim.c) | D S F | Build/help | fstrim; fstrim | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fw`](../loadables/fw.c) | S F | [Contract](../tests/large-smoke.py) | —; nft / iptables | N/M | P3 | Add a matched workload and timing. |
| [`genl`](../loadables/genl.c) | D S F | Build/help | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| `getconf`* | D S F | [Bench checked](#case-getconf-nproc) | —; getconf | 4.940 / — / 68.731; [getconf-nproc](#case-getconf-nproc), 123 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`getfacl`](../loadables/getfacl.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; getfacl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`gpu`](../loadables/gpu.c) | T F | [Contract](../tests/gpu-smoke.py); [S](../tests/gpu-sanitize.sh) | —; API fixture | [Transport data](#graphics-metrics); no applet ratio | P3 | Measure application frame latency and driver behavior on the intended device. |
| [`grep`](../loadables/grep.c) | C D S T F | [Parity](../tests/grep-parity.sh); [limited](#scope-notes); [S](../tests/grep-host.c) | grep; grep | 60.645 / 464.223 / 51.343; [grep-lines](#case-grep-lines), 64 passes; 2 cases total | P3 | Decide required option scope; see limitations. |
| [`halt`](../loadables/halt.c) | D S F | Build/help | halt; halt | N/M | P3 | Add behavioral fixtures, then timing. |
| `head`* | P C D S T F | [Parity](../tests/head-sed-parity.py); [limited](#scope-notes); [S](../tests/head-sed-sanitize.sh) | head; head | 9.653 / 64.140 / 51.550; [head](#case-head), 80 passes | P3 | Decide required option scope; see limitations. |
| [`hexdump`](../loadables/hexdump.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | hexdump; hexdump | 81.659 / 100.196 / 131.270; [hexdump](#case-hexdump), 11 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`hl`](../loadables/hl.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; highlight (missing) | N/M | P3 | Add a matched workload and timing. |
| [`hostid`](../loadables/hostid.c) | D S F | Build/help | hostid; hostid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`hostname`](../loadables/hostname.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | hostname; hostname | 4.717 / 112.777 / 90.821; [hostname-s](#case-hostname-s), 122 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`http`](../loadables/http.c) | D S F | [Contract](../tests/network-smoke.py) | wget; curl | N/M | P3 | Add a matched workload and timing. |
| [`httpd`](../loadables/httpd.c) | S F | [Contract](../tests/httpd-host.c); [S](../tests/run.sh) | httpd; HTTP server fixture | N/M | P3 | Add a matched workload and timing. |
| [`hwclock`](../loadables/hwclock.c) | D S F | Build/help | hwclock; hwclock | N/M | P3 | Add behavioral fixtures, then timing. |
| `id`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | id; id | 5.817 / 97.085 / 101.429; [id-group](#case-id-group), 127 passes; 3 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`index`](../loadables/index.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git update-index | N/M | P3 | Add a matched workload and timing. |
| [`integrity`](../loadables/integrity.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`ionice`](../loadables/ionice.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | ionice; ionice | 4.049 / 98.877 / 81.121; [ionice](#case-ionice), 142 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ip`](../loadables/ip.c) | D S F | Build/help | ip; ip | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ipcctl`](../loadables/ipcctl.c) | D S F | Build/help | ipcs (not in build); ipcs / ipcrm | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ipcmk`](../loadables/ipcmk.c) | D S F | Build/help | —; ipcmk | N/M | P3 | Add behavioral fixtures, then timing. |
| [`join`](../loadables/join.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; join | 73.366 / — / 46.391; [join](#case-join), 19 passes | P3 | Confirm join (1.58× external time), then profile. |
| [`jq`](../loadables/jq.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; jq | 74.028 / — / 102.110; [jq](#case-jq), 12 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`keyctl`](../loadables/keyctl.c) | S F | Build/help | —; keyctl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`kgetch`](../loadables/kgetch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`killall`](../loadables/killall.c) | C D S T F | Build/help | killall; killall (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`killall5`](../loadables/killall5.c) | F | Build/help | —; killall5 | N/M | P3 | Add behavioral fixtures, then timing. |
| [`kitty`](../loadables/kitty.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; kitten icat | N/M | P3 | Add a matched workload and timing. |
| [`ldap`](../loadables/ldap.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-ldap.c) | —; ldapsearch (missing) | N/M | P3 | Add a matched workload and timing. |
| [`less`](../loadables/less.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | less; less | N/M | P3 | Add a matched workload and timing. |
| [`link`](../loadables/link.c) | C D S T F | Build/help | link; link | N/M | P3 | Add behavioral fixtures, then timing. |
| `ln`* | P C D S T F | [Bench checked](#case-ln) | ln; ln | 4.898 / 86.318 / 76.325; [ln](#case-ln), 121 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`locale`](../loadables/locale.c) | T F | [Contract](../tests/misc-smoke.py) | —; locale / Python locale | N/M | P3 | Add a matched workload and timing. |
| [`login`](../loadables/login.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | login; login | N/M | P3 | Add a matched workload and timing. |
| `logname`* | P C D S T F | [Bench checked](#case-logname) | logname; logname | 5.043 / 98.179 / 78.951; [logname](#case-logname), 127 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`losetup`](../loadables/losetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | losetup; losetup | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lpr`](../loadables/lpr.c) | F | [Smoke](../tests/misc-smoke.py); [limited](#scope-notes) | lpr (not in build); lpr (missing) | N/M | P3 | Decide whether real print delivery belongs in this loadable. |
| [`ls`](../loadables/ls.c) | C D S T F | [Bench checked](#case-ls) | ls; ls | 16.441 / 90.824 / 81.621; [ls](#case-ls), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`lsattr`](../loadables/lsattr.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; lsattr | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lsblk`](../loadables/lsblk.c) | D S F | Build/help | —; lsblk | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lsof`](../loadables/lsof.c) | D S T F | [Smoke](../tests/system-smoke.sh) | —; lsof | N/M | P3 | Add behavioral fixtures, then timing. |
| [`mail`](../loadables/mail.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | sendmail (not in build); sendmail / mailq | N/M | P3 | Add a controlled submission/delivery benchmark. |
| [`man`](../loadables/man.c) | T F | [Contract](../tests/misc-smoke.py) | —; man | N/M | P3 | Add a matched workload and timing. |
| `mkdir`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | mkdir; mkdir | 3.963 / 95.221 / 103.401; [mkdir](#case-mkdir), 134 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `mkfifo`* | P C D S T F | Build/help | mkfifo; mkfifo | N/M | P3 | Add behavioral fixtures, then timing. |
| [`mkfs`](../loadables/mkfs.c) | D S F | [Contract](../tests/misc-smoke.py) | —; mkfs | N/M | P3 | Add a matched workload and timing. |
| [`mkswap`](../loadables/mkswap.c) | D S F | Build/help | mkswap; mkswap | N/M | P3 | Add behavioral fixtures, then timing. |
| `mktemp`* | P C D S T F | Build/help | mktemp; mktemp | N/M | P3 | Add behavioral fixtures, then timing. |
| [`mlock`](../loadables/mlock.c) | D S F | [Smoke](../tests/system-smoke.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`more`](../loadables/more.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | more; more | N/M | P3 | Add a matched workload and timing. |
| [`mouse`](../loadables/mouse.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`mv`](../loadables/mv.c) | C D S T F | Build/help | mv; mv | N/M | P3 | Add behavioral fixtures, then timing. |
| [`nano`](../loadables/nano.c) | T F | [Contract](../tests/final-smoke.py); [limited](#scope-notes); [S](../tests/final-sanitize.sh) | —; nano | N/M | P3 | Decide required option scope; see limitations. |
| [`nano2`](../loadables/nano2.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; nano | N/M | P3 | Add a matched workload and timing. |
| [`nc`](../loadables/nc.c) | D S F | [Contract](../tests/network-smoke.py) | nc; nc | N/M | P3 | Add a matched workload and timing. |
| [`ncdu`](../loadables/ncdu.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; ncdu | N/M | P3 | Add a matched workload and timing. |
| [`netids`](../loadables/netids.c) | S F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; suricata (missing) | N/M | P3 | Add a matched workload and timing. |
| [`netstat`](../loadables/netstat.c) | D S F | Build/help | netstat; netstat (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`nice`](../loadables/nice.c) | C D S T F | [Contract](../tests/regressions.py) | —; nice | 27.322 / — / 43.830; [nice](#case-nice), 52 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`nl`](../loadables/nl.c) | C D S T F | [Parity](../tests/nl-parity.py); [limited](#scope-notes); [S](../tests/nl-sanitize.sh) | nl; nl | 50.805 / 230.896 / 124.638; [nl](#case-nl), 55 passes | P3 | Decide required option scope; see limitations. |
| [`nohup`](../loadables/nohup.c) | C D S T F | [Contract](../tests/regressions.py) | —; nohup | 36.118 / — / 60.124; [nohup](#case-nohup), 71 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`notify`](../loadables/notify.c) | T F | [Contract](../tests/misc-smoke.py) | —; systemd-notify | N/M | P3 | Add a matched workload and timing. |
| [`ns`](../loadables/ns.c) | S F | [Smoke](../tests/system-smoke.sh) | unshare; unshare / nsenter | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ntp`](../loadables/ntp.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | ntpd (not in build); chronyc / ntpd | N/M | P3 | Add a matched workload and timing. |
| [`obj`](../loadables/obj.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git hash-object / cat-file | N/M | P3 | Add a matched workload and timing. |
| [`od`](../loadables/od.c) | C D S T F | [Bench checked](#case-od) | od; od | 72.697 / 60.780 / 133.747; [od](#case-od), 12 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`opt`](../loadables/opt.c) | T F | [Contract](../tests/misc-smoke.py) | getopt; getopt | N/M | P3 | Add a matched workload and timing. |
| [`pack`](../loadables/pack.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git pack-objects / index-pack | N/M | P3 | Add a matched workload and timing. |
| [`passwd`](../loadables/passwd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | passwd; passwd | N/M | P3 | Add a matched workload and timing. |
| [`paste`](../loadables/paste.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | paste; paste | 75.320 / 401.296 / 73.930; [paste](#case-paste), 10 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `pathchk`* | P C D S T F | [Bench checked](#case-pathchk) | —; pathchk | 3.880 / — / 77.178; [pathchk](#case-pathchk), 107 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
| [`pr`](../loadables/pr.c) | C D S T F | [Parity](../tests/pr-parity.py); [limited](#scope-notes); [S](../tests/pr-sanitize.sh) | —; pr | 24.147 / — / 370.658; [pr](#case-pr), 80 passes | P3 | Decide required option scope; see limitations. |
| `printenv`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | —; printenv | 3.938 / — / 63.410; [printenv-lcall](#case-printenv-lcall), 112 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`prlimit`](../loadables/prlimit.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; prlimit | N/M | P3 | Add behavioral fixtures, then timing. |
| [`procstat`](../loadables/procstat.c) | D S T F | [Contract](../tests/procstat-smoke.py); [S](../tests/procstat-sanitize.sh) | —; iostat / mpstat / sar / pidstat / pmap / pldd | N/M | P3 | Add a matched workload and timing. |
| [`ps`](../loadables/ps.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | ps; ps | N/M | P3 | Add a matched workload and timing. |
| [`pty`](../loadables/pty.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; Python pty | N/M | P3 | Add a matched workload and timing. |
| [`ptybroker`](../loadables/ptybroker.c) | T F | Build/help | —; ptybroker (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`readlink`](../loadables/readlink.c) | C D S T F | [Bench checked](#case-readlink) | readlink; readlink | 3.833 / 92.081 / 75.698; [readlink](#case-readlink), 120 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `realpath`* | P C D S T F | [Bench checked](#case-realpath) | realpath; realpath | 5.531 / 120.401 / 98.150; [realpath](#case-realpath), 124 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`reboot`](../loadables/reboot.c) | D S F | Build/help | reboot; reboot | N/M | P3 | Add behavioral fixtures, then timing. |
| [`renice`](../loadables/renice.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | renice; renice | N/M | P3 | Add behavioral fixtures, then timing. |
| [`rev`](../loadables/rev.c) | C D S T F | [Bench checked](#case-rev) | rev; rev | 66.166 / 37.455 / 127.183; [rev](#case-rev), 14 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `rm`* | P C D S T F | [Bench checked](#case-rm) | rm; rm | 3.869 / 97.782 / 79.475; [rm](#case-rm), 136 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `rmdir`* | P C D S T F | Build/help | rmdir; rmdir | N/M | P3 | Add behavioral fixtures, then timing. |
| [`rngseed`](../loadables/rngseed.c) | D S F | [Contract](../tests/rngseed-host.c); [S](../tests/run.sh) | seedrng (not in build); systemd-random-seed (missing) | N/M | P3 | Add a matched workload and timing. |
| [`rsync`](../loadables/rsync.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; rsync | N/M | P3 | Add a matched workload and timing. |
| [`rtspcat`](../loadables/rtspcat.c) | F | Build/help | —; ffmpeg / openRTSP | N/M | P3 | Add a controlled RTSP/RTP stream with loss, reordering and framing checks. |
| [`scm`](../loadables/scm.c) | F | [Contract](../tests/misc-smoke.py) | —; Python socket SCM_RIGHTS | N/M | P3 | Add a matched workload and timing. |
| [`scp`](../loadables/scp.c) | S F | [Contract](../tests/network-smoke.py) | —; scp | N/M | P3 | Add a matched workload and timing. |
| [`screen`](../loadables/screen.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; screen (missing) | N/M | P3 | Measure live PTY relay, backpressure and cleanup. |
| [`script`](../loadables/script.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; script | N/M | P3 | Add a matched workload and timing. |
| [`scrub`](../loadables/scrub.c) | F | [Contract](../tests/misc-smoke.py) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`sed`](../loadables/sed.c) | C D S T F | [Parity](../tests/head-sed-parity.py); [limited](#scope-notes); [S](../tests/head-sed-sanitize.sh) | sed; sed | 69.457 / 80.760 / 57.735; [sed](#case-sed), 9 passes | P3 | Decide required option scope; see limitations. |
| [`seq`](../loadables/seq.c) | P C D S T F | [Parity](../tests/seq-parity.sh) | seq; seq | 52.803 / 1422.523 / 52.144; [seq](#case-seq), 40 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`setfacl`](../loadables/setfacl.c) | D S F | Build/help | —; setfacl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| `setpgid`* | D S F | Build/help | —; Python os.setpgid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`setsid`](../loadables/setsid.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | setsid; setsid | 37.899 / 74.902 / 65.282; [setsid](#case-setsid), 74 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sftp`](../loadables/sftp.c) | S F | [Contract](../tests/network-smoke.py) | —; sftp | N/M | P3 | Add a matched workload and timing. |
| [`signal`](../loadables/signal.c) | D S F | [Contract](../tests/system-smoke.sh) | kill; kill -l / Bash kill | N/M | P3 | Add a matched workload and timing. |
| [`sixel`](../loadables/sixel.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; img2sixel (missing) | N/M | P3 | Add a matched workload and timing. |
| [`slabtop`](../loadables/slabtop.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; slabtop | N/M | P3 | Add a matched workload and timing. |
| `sleep`* | P C D S T F | [Bench checked](#case-sleep) | sleep; sleep | 11.390 / 98.537 / 84.003; [sleep](#case-sleep), 136 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sort`](../loadables/sort.c) | C D S T F | [Parity](../tests/sort-parity.sh) | sort; sort | 73.756 / 72.196 / 31.660; [sort-text](#case-sort-text), 10 passes; 2 cases total | P2 | Profile input/output and allocation costs on the sort-text fixture, then measure the proposed change. |
| [`split`](../loadables/split.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; split | N/M | P3 | Add a matched workload and timing. |
| [`sqlite`](../loadables/sqlite.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; sqlite3 / Python sqlite3 | N/M | P3 | Add a matched workload and timing. |
| [`ss`](../loadables/ss.c) | D S F | Build/help | —; ss | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ssh`](../loadables/ssh.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; ssh | N/M | P3 | Add a matched workload and timing. |
| [`sshd`](../loadables/sshd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sshd | N/M | P3 | Add a matched workload and timing. |
| [`stat`](../loadables/stat.c) | P C D S T F | [Parity](../tests/stat-parity.sh) | stat; stat | 4.189 / 99.154 / 95.729; [stat](#case-stat), 124 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`strace`](../loadables/strace.c) | F | [Contract](../tests/large-smoke.py) | —; strace (missing) | N/M | P3 | Add a matched workload and timing. |
| `strftime`* | P C D S T F | Build/help | date; date / Bash printf | N/M | P3 | Add behavioral fixtures, then timing. |
| [`strings`](../loadables/strings.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | strings; strings | 28.865 / 83.415 / 126.163; [strings](#case-strings), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `strptime`* | P C D S T F | Build/help | —; Python datetime.strptime | N/M | P3 | Add behavioral fixtures, then timing. |
| [`su`](../loadables/su.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | su; su | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sudo`](../loadables/sudo.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sudo | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sv`](../loadables/sv.c) | S F | [Contract](../tests/large-smoke.py) | —; runit sv | N/M | P3 | Add a matched workload and timing. |
| [`swapoff`](../loadables/swapoff.c) | D S F | Build/help | swapoff; swapoff | N/M | P3 | Add behavioral fixtures, then timing. |
| [`swapon`](../loadables/swapon.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | swapon; swapon | N/M | P3 | Add behavioral fixtures, then timing. |
| `sync`* | P C D S T F | [Bench checked](#case-sync) | sync; sync | 6.070 / 22.557 / 19.131; [sync](#case-sync), 20 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sysctl`](../loadables/sysctl.c) | D S F | [Contract](../tests/system-smoke.sh) | sysctl; sysctl | 4.725 / 86.759 / 72.179; [sysctl](#case-sysctl), 124 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tac`](../loadables/tac.c) | C D S T F | [Parity](../tests/tac-parity.py); [limited](#scope-notes); [S](../tests/tac-sanitize.sh) | tac; tac | 9.074 / 188.217 / 39.204; [tac](#case-tac), 40 passes | P3 | Decide bounded-memory input and GNU regex scope; see the tac follow-up. |
| [`tail`](../loadables/tail.c) | C D S T F | [Parity](../tests/wc-tail-parity.sh) | tail; tail | 5.092 / 133.554 / 57.093; [tail](#case-tail), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`taskset`](../loadables/taskset.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | taskset; taskset | 3.779 / 80.443 / 64.532; [taskset](#case-taskset), 113 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `tee`* | P C D S T F | [Correctness bug](#additional-correctness-checks) | tee; tee | N/M | P1 | Stop reading when every output has failed, preserving healthy destinations; then remeasure. Assigned to grok-bash-3. |
| [`termpixel`](../loadables/termpixel.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`termpixel_pong`](../loadables/termpixel_pong.c) | F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`timeout`](../loadables/timeout.c) | C D S T F | [Contract](../tests/system-smoke.sh) | timeout; timeout | N/M | P3 | Add a matched workload and timing. |
| [`tinfo`](../loadables/tinfo.c) | T F | Build/help | —; infocmp / tput | N/M | P3 | Add behavioral fixtures, then timing. |
| [`tiv`](../loadables/tiv.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; chafa (missing) | N/M | P3 | Add a matched workload and timing. |
| [`toml`](../loadables/toml.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh); [Fz](../tests/fuzz-toml.c) | —; Python tomllib | N/M | P3 | Add a matched workload and timing. |
| [`top`](../loadables/top.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | top; top | N/M | P3 | Add a matched workload and timing. |
| [`totp`](../loadables/totp.c) | F | [Contract](../tests/misc-smoke.py) | —; oathtool (missing) | N/M | P3 | Add a matched workload and timing. |
| [`touch`](../loadables/touch.c) | C D S T F | [Bench checked](#case-touch) | touch; touch | 3.721 / 78.002 / 65.572; [touch](#case-touch), 118 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tput`](../loadables/tput.c) | T F | Build/help | —; tput | N/M | P3 | Add behavioral fixtures, then timing. |
| [`tr`](../loadables/tr.c) | C D S T F | [Bench checked](#case-tr) | tr; tr | 46.042 / 90.490 / 52.194; [tr](#case-tr), 62 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`truncate`](../loadables/truncate.c) | C D S T F | Build/help | truncate; truncate | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ts`](../loadables/ts.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; tree-sitter (missing) | N/M | P3 | Add a matched workload and timing. |
| `tty`* | P C D S T F | Build/help | tty; tty | N/M | P3 | Add behavioral fixtures, then timing. |
| [`tui`](../loadables/tui.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`tz`](../loadables/tz.c) | T F | [Contract](../tests/misc-smoke.py) | date; date / Python zoneinfo | N/M | P3 | Add a matched workload and timing. |
| [`uclampset`](../loadables/uclampset.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; uclampset | N/M | P3 | Decide whether to implement the missing setter surface. |
| `uname`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | uname; uname | 4.143 / 81.471 / 65.265; [uname-s](#case-uname-s), 87 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`undo`](../loadables/undo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`unexpand`](../loadables/unexpand.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | unexpand; unexpand | 80.489 / 97.339 / 39.995; [unexpand](#case-unexpand), 9 passes | P3 | Confirm unexpand (2.01× external time), then profile. |
| [`uniq`](../loadables/uniq.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | uniq; uniq | 74.467 / 439.148 / 94.957; [uniq](#case-uniq), 19 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `unlink`* | P C D S T F | Build/help | unlink; unlink | N/M | P3 | Add behavioral fixtures, then timing. |
| [`uptime`](../loadables/uptime.c) | D S T F | [Smoke](../tests/system-smoke.sh) | uptime; uptime | 8.760 / 89.558 / 119.479; [uptime](#case-uptime), 95 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
| [`wc`](../loadables/wc.c) | C D S T F | [Parity](../tests/wc-tail-parity.sh) | wc; wc | 55.391 / 114.215 / 28.314; [wc-characters](#case-wc-characters), 34 passes; 3 cases total | P3 | Confirm wc-characters (1.96× external time), then profile. |
| [`wg`](../loadables/wg.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; wg (missing) | N/M | P3 | Add a matched workload and timing. |
| [`wget_wch`](../loadables/wget_wch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`wgetch`](../loadables/wgetch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`whatis`](../loadables/whatis.c) | T F | [Contract](../tests/misc-smoke.py) | —; whatis | N/M | P3 | Add a matched workload and timing. |
| [`whiptail`](../loadables/whiptail.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; whiptail | N/M | P3 | Add a matched workload and timing. |
| [`who`](../loadables/who.c) | D S T F | [Smoke](../tests/system-smoke.sh) | who; who | N/M | P3 | Add behavioral fixtures, then timing. |
| `whoami`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | whoami; whoami | 4.283 / 119.815 / 104.245; [whoami](#case-whoami), 156 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
These checks used source `db921ad9d9d73177d37cf5288e23a598620f7da7` and the same binary as the command measurements. The [evidence JSON](data/loadable-untimed-findings.json) records fixtures, references, exit statuses, output and created files. These cases have no timing measurements.

| Loadable | Invocation | Finding |
| --- | --- | --- |
| `diff` | `printf 'hello\n' &#124; diff - -` | A minus operand is opened as a file named '-'; two minus operands therefore fail instead of comparing the same stdin bytes. |
| `tee` | `timeout 2 tee /dev/full >/dev/full < /dev/zero` | After every output has failed the builtin keeps reading stdin until timeout 124; GNU tee returns 1 promptly. |
<!-- END UNTIMED -->

## Scope notes

These are specific reviewed limits or gaps, not an exhaustive option audit.
Source comments alone were not treated as proof of an unimplemented feature.

<!-- BEGIN NOTES -->
| Loadable | Scope / limitation |
| --- | --- |
| `ar` | Truncated member headers are rejected (tests/ar-check.sh). Coordinator probes on this binary already match GNU 2.44 on symlink/hard-link archive updates and extract-over-symlink. Extract still copies with fgetc/fputc and does not check write errors; a remaining recovery review is assigned. |
| `bc` | Repeated stdin is fixed. User functions, output-base printing, control flow, comments and file operands remain outside the supported language subset. [source](../docs/bc.md) |
| `cluster` | Only a version smoke check is mapped here. |
| `col` | Repeated redirected stdin is fixed; tests/col-check.sh matches GNU on three fresh redirections. |
| `colrm` | Repeated redirected stdin is fixed; tests/colrm-check.sh matches GNU on three fresh redirections. |
| `column` | Repeated redirected stdin is fixed; tests/column-check.sh matches GNU on three fresh redirections. |
| `comm` | Repeated-input and write-failure contracts are covered by tests/comm-check.sh. The timed comm case remains slower than GNU on this host. |
| `cp` | A forced copy that cannot read its source keeps the existing destination; tests/cp-check.sh matches GNU. |
| `crypto` | A failed digest write now returns failure; tests/crypto-check.sh covers sha256 -x > /dev/full. |
| `csplit` | Repeated redirected stdin is fixed; tests/csplit-check.sh matches GNU piece files across three redirections. |
| `diff` | The final-newline-only difference is fixed and timed. The timed case still measures identical files, not edit-script generation. |
| `dmsetup` | Some mutation verbs still return an explicit unimplemented-backend error. [source](../loadables/dmsetup.c) |
| `doas` | Current integration test rejects an invalid option before credential transition. |
| `du` | A failed size-report write now returns failure; tests/du-check.sh covers du -b file > /dev/full. |
| `expand` | Buffered output and per-invocation input are validated. Documented option/tab-stop differences and locale scope remain; tiny-input speedup is not established. [source](../docs/expand.md) |
| `fold` | Buffered ASCII processing is validated; the existing permissive UTF-8 decoder and short-input fread lookahead behavior remain. Unicode and appliance throughput are not established. [source](../docs/fold.md) |
| `free` | tests/free-check.sh matches GNU field layout on a private meminfo, including buff/cache as Buffers+Cached+SReclaimable. Live `free -k` timings are not published because counters move between invocations. |
| `gpu` | CPU/protocol, native driver and isolated Kilix checks exist. Static builds support CPU presentation; native shaders require dynamic linking. |
| `grep` | Default build disables -P; the separate pcre loadable supplies PCRE2 operations. See the source build switch. [source](../loadables/grep.c) |
| `head` | Repeated stdin is fixed. The stock Bash option subset remains; private streams restore seekable read-ahead and use unbuffered pipe input. [source](../docs/head-sed.md) |
| `hexdump` | Repeated redirected stdin is fixed; tests/hexdump-check.sh matches GNU on three fresh redirections. |
| `hostid` | Default is gethostid(3), matching hostid(1), including on this measured full binary. tests/hostid-check.sh covers override files and the machine-id fallback. [source](../docs/hostid.md) |
| `join` | Write-failure stop and GNU comparison are covered by tests/join-check.sh. |
| `ldap` | BER/filter fixtures and bounded fuzzing pass; live server/authentication throughput is unmeasured. |
| `lpr` | Submit copies into a spool and sleeps to simulate printing. No real printer throughput claim. [source](../loadables/lpr.c) |
| `mail` | Alias compilation/expansion fixtures exist; no SMTP delivery throughput measurement. |
| `mv` | Moving a file to itself now fails and preserves bytes; tests/mv-check.sh matches GNU. |
| `nano` | Editor selftests pass; justify, spell and completion still report unimplemented. [source](../loadables/nano.c) |
| `nl` | Repeated stdin, stale stream read-ahead and named-file descriptor ownership are fixed. BRE matching uses the host regex library; without REG_STARTEND, patterns cannot match past embedded NUL bytes. [source](../docs/nl.md) |
| `od` | Repeated redirected stdin is fixed; tests/od-check.sh matches GNU on three fresh redirections. |
| `payload` | Install/remove invoke a helper outside this repository; the current fixture only calls help. [source](../loadables/payload.c) |
| `pgrep` | Matching is substring-based unless exact matching is selected; not full procps regular-expression behavior. [source](../loadables/pgrep.c) |
| `pkill` | Shares pgrep matching and process traversal; validate signals only against owned child fixtures. [source](../loadables/pkill.c) |
| `pr` | Repeated stdin, paging and output failures are fixed for the tested subset. Numbered multi-column control bytes, merged unterminated records and several GNU options remain documented exclusions. [source](../docs/pr.md) |
| `rev` | Write-failure stop and GNU comparison are covered by tests/rev-check.sh. |
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
| `tee` | Closed-stdin now returns failure via patches/tee-io.patch. Stock examples/loadables/tee.c is still the source. |
| `truncate` | Size arithmetic overflow is rejected and existing bytes are preserved; tests/truncate-check.sh matches GNU. |
| `uclampset` | Query subset; setting PID/system clamps and command mode are refused. [source](../loadables/uclampset.c) |
| `unexpand` | Write-failure stop and GNU comparison are covered by tests/unexpand-check.sh. |
| `wc` | Requested word-count assertions are covered by tests/wc-check.sh and tests/wc-tail-parity.sh. |
| `zstd` | Default-level stdin compress/decompress is ahead of host zstd(1) on the catalog binary; frames are not byte-identical and validation is round-trip. BusyBox has no applet. Whole-file reads and one-shot ZSTD_compress remain. [source](../docs/zstd.md) |
<!-- END NOTES -->

## Individual benchmark cases

<!-- BEGIN CASES -->
| Case | Builtin command | External command | Input | Passes | BOS ms | BB ms | External ms | BOS / external | Samples |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| <a id="case-cat"></a>cat | `cat` | `cat` | text (423,000 stdin bytes) | 80 | 8.371 | 63.602 | 64.670 | 0.13× | 7 |
| <a id="case-head"></a>head | `head -n 100` | `head -n 100` | text (423,000 stdin bytes) | 80 | 9.653 | 64.140 | 51.550 | 0.19× | 7 |
| <a id="case-tail"></a>tail | `tail -n 100` | `tail -n 100` | text (423,000 stdin bytes) | 80 | 5.092 | 133.554 | 57.093 | 0.09× | 7 |
| <a id="case-wc-counts"></a>wc-counts | `wc -lwc` | `wc -lwc` | text (423,000 stdin bytes) | 30 | 44.928 | 96.619 | 61.979 | 0.72× | 7 |
| <a id="case-wc-characters"></a>wc-characters | `wc -m` | `wc -m` | text (423,000 stdin bytes) | 34 | 55.391 | 114.215 | 28.314 | 1.96× | 7 |
| <a id="case-wc-width"></a>wc-width | `wc -L` | `wc -L` | text (423,000 stdin bytes) | 39 | 57.907 | 126.906 | 76.296 | 0.76× | 7 |
| <a id="case-cut"></a>cut | `cut -d ' ' -f 1` | `cut -d ' ' -f 1` | text (423,000 stdin bytes) | 59 | 24.896 | 267.905 | 130.581 | 0.19× | 7 |
| <a id="case-grep-count"></a>grep-count | `grep -c alpha` | `grep -c alpha` | text (423,000 stdin bytes) | 61 | 41.825 | 424.334 | 51.422 | 0.81× | 7 |
| <a id="case-grep-lines"></a>grep-lines | `grep alpha` | `grep alpha` | text (423,000 stdin bytes) | 64 | 60.645 | 464.223 | 51.343 | 1.18× | 7 |
| <a id="case-sed"></a>sed | `sed s/alpha/OMEGA/g` | `sed s/alpha/OMEGA/g` | text (423,000 stdin bytes) | 9 | 69.457 | 80.760 | 57.735 | 1.20× | 7 |
| <a id="case-sort-numeric"></a>sort-numeric | `sort -n` | `sort -n` | numbers (369,296 stdin bytes) | 5 | 71.899 | 534.490 | 135.083 | 0.53× | 7 |
| <a id="case-sort-text"></a>sort-text | `sort` | `sort` | text (423,000 stdin bytes) | 10 | 73.756 | 72.196 | 31.660 | 2.33× | 7 |
| <a id="case-seq"></a>seq | `seq 100000` | `seq 100000` | No stdin; named fixtures / arguments | 40 | 52.803 | 1422.523 | 52.144 | 1.01× | 7 |
| <a id="case-tr"></a>tr | `tr a-z A-Z` | `tr a-z A-Z` | text (423,000 stdin bytes) | 62 | 46.042 | 90.490 | 52.194 | 0.88× | 7 |
| <a id="case-uniq"></a>uniq | `uniq` | `uniq` | duplicates (1,680,000 stdin bytes) | 19 | 74.467 | 439.148 | 94.957 | 0.78× | 7 |
| <a id="case-paste"></a>paste | `paste duplicates duplicates` | `paste duplicates duplicates` | No stdin; named fixtures / arguments | 10 | 75.320 | 401.296 | 73.930 | 1.02× | 7 |
| <a id="case-nl"></a>nl | `nl -ba` | `nl -ba` | text (423,000 stdin bytes) | 55 | 50.805 | 230.896 | 124.638 | 0.41× | 7 |
| <a id="case-rev"></a>rev | `rev` | `rev` | text (423,000 stdin bytes) | 14 | 66.166 | 37.455 | 127.183 | 0.52× | 7 |
| <a id="case-fold"></a>fold | `fold -w 40` | `fold -w 40` | text (423,000 stdin bytes) | 50 | 53.248 | 207.353 | 126.044 | 0.42× | 7 |
| <a id="case-tac"></a>tac | `tac` | `tac` | text (423,000 stdin bytes) | 40 | 9.074 | 188.217 | 39.204 | 0.23× | 7 |
| <a id="case-comm"></a>comm | `comm left right` | `comm left right` | No stdin; named fixtures / arguments | 16 | 66.232 | — | 26.309 | 2.52× | 7 |
| <a id="case-join"></a>join | `join left right` | `join left right` | No stdin; named fixtures / arguments | 19 | 73.366 | — | 46.391 | 1.58× | 7 |
| <a id="case-expand"></a>expand | `expand -t 8` | `expand -t 8` | tabs (340,000 stdin bytes) | 34 | 57.677 | 258.313 | 66.695 | 0.86× | 7 |
| <a id="case-unexpand"></a>unexpand | `unexpand -a` | `unexpand -a` | spaces (440,000 stdin bytes) | 9 | 80.489 | 97.339 | 39.995 | 2.01× | 7 |
| <a id="case-pr"></a>pr | `pr -t` | `pr -t` | text (423,000 stdin bytes) | 80 | 24.147 | — | 370.658 | 0.07× | 7 |
| <a id="case-colrm"></a>colrm | `colrm 4` | `colrm 4` | text (423,000 stdin bytes) | 23 | 67.889 | — | 122.633 | 0.55× | 7 |
| <a id="case-column"></a>column | `column -t` | `column -t` | tabs (340,000 stdin bytes) | 7 | 88.266 | — | 360.430 | 0.24× | 7 |
| <a id="case-strings"></a>strings | `strings -n 4` | `strings -n 4` | bytes (65,536 stdin bytes) | 80 | 28.865 | 83.415 | 126.163 | 0.23× | 7 |
| <a id="case-od"></a>od | `od -An -tx1` | `od -An -tx1` | bytes (65,536 stdin bytes) | 12 | 72.697 | 60.780 | 133.747 | 0.54× | 7 |
| <a id="case-hexdump"></a>hexdump | `hexdump -C` | `hexdump -C` | bytes (65,536 stdin bytes) | 11 | 81.659 | 100.196 | 131.270 | 0.62× | 7 |
| <a id="case-basename"></a>basename | `basename /fixture/path/file.txt` | `basename /fixture/path/file.txt` | No stdin; named fixtures / arguments | 119 | 3.890 | 89.303 | 73.538 | 0.05× | 7 |
| <a id="case-dirname"></a>dirname | `dirname /fixture/path/file.txt` | `dirname /fixture/path/file.txt` | No stdin; named fixtures / arguments | 129 | 4.341 | 92.567 | 76.056 | 0.06× | 7 |
| <a id="case-readlink"></a>readlink | `readlink link` | `readlink link` | No stdin; named fixtures / arguments | 120 | 3.833 | 92.081 | 75.698 | 0.05× | 7 |
| <a id="case-realpath"></a>realpath | `realpath link` | `realpath link` | No stdin; named fixtures / arguments | 124 | 5.531 | 120.401 | 98.150 | 0.06× | 7 |
| <a id="case-stat"></a>stat | `stat -c %s text` | `stat -c %s text` | No stdin; named fixtures / arguments | 124 | 4.189 | 99.154 | 95.729 | 0.04× | 7 |
| <a id="case-ls"></a>ls | `ls -1 tree` | `ls -1 tree` | No stdin; named fixtures / arguments | 80 | 16.441 | 90.824 | 81.621 | 0.20× | 7 |
| <a id="case-find"></a>find | `find tree -type f` | `find tree -type f` | No stdin; named fixtures / arguments | 80 | 25.817 | 91.764 | 83.396 | 0.31× | 7 |
| <a id="case-cmp"></a>cmp | `cmp text copy` | `cmp text copy` | No stdin; named fixtures / arguments | 55 | 37.250 | 223.320 | 48.530 | 0.77× | 7 |
| <a id="case-diff"></a>diff | `diff text copy` | `diff text copy` | No stdin; named fixtures / arguments | 35 | 70.291 | 66.840 | 44.839 | 1.57× | 7 |
| <a id="case-dd"></a>dd | `dd if=text bs=64K status=none` | `dd if=text bs=64K status=none` | No stdin; named fixtures / arguments | 80 | 5.781 | 62.028 | 53.996 | 0.11× | 7 |
| <a id="case-cp"></a>cp | `cp text copied` | `cp text copied` | No stdin; named fixtures / arguments | 80 | 13.928 | 71.240 | 83.254 | 0.17× | 7 |
| <a id="case-cksum"></a>cksum | `cksum` | `cksum` | text (423,000 stdin bytes) | 47 | 53.171 | — | 80.170 | 0.66× | 7 |
| <a id="case-bashbase64"></a>bashbase64 | `bashbase64 -w 0` | `base64 -w 0` | bytes (65,536 stdin bytes) | 80 | 9.732 | 69.070 | 58.131 | 0.17× | 7 |
| <a id="case-bashjson"></a>bashjson | `bashjson get .answer` | `jq .answer` | object (39,133 stdin bytes) | 74 | 35.666 | — | 280.212 | 0.13× | 7 |
| <a id="case-awk"></a>awk | `awk '{sum += $2} END {print sum}'` | `awk '{sum += $2} END {print sum}'` | records (162,830 stdin bytes) | 12 | 62.731 | 127.772 | 66.181 | 0.95× | 7 |
| <a id="case-jq"></a>jq | `jq -c '[.[] &#124; select(. > 50)]'` | `jq -c '[.[] &#124; select(. > 50)]'` | array (39,109 stdin bytes) | 12 | 74.028 | — | 102.110 | 0.72× | 7 |
| <a id="case-bc"></a>bc | `bc` | `bc` | arithmetic (18 stdin bytes) | 80 | 4.848 | 64.443 | 63.779 | 0.08× | 7 |
| <a id="case-expr"></a>expr | `expr 123 '*' 456` | `expr 123 '*' 456` | No stdin; named fixtures / arguments | 146 | 4.065 | 103.137 | 89.712 | 0.05× | 7 |
| <a id="case-crypto"></a>crypto | `crypto sha256 -x` | `sha256sum` | blob (1,048,576 stdin bytes) | 12 | 83.783 | 81.154 | 55.084 | 1.52× | 7 |
| <a id="case-uname"></a>uname | `uname` | `uname` | No stdin; named fixtures / arguments | 138 | 3.981 | 96.189 | 76.509 | 0.05× | 7 |
| <a id="case-whoami"></a>whoami | `whoami` | `whoami` | No stdin; named fixtures / arguments | 156 | 4.283 | 119.815 | 104.245 | 0.04× | 7 |
| <a id="case-logname"></a>logname | `logname` | `logname` | No stdin; named fixtures / arguments | 127 | 5.043 | 98.179 | 78.951 | 0.06× | 7 |
| <a id="case-hostname"></a>hostname | `hostname` | `hostname` | No stdin; named fixtures / arguments | 146 | 3.834 | 98.834 | 79.442 | 0.05× | 7 |
| <a id="case-id-uid"></a>id-uid | `id -u` | `id -u` | No stdin; named fixtures / arguments | 135 | 4.053 | 106.809 | 96.912 | 0.04× | 7 |
| <a id="case-printenv-lcall"></a>printenv-lcall | `printenv LC_ALL` | `printenv LC_ALL` | No stdin; named fixtures / arguments | 112 | 3.938 | — | 63.410 | 0.06× | 7 |
| <a id="case-touch"></a>touch | `touch touched` | `touch touched` | No stdin; named fixtures / arguments | 118 | 3.721 | 78.002 | 65.572 | 0.06× | 7 |
| <a id="case-mkdir"></a>mkdir | `mkdir -p mdir` | `mkdir -p mdir` | No stdin; named fixtures / arguments | 134 | 3.963 | 95.221 | 103.401 | 0.04× | 7 |
| <a id="case-chmod"></a>chmod | `chmod 644 text` | `chmod 644 text` | No stdin; named fixtures / arguments | 119 | 4.041 | 89.295 | 72.428 | 0.06× | 7 |
| <a id="case-date-year"></a>date-year | `date -u +%Y` | `date -u +%Y` | No stdin; named fixtures / arguments | 142 | 4.785 | 110.431 | 91.274 | 0.05× | 7 |
| <a id="case-getconf"></a>getconf | `getconf PAGE_SIZE` | `getconf PAGE_SIZE` | No stdin; named fixtures / arguments | 107 | 4.934 | — | 89.946 | 0.05× | 7 |
| <a id="case-pathchk"></a>pathchk | `pathchk text` | `pathchk text` | No stdin; named fixtures / arguments | 107 | 3.880 | — | 77.178 | 0.05× | 7 |
| <a id="case-ln"></a>ln | `ln -f text lnout` | `ln -f text lnout` | No stdin; named fixtures / arguments | 121 | 4.898 | 86.318 | 76.325 | 0.06× | 7 |
| <a id="case-sync"></a>sync | `sync` | `sync` | No stdin; named fixtures / arguments | 20 | 6.070 | 22.557 | 19.131 | 0.32× | 7 |
| <a id="case-rm"></a>rm | `rm -f nosuch` | `rm -f nosuch` | No stdin; named fixtures / arguments | 136 | 3.869 | 97.782 | 79.475 | 0.05× | 7 |
| <a id="case-chown"></a>chown | `chown pleb text` | `chown pleb text` | No stdin; named fixtures / arguments | 118 | 4.760 | 90.487 | 75.419 | 0.06× | 7 |
| <a id="case-chgrp"></a>chgrp | `chgrp pleb text` | `chgrp pleb text` | No stdin; named fixtures / arguments | 150 | 5.511 | 111.758 | 92.705 | 0.06× | 7 |
| <a id="case-sleep"></a>sleep | `sleep 0` | `sleep 0` | No stdin; named fixtures / arguments | 136 | 11.390 | 98.537 | 84.003 | 0.14× | 7 |
| <a id="case-nice"></a>nice | `nice -n 0 /bin/true` | `nice -n 0 /bin/true` | No stdin; named fixtures / arguments | 52 | 27.322 | — | 43.830 | 0.62× | 7 |
| <a id="case-nohup"></a>nohup | `nohup /bin/true` | `nohup /bin/true` | No stdin; named fixtures / arguments | 71 | 36.118 | — | 60.124 | 0.60× | 7 |
| <a id="case-setsid"></a>setsid | `setsid /bin/true` | `setsid /bin/true` | No stdin; named fixtures / arguments | 74 | 37.899 | 74.902 | 65.282 | 0.58× | 7 |
| <a id="case-flock"></a>flock | `flock -n lockfile /bin/true` | `flock -n lockfile /bin/true` | No stdin; named fixtures / arguments | 83 | 41.078 | — | 80.069 | 0.51× | 7 |
| <a id="case-taskset"></a>taskset | `taskset -p 1` | `taskset -p 1` | No stdin; named fixtures / arguments | 113 | 3.779 | 80.443 | 64.532 | 0.06× | 7 |
| <a id="case-ionice"></a>ionice | `ionice -p 1` | `ionice -p 1` | No stdin; named fixtures / arguments | 142 | 4.049 | 98.877 | 81.121 | 0.05× | 7 |
| <a id="case-env"></a>env | `env -i FOO=bar /usr/bin/printenv FOO` | `env -i FOO=bar /usr/bin/printenv FOO` | No stdin; named fixtures / arguments | 70 | 38.598 | 69.160 | 60.351 | 0.64× | 7 |
| <a id="case-sysctl"></a>sysctl | `sysctl -n kernel.osrelease` | `sysctl -n kernel.osrelease` | No stdin; named fixtures / arguments | 124 | 4.725 | 86.759 | 72.179 | 0.07× | 7 |
| <a id="case-id-user"></a>id-user | `id -un` | `id -un` | No stdin; named fixtures / arguments | 141 | 4.980 | 105.972 | 109.788 | 0.05× | 7 |
| <a id="case-id-group"></a>id-group | `id -gn` | `id -gn` | No stdin; named fixtures / arguments | 127 | 5.817 | 97.085 | 101.429 | 0.06× | 7 |
| <a id="case-hostname-s"></a>hostname-s | `hostname -s` | `hostname -s` | No stdin; named fixtures / arguments | 122 | 4.717 | 112.777 | 90.821 | 0.05× | 7 |
| <a id="case-uname-s"></a>uname-s | `uname -s` | `uname -s` | No stdin; named fixtures / arguments | 87 | 4.143 | 81.471 | 65.265 | 0.06× | 7 |
| <a id="case-date-ymd"></a>date-ymd | `date -u +%Y-%m-%d` | `date -u +%Y-%m-%d` | No stdin; named fixtures / arguments | 107 | 4.185 | 73.782 | 62.543 | 0.07× | 7 |
| <a id="case-getconf-nproc"></a>getconf-nproc | `getconf _NPROCESSORS_ONLN` | `getconf _NPROCESSORS_ONLN` | No stdin; named fixtures / arguments | 123 | 4.940 | — | 68.731 | 0.07× | 7 |
| <a id="case-df"></a>df | `df -P /dev` | `df -P /dev` | No stdin; named fixtures / arguments | 109 | 18.652 | 107.771 | 99.389 | 0.19× | 7 |
| <a id="case-uptime"></a>uptime | `uptime -s` | `uptime -s` | No stdin; named fixtures / arguments | 95 | 8.760 | 89.558 | 119.479 | 0.07× | 7 |
<!-- END CASES -->

## Method and limits

<!-- BEGIN METHOD -->
The command measurements use the native dynamic full `out/bash` at the source above, SHA-256 `00063f9f3b758ac8423a6ef7314fb2d99e3bad373d38a72b931146072df0c517`. Host: Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz, x86_64 Linux 6.12.96+deb13-amd64; pinned CPUs: 11. Reference versions and fixture hashes are recorded in the measurement JSON. These are host measurements; no per-command RISC-V or appliance performance is claimed.

Every case uses 7 timed samples after output validation and warm-up. The one-minute host load was 3.2 at the start and 4.5 at the end. A shared lock serialized participating benchmarks; builds and other host activity could still contend. Use the recorded ranges for prioritization and repeat on the intended device before claiming small performance differences.
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
