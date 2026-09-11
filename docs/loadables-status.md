# Loadable status and benchmark work queue

The [PTY broker and live-pane changes](ptybroker.md) have dedicated lifecycle
and binary-I/O regression suites.

Repeated-input, overflow and write-error fixtures named in the 2026-09-08
queue are in this measured full build: `head`, `sed`, `bc`, `nl`, `pr`,
`fold`, `expand`, `tac`, `col`, `colrm`, `column`, `strings`, `od`,
`hexdump`, `split`, `csplit`, `tail`, `tee` (closed stdin), `crypto`, `du`,
`mv`, `truncate`, `cp`, `join`, `comm`, `unexpand`, `rev`, `sort` and `wc`.

This is the **2026-09-11** review of the complete
[build catalog](../config/bash-loadables.list) at `c591f19`. The
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

Named P1 fixtures from the 2026-09-08 queue, including leftover `diff - -`,
`tee` stop-when-all-outputs-failed, and `ar` extract write-error cleanup, are
in this measured full build. Two unmeasured-catalog batches now have GNU- or
BusyBox-matching timings on this binary (`tee`, `hostid`, `timeout`, `du`,
`truncate`, `ar t`, `zstd`/`zstdcat`, `zcat`, `file`, `split`, `csplit`,
`opt`, `uudecode`, then `strftime`, `strptime`, `zlib`, `pax`, `tput`,
`less`, `chrt`, `signal`, `cal`, `ed`, `finfo`, `fltexpr`, `pcre`,
`uclampset`, `tz`, `ip`, `tinfo`, plus extra `tput`/`signal`/`finfo`/`chrt`
cases, `zlib` xz/bzip2, `coreutils` numfmt/tsort/factor/groups/install/fmt/tac,
`lsblk`, `binhex`, `prlimit`, `fincore`, `col -b`, `bignum`, `ncdu`, `blkid`,
and `man -w`). Live `free -k` timings are not published because counters
move between invocations.

<!-- BEGIN SUMMARY -->
Catalog: **279 loadables** (248 local sources, 31 stock Bash sources). Command benchmark: **142 cases covering 114 loadables**; 114 loadables passed the selected output checks, 0 have confirmed correctness findings. The other 165 have no individual command timings here; GPU transport measurements are reported separately.

| Profile | Included loadables |
| --- | --- |
| shell | 0 |
| pure | 28 |
| core | 89 |
| device | 160 |
| server | 214 |
| desktop | 155 |
| full | 279 |

Command measurement source: `c591f19db622d9b29af372c4689ba56f2838ff28`. The measured full binary passed tests/ar-check.sh (18), tests/tee-check.sh (7) and tests/diff-check.sh (7). Unmeasured-catalog batches matched GNU or BusyBox on this binary across seven samples (59 published cases after binhex/prlimit/col/fincore/bignum/ncdu/blkid/man). col was omitted (GNU adds a trailing byte under LC_ALL=C). xargs and uuencode matched on the first pass but failed the repeated-input batch. coreutils nproc is omitted because BusyBox reports the pinned CPU. Live `free -k` timings are omitted because counters move between invocations. tests/run.sh was not re-run in full for this refresh.

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
| P2 | [comm](#case-comm) | 2.59× external time; output checks pass, seven samples. | Profile input/output and allocation costs on the comm fixture, then measure the proposed change. |
| P2 | [sort-text](#case-sort-text) | 2.05× external time; 0.94× BusyBox time; output checks pass, seven samples. | Profile input/output and allocation costs on the sort-text fixture, then measure the proposed change. |
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
| [`ar`](../loadables/ar.c) | C D S T F | [Bench checked](#case-ar) | ar; ar | 5.109 / 108.164 / 144.300; [ar](#case-ar), 114 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `asort`* | F | [Contract](../tests/misc-smoke.py) | —; gawk asort() | N/M | P3 | Add a matched workload and timing. |
| [`at`](../loadables/at.c) | S F | [Contract](../tests/misc-smoke.py) | —; at (missing) | N/M | P3 | Add a matched workload and timing. |
| [`audit`](../loadables/audit.c) | S F | [Contract](../tests/network-smoke.py) | —; auditctl / ausearch | N/M | P3 | Add a matched workload and timing. |
| [`auth`](../loadables/auth.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`awk`](../loadables/awk.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | awk; awk | 62.968 / 126.214 / 69.215; [awk](#case-awk), 12 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `basename`* | P C D S T F | [Contract](../tests/host-smoke.sh) | basename; basename | 3.679 / 80.543 / 66.570; [basename](#case-basename), 128 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashbase64`](../loadables/bashbase64.c) | D S F | [Bench checked](#case-bashbase64) | base64; base64 | 8.261 / 68.794 / 56.985; [bashbase64](#case-bashbase64), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashclock`](../loadables/bashclock.c) | D S F | Build/help | —; Bash EPOCHREALTIME / Python time | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashdhcp`](../loadables/bashdhcp.c) | D S F | Build/help | udhcpc; dhclient / udhcpc | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashinotify`](../loadables/bashinotify.c) | D S F | Build/help | inotifyd (not in build); inotifywait (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashio`](../loadables/bashio.c) | D S F | Build/help | —; Python os.pread/os.pwrite | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashjson`](../loadables/bashjson.c) | D S F | [Bench checked](#case-bashjson) | —; jq | 35.779 / — / 305.617; [bashjson](#case-bashjson), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashkmod`](../loadables/bashkmod.c) | D S F | Build/help | modprobe; modprobe / insmod / rmmod | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashlogger`](../loadables/bashlogger.c) | D S F | Build/help | logger; logger | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashmount`](../loadables/bashmount.c) | D S F | Build/help | mount; mount / umount / findmnt | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashpoll`](../loadables/bashpoll.c) | D S T F | Build/help | —; Python selectors / socket | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashsyslogd`](../loadables/bashsyslogd.c) | D S F | Build/help | syslogd; rsyslogd / syslogd | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashtermraw`](../loadables/bashtermraw.c) | D S F | Build/help | stty; stty | N/M | P3 | Add behavioral fixtures, then timing. |
| [`batch`](../loadables/batch.c) | S F | [Contract](../tests/misc-smoke.py) | —; batch (missing) | N/M | P3 | Add a matched workload and timing. |
| [`bc`](../loadables/bc.c) | S T F | [Parity](../tests/bc-parity.py); [limited](#scope-notes); [S](../tests/bc-sanitize.sh) | bc; bc | 4.644 / 64.313 / 65.473; [bc](#case-bc), 80 passes | P3 | Decide required option scope; see limitations. |
| [`bignum`](../loadables/bignum.c) | T F | [Contract](../tests/misc-smoke.py) | bc; Python int / bc | 4.824 / 116.978 / 91.528; [bignum](#case-bignum), 132 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`binhex`](../loadables/binhex.c) | D S F | [Bench checked](#case-binhex-decode) | xxd; xxd | 31.396 / 187.850 / 167.220; [binhex-decode](#case-binhex-decode), 80 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`blkid`](../loadables/blkid.c) | D S F | [Bench checked](#case-blkid-type) | blkid; blkid | 5.277 / INVALID / 149.470; [blkid-type](#case-blkid-type), 112 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`blockdev`](../loadables/blockdev.c) | D S F | Build/help | blockdev; blockdev | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bsdgames`](../loadables/bsdgames.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; bsdgames (missing) | N/M | P3 | Add a matched workload and timing. |
| [`buf`](../loadables/buf.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cal`](../loadables/cal.c) | T F | [Contract](../tests/misc-smoke.py) | cal; cal (missing) | 4.032 / 95.664 / —; [cal](#case-cal), 132 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`caps`](../loadables/caps.c) | S F | [Smoke](../tests/system-smoke.sh) | —; capsh / setpriv | N/M | P3 | Add behavioral fixtures, then timing. |
| `cat`* | P C D S T F | [Contract](../tests/host-smoke.sh) | cat; cat | 7.768 / 53.060 / 53.499; [cat](#case-cat), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chattr`](../loadables/chattr.c) | D S F | Build/help | —; chattr | N/M | P3 | Add behavioral fixtures, then timing. |
| [`chgrp`](../loadables/chgrp.c) | C D S T F | [Bench checked](#case-chgrp) | chgrp; chgrp | 5.311 / 86.114 / 72.067; [chgrp](#case-chgrp), 116 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `chmod`* | P C D S T F | [Bench checked](#case-chmod) | chmod; chmod | 4.484 / 90.870 / 73.351; [chmod](#case-chmod), 102 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chown`](../loadables/chown.c) | C D S T F | [Bench checked](#case-chown) | chown; chown | 5.242 / 106.276 / 91.887; [chown](#case-chown), 144 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chrt`](../loadables/chrt.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | —; chrt | 4.115 / — / 73.644; [chrt](#case-chrt), 127 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`cksum`](../loadables/cksum.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; cksum | 52.159 / — / 78.598; [cksum](#case-cksum), 48 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`claude`](../loadables/claude.c) | F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`clip`](../loadables/clip.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cluster`](../loadables/cluster.c) | F | [Smoke](../tests/misc-smoke.py) | —; API fixture | N/M | P3 | Add peer membership, timeout and disconnect fixtures. |
| [`cmp`](../loadables/cmp.c) | C D S T F | [Bench checked](#case-cmp) | cmp; cmp | 44.183 / 222.165 / 53.205; [cmp](#case-cmp), 70 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`col`](../loadables/col.c) | C D S T F | [Bench checked](#case-col) | —; col | 63.847 / — / 116.183; [col](#case-col), 19 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`colrm`](../loadables/colrm.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; colrm | 65.306 / — / 125.531; [colrm](#case-colrm), 24 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`column`](../loadables/column.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; column | 82.020 / — / 343.863; [column](#case-column), 7 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`comm`](../loadables/comm.c) | C D S T F | [Bench checked](#case-comm) | —; comm | 71.590 / — / 27.610; [comm](#case-comm), 18 passes | P2 | Profile input/output and allocation costs on the comm fixture, then measure the proposed change. |
| [`coreutils`](../loadables/coreutils.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; Individual coreutils programs | 55.077 / 101.479 / 23.139; [coreutils-tac](#case-coreutils-tac), 21 passes; 8 cases total | P3 | Confirm coreutils-tac (2.38× external time), then profile. |
| [`cp`](../loadables/cp.c) | C D S T F | [Contract](../tests/host-smoke.sh) | cp; cp | 14.991 / 68.229 / 84.129; [cp](#case-cp), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`cred`](../loadables/cred.c) | S F | [Smoke](../tests/system-smoke.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cron`](../loadables/cron.c) | S F | [Contract](../tests/large-smoke.py) | crond; cron / crond | N/M | P3 | Add a matched workload and timing. |
| [`crontab`](../loadables/crontab.c) | S F | [Contract](../tests/misc-smoke.py) | crontab; crontab | N/M | P3 | Add a matched workload and timing. |
| [`crypto`](../loadables/crypto.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | sha256sum; sha256sum / openssl | 74.817 / 74.245 / 50.746; [crypto](#case-crypto), 12 passes | P3 | Confirm crypto (1.47× external time), then profile. |
| [`csplit`](../loadables/csplit.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; csplit | 36.451 / — / 47.426; [csplit](#case-csplit), 39 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`curl`](../loadables/curl.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; curl | N/M | P3 | Add a matched workload and timing. |
| [`cut`](../loadables/cut.c) | P C D S T F | [Parity](../tests/cut-parity.sh) | cut; cut | 30.193 / 333.940 / 160.108; [cut](#case-cut), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`date`](../loadables/date.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | date; date | 3.255 / 58.465 / 46.877; [date-ymd](#case-date-ymd), 82 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dd`](../loadables/dd.c) | C D S T F | [Bench checked](#case-dd) | dd; dd | 5.449 / 59.103 / 51.778; [dd](#case-dd), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`df`](../loadables/df.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | df; df | 14.781 / 94.035 / 85.720; [df](#case-df), 99 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dhcp6`](../loadables/dhcp6.c) | S F | [Contract](../tests/network-smoke.py) | udhcpc6; dhclient -6 | N/M | P3 | Add a matched workload and timing. |
| [`dhcpd`](../loadables/dhcpd.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | udhcpd; dnsmasq / dhcpd | N/M | P3 | Add a matched workload and timing. |
| [`dhcpd6`](../loadables/dhcpd6.c) | S F | [Contract](../tests/network-smoke.py) | —; kea-dhcp6 (missing) | N/M | P3 | Add a matched workload and timing. |
| [`dialog`](../loadables/dialog.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; dialog (missing) | N/M | P3 | Add a matched workload and timing. |
| [`diff`](../loadables/diff.c) | C D S T F | [Bench checked](#case-diff) | diff; diff | 70.812 / 59.935 / 42.551; [diff](#case-diff), 37 passes | P3 | Confirm diff (1.66× external time), then profile. |
| `dirname`* | P C D S T F | [Bench checked](#case-dirname) | dirname; dirname | 3.700 / 92.299 / 74.296; [dirname](#case-dirname), 140 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dmesg`](../loadables/dmesg.c) | D S F | Build/help | dmesg; dmesg | N/M | P3 | Add behavioral fixtures, then timing. |
| [`dmsetup`](../loadables/dmsetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; dmsetup | N/M | P3 | Define required mapper mutation verbs and add isolated device fixtures. |
| [`dns`](../loadables/dns.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | nslookup; dig / drill | N/M | P3 | Add a matched workload and timing. |
| [`doas`](../loadables/doas.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; doas (missing) | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`du`](../loadables/du.c) | C D S T F | [Bench checked](#case-du-tree) | du; du | 24.347 / INVALID / 83.615; [du-tree](#case-du-tree), 80 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ed`](../loadables/ed.c) | C D S T F | [Bench checked](#case-ed) | ed; ed (missing) | 45.937 / 66.697 / —; [ed](#case-ed), 48 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`env`](../loadables/env.c) | C D S T F | [Contract](../tests/regressions.py) | env; env | 34.064 / 65.522 / 57.376; [env](#case-env), 63 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`escdelay`](../loadables/escdelay.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`expand`](../loadables/expand.c) | C D S T F | [Parity](../tests/expand-parity.py); [limited](#scope-notes); [S](../tests/expand-sanitize.sh) | expand; expand | 62.200 / 291.918 / 74.917; [expand](#case-expand), 38 passes | P3 | Decide required option scope; see limitations. |
| [`expect`](../loadables/expect.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; expect (missing) | N/M | P3 | Add a matched workload and timing. |
| [`expr`](../loadables/expr.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | expr; expr | 4.508 / 111.572 / 102.782; [expr](#case-expr), 154 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`fail2ban`](../loadables/fail2ban.c) | S F | [Contract](../tests/network-smoke.py) | —; fail2ban-client (missing) | N/M | P3 | Add a matched workload and timing. |
| `fdflags`* | D S F | Build/help | —; Python fcntl | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fdisk`](../loadables/fdisk.c) | D S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | fdisk; fdisk | N/M | P3 | Add a matched workload and timing. |
| [`fifo`](../loadables/fifo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`file`](../loadables/file.c) | T F | [Contract](../tests/misc-smoke.py) | —; file | 4.289 / — / 965.361; [file](#case-file), 106 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`fincore`](../loadables/fincore.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; fincore | 5.656 / — / 90.871; [fincore](#case-fincore), 118 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`find`](../loadables/find.c) | C D S T F | [Contract](../tests/regressions.py) | find; find | 25.423 / 78.876 / 76.467; [find](#case-find), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `finfo`* | D S F | [Bench checked](#case-finfo-mode) | stat; stat | 3.729 / 87.294 / 84.916; [finfo-mode](#case-finfo-mode), 106 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`flock`](../loadables/flock.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | —; flock | 40.423 / — / 75.590; [flock](#case-flock), 81 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `fltexpr`* | D S F | [Bench checked](#case-fltexpr) | awk; awk / bc | 4.832 / 120.849 / 221.000; [fltexpr](#case-fltexpr), 130 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`fold`](../loadables/fold.c) | C D S T F | [Parity](../tests/fold-parity.py); [limited](#scope-notes); [S](../tests/fold-sanitize.sh) | fold; fold | 46.360 / 168.253 / 107.431; [fold](#case-fold), 43 passes | P3 | Decide required option scope; see limitations. |
| [`free`](../loadables/free.c) | C D S T F | Build/help | free; free | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fsck`](../loadables/fsck.c) | D S F | [Contract](../tests/misc-smoke.py) | —; fsck | N/M | P3 | Add a matched workload and timing. |
| [`fsfreeze`](../loadables/fsfreeze.c) | D S F | Build/help | fsfreeze; fsfreeze | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fstrim`](../loadables/fstrim.c) | D S F | Build/help | fstrim; fstrim | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fw`](../loadables/fw.c) | S F | [Contract](../tests/large-smoke.py) | —; nft / iptables | N/M | P3 | Add a matched workload and timing. |
| [`genl`](../loadables/genl.c) | D S F | Build/help | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| `getconf`* | D S F | [Bench checked](#case-getconf-nproc) | —; getconf | 4.461 / — / 82.935; [getconf-nproc](#case-getconf-nproc), 147 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`getfacl`](../loadables/getfacl.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; getfacl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`gpu`](../loadables/gpu.c) | T F | [Contract](../tests/gpu-smoke.py); [S](../tests/gpu-sanitize.sh) | —; API fixture | [Transport data](#graphics-metrics); no applet ratio | P3 | Measure application frame latency and driver behavior on the intended device. |
| [`grep`](../loadables/grep.c) | C D S T F | [Parity](../tests/grep-parity.sh); [limited](#scope-notes); [S](../tests/grep-host.c) | grep; grep | 41.913 / 307.101 / 38.464; [grep-lines](#case-grep-lines), 48 passes; 2 cases total | P3 | Decide required option scope; see limitations. |
| [`halt`](../loadables/halt.c) | D S F | Build/help | halt; halt | N/M | P3 | Add behavioral fixtures, then timing. |
| `head`* | P C D S T F | [Parity](../tests/head-sed-parity.py); [limited](#scope-notes); [S](../tests/head-sed-sanitize.sh) | head; head | 8.380 / 57.057 / 45.965; [head](#case-head), 80 passes | P3 | Decide required option scope; see limitations. |
| [`hexdump`](../loadables/hexdump.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | hexdump; hexdump | 79.830 / 95.853 / 141.459; [hexdump](#case-hexdump), 12 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`hl`](../loadables/hl.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; highlight (missing) | N/M | P3 | Add a matched workload and timing. |
| [`hostid`](../loadables/hostid.c) | D S F | [Bench checked](#case-hostid) | hostid; hostid | 6.507 / 137.975 / 114.184; [hostid](#case-hostid), 132 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`hostname`](../loadables/hostname.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | hostname; hostname | 3.775 / 97.378 / 75.446; [hostname](#case-hostname), 143 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`http`](../loadables/http.c) | D S F | [Contract](../tests/network-smoke.py) | wget; curl | N/M | P3 | Add a matched workload and timing. |
| [`httpd`](../loadables/httpd.c) | S F | [Contract](../tests/httpd-host.c); [S](../tests/run.sh) | httpd; HTTP server fixture | N/M | P3 | Add a matched workload and timing. |
| [`hwclock`](../loadables/hwclock.c) | D S F | Build/help | hwclock; hwclock | N/M | P3 | Add behavioral fixtures, then timing. |
| `id`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | id; id | 4.865 / 86.569 / 90.369; [id-group](#case-id-group), 116 passes; 3 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`index`](../loadables/index.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git update-index | N/M | P3 | Add a matched workload and timing. |
| [`integrity`](../loadables/integrity.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`ionice`](../loadables/ionice.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | ionice; ionice | 3.740 / 91.492 / 72.305; [ionice](#case-ionice), 124 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ip`](../loadables/ip.c) | D S F | [Bench checked](#case-ip) | ip; ip | 6.611 / ERROR / 151.618; [ip](#case-ip), 130 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ipcctl`](../loadables/ipcctl.c) | D S F | Build/help | ipcs (not in build); ipcs / ipcrm | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ipcmk`](../loadables/ipcmk.c) | D S F | Build/help | —; ipcmk | N/M | P3 | Add behavioral fixtures, then timing. |
| [`join`](../loadables/join.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; join | 67.603 / — / 43.602; [join](#case-join), 18 passes | P3 | Confirm join (1.55× external time), then profile. |
| [`jq`](../loadables/jq.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; jq | 52.894 / — / 81.540; [jq](#case-jq), 9 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`keyctl`](../loadables/keyctl.c) | S F | Build/help | —; keyctl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`kgetch`](../loadables/kgetch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`killall`](../loadables/killall.c) | C D S T F | Build/help | killall; killall (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`killall5`](../loadables/killall5.c) | F | Build/help | —; killall5 | N/M | P3 | Add behavioral fixtures, then timing. |
| [`kitty`](../loadables/kitty.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; kitten icat | N/M | P3 | Add a matched workload and timing. |
| [`ldap`](../loadables/ldap.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-ldap.c) | —; ldapsearch (missing) | N/M | P3 | Add a matched workload and timing. |
| [`less`](../loadables/less.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | less; less | 53.126 / 17.116 / 99.188; [less](#case-less), 23 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`link`](../loadables/link.c) | C D S T F | Build/help | link; link | N/M | P3 | Add behavioral fixtures, then timing. |
| `ln`* | P C D S T F | [Bench checked](#case-ln) | ln; ln | 4.918 / 104.882 / 93.018; [ln](#case-ln), 152 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`locale`](../loadables/locale.c) | T F | [Contract](../tests/misc-smoke.py) | —; locale / Python locale | N/M | P3 | Add a matched workload and timing. |
| [`login`](../loadables/login.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | login; login | N/M | P3 | Add a matched workload and timing. |
| `logname`* | P C D S T F | [Bench checked](#case-logname) | logname; logname | 5.290 / 107.028 / 84.809; [logname](#case-logname), 132 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`losetup`](../loadables/losetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | losetup; losetup | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lpr`](../loadables/lpr.c) | F | [Smoke](../tests/misc-smoke.py); [limited](#scope-notes) | lpr (not in build); lpr (missing) | N/M | P3 | Decide whether real print delivery belongs in this loadable. |
| [`ls`](../loadables/ls.c) | C D S T F | [Bench checked](#case-ls) | ls; ls | 14.262 / 86.634 / 77.091; [ls](#case-ls), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`lsattr`](../loadables/lsattr.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; lsattr | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lsblk`](../loadables/lsblk.c) | D S F | [Bench checked](#case-lsblk) | —; lsblk | 46.983 / — / 89.697; [lsblk](#case-lsblk), 62 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`lsof`](../loadables/lsof.c) | D S T F | [Smoke](../tests/system-smoke.sh) | —; lsof | N/M | P3 | Add behavioral fixtures, then timing. |
| [`mail`](../loadables/mail.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | sendmail (not in build); sendmail / mailq | N/M | P3 | Add a controlled submission/delivery benchmark. |
| [`man`](../loadables/man.c) | T F | [Contract](../tests/misc-smoke.py) | —; man | 4.030 / — / 1248.570; [man](#case-man), 84 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `mkdir`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | mkdir; mkdir | 5.168 / 121.505 / 131.795; [mkdir](#case-mkdir), 139 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
| [`ncdu`](../loadables/ncdu.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; ncdu | 28.085 / ERROR / 104.802; [ncdu-print](#case-ncdu-print), 98 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`netids`](../loadables/netids.c) | S F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; suricata (missing) | N/M | P3 | Add a matched workload and timing. |
| [`netstat`](../loadables/netstat.c) | D S F | Build/help | netstat; netstat (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`nice`](../loadables/nice.c) | C D S T F | [Contract](../tests/regressions.py) | —; nice | 40.315 / — / 66.109; [nice](#case-nice), 60 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`nl`](../loadables/nl.c) | C D S T F | [Parity](../tests/nl-parity.py); [limited](#scope-notes); [S](../tests/nl-sanitize.sh) | nl; nl | 34.206 / 138.103 / 76.600; [nl](#case-nl), 34 passes | P3 | Decide required option scope; see limitations. |
| [`nohup`](../loadables/nohup.c) | C D S T F | [Contract](../tests/regressions.py) | —; nohup | 37.776 / — / 61.629; [nohup](#case-nohup), 56 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`notify`](../loadables/notify.c) | T F | [Contract](../tests/misc-smoke.py) | —; systemd-notify | N/M | P3 | Add a matched workload and timing. |
| [`ns`](../loadables/ns.c) | S F | [Smoke](../tests/system-smoke.sh) | unshare; unshare / nsenter | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ntp`](../loadables/ntp.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | ntpd (not in build); chronyc / ntpd | N/M | P3 | Add a matched workload and timing. |
| [`obj`](../loadables/obj.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git hash-object / cat-file | N/M | P3 | Add a matched workload and timing. |
| [`od`](../loadables/od.c) | C D S T F | [Bench checked](#case-od) | od; od | 67.196 / 57.117 / 128.984; [od](#case-od), 12 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`opt`](../loadables/opt.c) | T F | [Contract](../tests/misc-smoke.py) | getopt; getopt | 4.558 / 105.866 / 86.712; [opt](#case-opt), 131 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`pack`](../loadables/pack.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git pack-objects / index-pack | N/M | P3 | Add a matched workload and timing. |
| [`passwd`](../loadables/passwd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | passwd; passwd | N/M | P3 | Add a matched workload and timing. |
| [`paste`](../loadables/paste.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | paste; paste | 78.052 / 424.001 / 79.017; [paste](#case-paste), 11 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `pathchk`* | P C D S T F | [Bench checked](#case-pathchk) | —; pathchk | 3.318 / — / 68.444; [pathchk](#case-pathchk), 120 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`pax`](../loadables/pax.c) | C D S T F | [Contract](../tests/host-smoke.sh) | —; pax (missing) | 4.829 / 74.143 / 104.667; [pax](#case-pax), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`payload`](../loadables/payload.c) | F | [Smoke](../tests/misc-smoke.py); [limited](#scope-notes) | —; API fixture | N/M | P3 | Add an installer-boundary fixture and document the external helper. |
| [`pcap`](../loadables/pcap.c) | D S F | [Contract](../tests/network-smoke.py) | —; tcpdump (missing) | N/M | P3 | Add a matched workload and timing. |
| [`pcre`](../loadables/pcre.c) | S F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; pcre2grep / grep -P | 46.109 / ERROR / 10.564; [pcre](#case-pcre), 10 passes | P3 | Confirm pcre (4.36× external time), then profile. |
| [`pgrep`](../loadables/pgrep.c) | C D S T F | Build/help; [limited](#scope-notes) | —; pgrep | N/M | P3 | Decide required option scope; see limitations. |
| [`pidof`](../loadables/pidof.c) | C D S T F | Build/help | pidof; pidof | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ping`](../loadables/ping.c) | D S F | Build/help | ping; ping | N/M | P3 | Add behavioral fixtures, then timing. |
| [`pkg`](../loadables/pkg.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`pkill`](../loadables/pkill.c) | C D S T F | Build/help; [limited](#scope-notes) | —; pkill | N/M | P3 | Decide required option scope; see limitations. |
| [`pkt`](../loadables/pkt.c) | D S F | [Contract](../tests/network-smoke.py) | —; scapy (missing) | N/M | P3 | Add a matched workload and timing. |
| [`poweroff`](../loadables/poweroff.c) | D S F | Build/help | poweroff; poweroff | N/M | P3 | Add behavioral fixtures, then timing. |
| [`pr`](../loadables/pr.c) | C D S T F | [Parity](../tests/pr-parity.py); [limited](#scope-notes); [S](../tests/pr-sanitize.sh) | —; pr | 20.020 / — / 283.951; [pr](#case-pr), 65 passes | P3 | Decide required option scope; see limitations. |
| `printenv`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | —; printenv | 4.182 / — / 71.297; [printenv-lcall](#case-printenv-lcall), 122 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`prlimit`](../loadables/prlimit.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; prlimit | 4.625 / — / 104.772; [prlimit-cpu](#case-prlimit-cpu), 110 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`procstat`](../loadables/procstat.c) | D S T F | [Contract](../tests/procstat-smoke.py); [S](../tests/procstat-sanitize.sh) | —; iostat / mpstat / sar / pidstat / pmap / pldd | N/M | P3 | Add a matched workload and timing. |
| [`ps`](../loadables/ps.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | ps; ps | N/M | P3 | Add a matched workload and timing. |
| [`pty`](../loadables/pty.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; Python pty | N/M | P3 | Add a matched workload and timing. |
| [`ptybroker`](../loadables/ptybroker.c) | T F | Build/help | —; ptybroker (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`readlink`](../loadables/readlink.c) | C D S T F | [Bench checked](#case-readlink) | readlink; readlink | 3.860 / 88.336 / 71.570; [readlink](#case-readlink), 127 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `realpath`* | P C D S T F | [Bench checked](#case-realpath) | realpath; realpath | 4.220 / 102.687 / 81.890; [realpath](#case-realpath), 143 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`reboot`](../loadables/reboot.c) | D S F | Build/help | reboot; reboot | N/M | P3 | Add behavioral fixtures, then timing. |
| [`renice`](../loadables/renice.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | renice; renice | N/M | P3 | Add behavioral fixtures, then timing. |
| [`rev`](../loadables/rev.c) | C D S T F | [Bench checked](#case-rev) | rev; rev | 67.972 / 37.060 / 123.604; [rev](#case-rev), 14 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `rm`* | P C D S T F | [Bench checked](#case-rm) | rm; rm | 3.660 / 89.885 / 76.418; [rm](#case-rm), 134 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `rmdir`* | P C D S T F | Build/help | rmdir; rmdir | N/M | P3 | Add behavioral fixtures, then timing. |
| [`rngseed`](../loadables/rngseed.c) | D S F | [Contract](../tests/rngseed-host.c); [S](../tests/run.sh) | seedrng (not in build); systemd-random-seed (missing) | N/M | P3 | Add a matched workload and timing. |
| [`rsync`](../loadables/rsync.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; rsync | N/M | P3 | Add a matched workload and timing. |
| [`rtspcat`](../loadables/rtspcat.c) | F | Build/help | —; ffmpeg / openRTSP | N/M | P3 | Add a controlled RTSP/RTP stream with loss, reordering and framing checks. |
| [`scm`](../loadables/scm.c) | F | [Contract](../tests/misc-smoke.py) | —; Python socket SCM_RIGHTS | N/M | P3 | Add a matched workload and timing. |
| [`scp`](../loadables/scp.c) | S F | [Contract](../tests/network-smoke.py) | —; scp | N/M | P3 | Add a matched workload and timing. |
| [`screen`](../loadables/screen.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; screen (missing) | N/M | P3 | Measure live PTY relay, backpressure and cleanup. |
| [`script`](../loadables/script.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; script | N/M | P3 | Add a matched workload and timing. |
| [`scrub`](../loadables/scrub.c) | F | [Contract](../tests/misc-smoke.py) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`sed`](../loadables/sed.c) | C D S T F | [Parity](../tests/head-sed-parity.py); [limited](#scope-notes); [S](../tests/head-sed-sanitize.sh) | sed; sed | 73.044 / 88.706 / 60.222; [sed](#case-sed), 10 passes | P3 | Decide required option scope; see limitations. |
| [`seq`](../loadables/seq.c) | P C D S T F | [Parity](../tests/seq-parity.sh) | seq; seq | 53.982 / 1465.274 / 58.837; [seq](#case-seq), 43 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`setfacl`](../loadables/setfacl.c) | D S F | Build/help | —; setfacl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| `setpgid`* | D S F | Build/help | —; Python os.setpgid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`setsid`](../loadables/setsid.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | setsid; setsid | 55.379 / 102.391 / 88.526; [setsid](#case-setsid), 108 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sftp`](../loadables/sftp.c) | S F | [Contract](../tests/network-smoke.py) | —; sftp | N/M | P3 | Add a matched workload and timing. |
| [`signal`](../loadables/signal.c) | D S F | [Contract](../tests/system-smoke.sh) | kill; kill -l / Bash kill | 3.605 / 93.127 / 76.166; [signal](#case-signal), 136 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sixel`](../loadables/sixel.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; img2sixel (missing) | N/M | P3 | Add a matched workload and timing. |
| [`slabtop`](../loadables/slabtop.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; slabtop | N/M | P3 | Add a matched workload and timing. |
| `sleep`* | P C D S T F | [Bench checked](#case-sleep) | sleep; sleep | 9.795 / 91.824 / 74.081; [sleep](#case-sleep), 94 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sort`](../loadables/sort.c) | C D S T F | [Parity](../tests/sort-parity.sh) | sort; sort | 75.082 / 79.791 / 36.701; [sort-text](#case-sort-text), 12 passes; 2 cases total | P2 | Profile input/output and allocation costs on the sort-text fixture, then measure the proposed change. |
| [`split`](../loadables/split.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; split | 36.133 / — / 70.925; [split](#case-split), 64 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sqlite`](../loadables/sqlite.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; sqlite3 / Python sqlite3 | N/M | P3 | Add a matched workload and timing. |
| [`ss`](../loadables/ss.c) | D S F | Build/help | —; ss | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ssh`](../loadables/ssh.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; ssh | N/M | P3 | Add a matched workload and timing. |
| [`sshd`](../loadables/sshd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sshd | N/M | P3 | Add a matched workload and timing. |
| [`stat`](../loadables/stat.c) | P C D S T F | [Parity](../tests/stat-parity.sh) | stat; stat | 4.251 / 102.813 / 108.442; [stat](#case-stat), 141 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`strace`](../loadables/strace.c) | F | [Contract](../tests/large-smoke.py) | —; strace (missing) | N/M | P3 | Add a matched workload and timing. |
| `strftime`* | P C D S T F | [Bench checked](#case-strftime) | date; date / Bash printf | 3.953 / 98.357 / 83.032; [strftime](#case-strftime), 140 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`strings`](../loadables/strings.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | strings; strings | 26.746 / 79.747 / 118.348; [strings](#case-strings), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `strptime`* | P C D S T F | [Bench checked](#case-strptime) | —; Python datetime.strptime | 5.318 / 86.082 / 70.941; [strptime](#case-strptime), 126 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`su`](../loadables/su.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | su; su | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sudo`](../loadables/sudo.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sudo | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sv`](../loadables/sv.c) | S F | [Contract](../tests/large-smoke.py) | —; runit sv | N/M | P3 | Add a matched workload and timing. |
| [`swapoff`](../loadables/swapoff.c) | D S F | Build/help | swapoff; swapoff | N/M | P3 | Add behavioral fixtures, then timing. |
| [`swapon`](../loadables/swapon.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | swapon; swapon | N/M | P3 | Add behavioral fixtures, then timing. |
| `sync`* | P C D S T F | [Bench checked](#case-sync) | sync; sync | 5.655 / 22.431 / 18.756; [sync](#case-sync), 20 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`sysctl`](../loadables/sysctl.c) | D S F | [Contract](../tests/system-smoke.sh) | sysctl; sysctl | 5.194 / 86.868 / 69.258; [sysctl](#case-sysctl), 120 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tac`](../loadables/tac.c) | C D S T F | [Parity](../tests/tac-parity.py); [limited](#scope-notes); [S](../tests/tac-sanitize.sh) | tac; tac | 14.556 / 373.698 / 77.264; [tac](#case-tac), 80 passes | P3 | Decide bounded-memory input and GNU regex scope; see the tac follow-up. |
| [`tail`](../loadables/tail.c) | C D S T F | [Parity](../tests/wc-tail-parity.sh) | tail; tail | 5.152 / 119.914 / 52.184; [tail](#case-tail), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`taskset`](../loadables/taskset.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | taskset; taskset | 3.962 / 96.418 / 79.384; [taskset](#case-taskset), 140 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `tee`* | P C D S T F | [Bench checked](#case-tee) | tee; tee | 7.061 / 76.696 / 52.926; [tee](#case-tee), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`termpixel`](../loadables/termpixel.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`termpixel_pong`](../loadables/termpixel_pong.c) | F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`timeout`](../loadables/timeout.c) | C D S T F | [Contract](../tests/system-smoke.sh) | timeout; timeout | 45.541 / 91.302 / 84.175; [timeout](#case-timeout), 79 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tinfo`](../loadables/tinfo.c) | T F | [Bench checked](#case-tinfo) | —; infocmp / tput | 4.312 / — / 87.535; [tinfo](#case-tinfo), 118 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tiv`](../loadables/tiv.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; chafa (missing) | N/M | P3 | Add a matched workload and timing. |
| [`toml`](../loadables/toml.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh); [Fz](../tests/fuzz-toml.c) | —; Python tomllib | N/M | P3 | Add a matched workload and timing. |
| [`top`](../loadables/top.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | top; top | N/M | P3 | Add a matched workload and timing. |
| [`totp`](../loadables/totp.c) | F | [Contract](../tests/misc-smoke.py) | —; oathtool (missing) | N/M | P3 | Add a matched workload and timing. |
| [`touch`](../loadables/touch.c) | C D S T F | [Bench checked](#case-touch) | touch; touch | 3.610 / 88.410 / 77.395; [touch](#case-touch), 118 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tput`](../loadables/tput.c) | T F | [Bench checked](#case-tput-lines) | —; tput | 3.688 / — / 78.494; [tput-lines](#case-tput-lines), 100 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`tr`](../loadables/tr.c) | C D S T F | [Bench checked](#case-tr) | tr; tr | 32.987 / 61.804 / 39.122; [tr](#case-tr), 42 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`truncate`](../loadables/truncate.c) | C D S T F | [Bench checked](#case-truncate) | truncate; truncate | 3.816 / 84.604 / 68.086; [truncate](#case-truncate), 116 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`ts`](../loadables/ts.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; tree-sitter (missing) | N/M | P3 | Add a matched workload and timing. |
| `tty`* | P C D S T F | Build/help | tty; tty | N/M | P3 | Add behavioral fixtures, then timing. |
| [`tui`](../loadables/tui.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`tz`](../loadables/tz.c) | T F | [Contract](../tests/misc-smoke.py) | date; date / Python zoneinfo | 3.830 / 94.323 / 76.262; [tz](#case-tz), 128 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`uclampset`](../loadables/uclampset.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; uclampset | 4.274 / — / 70.703; [uclampset](#case-uclampset), 120 passes | P3 | Decide whether to implement the missing setter surface. |
| `uname`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | uname; uname | 3.349 / 36.171 / 30.490; [uname](#case-uname), 52 passes; 2 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`undo`](../loadables/undo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`unexpand`](../loadables/unexpand.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | unexpand; unexpand | 73.840 / 94.820 / 37.042; [unexpand](#case-unexpand), 9 passes | P3 | Confirm unexpand (1.99× external time), then profile. |
| [`uniq`](../loadables/uniq.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | uniq; uniq | 73.634 / 417.861 / 89.978; [uniq](#case-uniq), 19 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `unlink`* | P C D S T F | Build/help | unlink; unlink | N/M | P3 | Add behavioral fixtures, then timing. |
| [`uptime`](../loadables/uptime.c) | D S T F | [Smoke](../tests/system-smoke.sh) | uptime; uptime | 6.502 / INVALID / 84.491; [uptime](#case-uptime), 84 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`userdb`](../loadables/userdb.c) | S F | [Contract](../tests/system-smoke.sh) | —; getent | N/M | P3 | Add a matched workload and timing. |
| [`utf8`](../loadables/utf8.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; Python Unicode / grapheme library | N/M | P3 | Add a matched workload and timing. |
| [`utmp`](../loadables/utmp.c) | D S F | [Contract](../tests/system-smoke.sh) | who; utmpdump / who | N/M | P3 | Add a matched workload and timing. |
| [`uudecode`](../loadables/uudecode.c) | C D S T F | [Bench checked](#case-uudecode) | uudecode; uudecode (missing) | 37.836 / 107.568 / —; [uudecode](#case-uudecode), 55 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`uuencode`](../loadables/uuencode.c) | C D S T F | Build/help | uuencode; uuencode (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`uuidgen`](../loadables/uuidgen.c) | F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; uuidgen (missing) | N/M | P3 | Add a matched workload and timing. |
| [`vec`](../loadables/vec.c) | T F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; NumPy | N/M | P3 | Add a matched workload and timing. |
| [`vi`](../loadables/vi.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | vi; vi | N/M | P3 | Add a matched workload and timing. |
| [`vmstat`](../loadables/vmstat.c) | D S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; vmstat | N/M | P3 | Add a matched workload and timing. |
| [`vt`](../loadables/vt.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`w`](../loadables/w.c) | D S T F | [Smoke](../tests/system-smoke.sh) | w; w | N/M | P3 | Add behavioral fixtures, then timing. |
| [`wall`](../loadables/wall.c) | T F | [Negative checks](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; wall | N/M | P3 | Add behavioral fixtures, then timing. |
| [`watch`](../loadables/watch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | watch; watch | N/M | P3 | Add a matched workload and timing. |
| [`wc`](../loadables/wc.c) | C D S T F | [Parity](../tests/wc-tail-parity.sh) | wc; wc | 55.759 / 120.230 / 27.311; [wc-characters](#case-wc-characters), 41 passes; 3 cases total | P3 | Confirm wc-characters (2.04× external time), then profile. |
| [`wg`](../loadables/wg.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; wg (missing) | N/M | P3 | Add a matched workload and timing. |
| [`wget_wch`](../loadables/wget_wch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`wgetch`](../loadables/wgetch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`whatis`](../loadables/whatis.c) | T F | [Contract](../tests/misc-smoke.py) | —; whatis | N/M | P3 | Add a matched workload and timing. |
| [`whiptail`](../loadables/whiptail.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; whiptail | N/M | P3 | Add a matched workload and timing. |
| [`who`](../loadables/who.c) | D S T F | [Smoke](../tests/system-smoke.sh) | who; who | N/M | P3 | Add behavioral fixtures, then timing. |
| `whoami`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | whoami; whoami | 3.432 / 102.193 / 84.347; [whoami](#case-whoami), 134 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`wipefs`](../loadables/wipefs.c) | D S F | Build/help | —; wipefs | N/M | P3 | Add behavioral fixtures, then timing. |
| [`write`](../loadables/write.c) | T F | [Negative checks](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; write (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`xargs`](../loadables/xargs.c) | C D S T F | [Contract](../tests/regressions.py) | xargs; xargs | N/M | P3 | Add a matched workload and timing. |
| [`xattr`](../loadables/xattr.c) | S F | [Contract](../tests/system-smoke.sh) | —; getfattr / setfattr | N/M | P3 | Add a matched workload and timing. |
| [`zcat`](../loadables/zcat.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | zcat; zcat | 52.693 / 166.064 / ERROR; [zcat](#case-zcat), 48 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`zlib`](../loadables/zlib.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | gzip; gzip / xz / zstd / bzip2 | 88.770 / 88.840 / 101.980; [zlib-bzip2](#case-zlib-bzip2), 7 passes; 3 cases total | P4 | Extend sizes/options; no selected-case performance priority. |
| [`zstd`](../loadables/zstd.c) | S T F | [Parity](../tests/zstd-check.sh); [S](../tests/zstd-host.c) | —; zstd | 35.039 / — / 82.607; [zstd-decompress](#case-zstd-decompress), 36 passes | P3 | See the dedicated zstd report; extend sizes and levels if a slower case appears. |
| [`zstdcat`](../loadables/zstdcat.c) | S T F | [Parity](../tests/zstd-check.sh) | —; zstdcat | 55.269 / — / 126.311; [zstdcat](#case-zstdcat), 59 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
| `cluster` | Only a version smoke check is mapped here. |
| `col` | Repeated redirected stdin is fixed; tests/col-check.sh matches GNU on three fresh redirections. |
| `colrm` | Repeated redirected stdin is fixed; tests/colrm-check.sh matches GNU on three fresh redirections. |
| `column` | Repeated redirected stdin is fixed; tests/column-check.sh matches GNU on three fresh redirections. |
| `comm` | Repeated-input and write-failure contracts are covered by tests/comm-check.sh. The timed comm case remains slower than GNU on this host. |
| `cp` | A forced copy that cannot read its source keeps the existing destination; tests/cp-check.sh matches GNU. |
| `crypto` | A failed digest write now returns failure; tests/crypto-check.sh covers sha256 -x > /dev/full. |
| `csplit` | Repeated redirected stdin is fixed; tests/csplit-check.sh matches GNU piece files across three redirections. |
| `diff` | Minus operands are stdin, including `diff - -`. The timed case still measures identical files, not edit-script generation. |
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
| `tee` | Closed-stdin and all-outputs-failed stop are covered by tests/tee-check.sh. Stock examples/loadables/tee.c is still the source. |
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
| <a id="case-cat"></a>cat | `cat` | `cat` | text (423,000 stdin bytes) | 80 | 7.768 | 53.060 | 53.499 | 0.15× | 7 |
| <a id="case-head"></a>head | `head -n 100` | `head -n 100` | text (423,000 stdin bytes) | 80 | 8.380 | 57.057 | 45.965 | 0.18× | 7 |
| <a id="case-tail"></a>tail | `tail -n 100` | `tail -n 100` | text (423,000 stdin bytes) | 80 | 5.152 | 119.914 | 52.184 | 0.10× | 7 |
| <a id="case-wc-counts"></a>wc-counts | `wc -lwc` | `wc -lwc` | text (423,000 stdin bytes) | 41 | 56.816 | 121.456 | 72.605 | 0.78× | 7 |
| <a id="case-wc-characters"></a>wc-characters | `wc -m` | `wc -m` | text (423,000 stdin bytes) | 41 | 55.759 | 120.230 | 27.311 | 2.04× | 7 |
| <a id="case-wc-width"></a>wc-width | `wc -L` | `wc -L` | text (423,000 stdin bytes) | 43 | 55.642 | 124.782 | 75.531 | 0.74× | 7 |
| <a id="case-cut"></a>cut | `cut -d ' ' -f 1` | `cut -d ' ' -f 1` | text (423,000 stdin bytes) | 80 | 30.193 | 333.940 | 160.108 | 0.19× | 7 |
| <a id="case-grep-count"></a>grep-count | `grep -c alpha` | `grep -c alpha` | text (423,000 stdin bytes) | 64 | 41.051 | 400.176 | 50.904 | 0.81× | 7 |
| <a id="case-grep-lines"></a>grep-lines | `grep alpha` | `grep alpha` | text (423,000 stdin bytes) | 48 | 41.913 | 307.101 | 38.464 | 1.09× | 7 |
| <a id="case-sed"></a>sed | `sed s/alpha/OMEGA/g` | `sed s/alpha/OMEGA/g` | text (423,000 stdin bytes) | 10 | 73.044 | 88.706 | 60.222 | 1.21× | 7 |
| <a id="case-sort-numeric"></a>sort-numeric | `sort -n` | `sort -n` | numbers (369,296 stdin bytes) | 6 | 80.151 | 587.549 | 151.871 | 0.53× | 7 |
| <a id="case-sort-text"></a>sort-text | `sort` | `sort` | text (423,000 stdin bytes) | 12 | 75.082 | 79.791 | 36.701 | 2.05× | 7 |
| <a id="case-seq"></a>seq | `seq 100000` | `seq 100000` | No stdin; named fixtures / arguments | 43 | 53.982 | 1465.274 | 58.837 | 0.92× | 7 |
| <a id="case-tr"></a>tr | `tr a-z A-Z` | `tr a-z A-Z` | text (423,000 stdin bytes) | 42 | 32.987 | 61.804 | 39.122 | 0.84× | 7 |
| <a id="case-uniq"></a>uniq | `uniq` | `uniq` | duplicates (1,680,000 stdin bytes) | 19 | 73.634 | 417.861 | 89.978 | 0.82× | 7 |
| <a id="case-paste"></a>paste | `paste duplicates duplicates` | `paste duplicates duplicates` | No stdin; named fixtures / arguments | 11 | 78.052 | 424.001 | 79.017 | 0.99× | 7 |
| <a id="case-nl"></a>nl | `nl -ba` | `nl -ba` | text (423,000 stdin bytes) | 34 | 34.206 | 138.103 | 76.600 | 0.45× | 7 |
| <a id="case-rev"></a>rev | `rev` | `rev` | text (423,000 stdin bytes) | 14 | 67.972 | 37.060 | 123.604 | 0.55× | 7 |
| <a id="case-fold"></a>fold | `fold -w 40` | `fold -w 40` | text (423,000 stdin bytes) | 43 | 46.360 | 168.253 | 107.431 | 0.43× | 7 |
| <a id="case-tac"></a>tac | `tac` | `tac` | text (423,000 stdin bytes) | 80 | 14.556 | 373.698 | 77.264 | 0.19× | 7 |
| <a id="case-comm"></a>comm | `comm left right` | `comm left right` | No stdin; named fixtures / arguments | 18 | 71.590 | — | 27.610 | 2.59× | 7 |
| <a id="case-join"></a>join | `join left right` | `join left right` | No stdin; named fixtures / arguments | 18 | 67.603 | — | 43.602 | 1.55× | 7 |
| <a id="case-expand"></a>expand | `expand -t 8` | `expand -t 8` | tabs (340,000 stdin bytes) | 38 | 62.200 | 291.918 | 74.917 | 0.83× | 7 |
| <a id="case-unexpand"></a>unexpand | `unexpand -a` | `unexpand -a` | spaces (440,000 stdin bytes) | 9 | 73.840 | 94.820 | 37.042 | 1.99× | 7 |
| <a id="case-pr"></a>pr | `pr -t` | `pr -t` | text (423,000 stdin bytes) | 65 | 20.020 | — | 283.951 | 0.07× | 7 |
| <a id="case-colrm"></a>colrm | `colrm 4` | `colrm 4` | text (423,000 stdin bytes) | 24 | 65.306 | — | 125.531 | 0.52× | 7 |
| <a id="case-column"></a>column | `column -t` | `column -t` | tabs (340,000 stdin bytes) | 7 | 82.020 | — | 343.863 | 0.24× | 7 |
| <a id="case-strings"></a>strings | `strings -n 4` | `strings -n 4` | bytes (65,536 stdin bytes) | 80 | 26.746 | 79.747 | 118.348 | 0.23× | 7 |
| <a id="case-od"></a>od | `od -An -tx1` | `od -An -tx1` | bytes (65,536 stdin bytes) | 12 | 67.196 | 57.117 | 128.984 | 0.52× | 7 |
| <a id="case-hexdump"></a>hexdump | `hexdump -C` | `hexdump -C` | bytes (65,536 stdin bytes) | 12 | 79.830 | 95.853 | 141.459 | 0.56× | 7 |
| <a id="case-basename"></a>basename | `basename /fixture/path/file.txt` | `basename /fixture/path/file.txt` | No stdin; named fixtures / arguments | 128 | 3.679 | 80.543 | 66.570 | 0.06× | 7 |
| <a id="case-dirname"></a>dirname | `dirname /fixture/path/file.txt` | `dirname /fixture/path/file.txt` | No stdin; named fixtures / arguments | 140 | 3.700 | 92.299 | 74.296 | 0.05× | 7 |
| <a id="case-readlink"></a>readlink | `readlink link` | `readlink link` | No stdin; named fixtures / arguments | 127 | 3.860 | 88.336 | 71.570 | 0.05× | 7 |
| <a id="case-realpath"></a>realpath | `realpath link` | `realpath link` | No stdin; named fixtures / arguments | 143 | 4.220 | 102.687 | 81.890 | 0.05× | 7 |
| <a id="case-stat"></a>stat | `stat -c %s text` | `stat -c %s text` | No stdin; named fixtures / arguments | 141 | 4.251 | 102.813 | 108.442 | 0.04× | 7 |
| <a id="case-ls"></a>ls | `ls -1 tree` | `ls -1 tree` | No stdin; named fixtures / arguments | 80 | 14.262 | 86.634 | 77.091 | 0.19× | 7 |
| <a id="case-find"></a>find | `find tree -type f` | `find tree -type f` | No stdin; named fixtures / arguments | 80 | 25.423 | 78.876 | 76.467 | 0.33× | 7 |
| <a id="case-cmp"></a>cmp | `cmp text copy` | `cmp text copy` | No stdin; named fixtures / arguments | 70 | 44.183 | 222.165 | 53.205 | 0.83× | 7 |
| <a id="case-diff"></a>diff | `diff text copy` | `diff text copy` | No stdin; named fixtures / arguments | 37 | 70.812 | 59.935 | 42.551 | 1.66× | 7 |
| <a id="case-dd"></a>dd | `dd if=text bs=64K status=none` | `dd if=text bs=64K status=none` | No stdin; named fixtures / arguments | 80 | 5.449 | 59.103 | 51.778 | 0.11× | 7 |
| <a id="case-cp"></a>cp | `cp text copied` | `cp text copied` | No stdin; named fixtures / arguments | 80 | 14.991 | 68.229 | 84.129 | 0.18× | 7 |
| <a id="case-cksum"></a>cksum | `cksum` | `cksum` | text (423,000 stdin bytes) | 48 | 52.159 | — | 78.598 | 0.66× | 7 |
| <a id="case-bashbase64"></a>bashbase64 | `bashbase64 -w 0` | `base64 -w 0` | bytes (65,536 stdin bytes) | 80 | 8.261 | 68.794 | 56.985 | 0.14× | 7 |
| <a id="case-bashjson"></a>bashjson | `bashjson get .answer` | `jq .answer` | object (39,133 stdin bytes) | 80 | 35.779 | — | 305.617 | 0.12× | 7 |
| <a id="case-awk"></a>awk | `awk '{sum += $2} END {print sum}'` | `awk '{sum += $2} END {print sum}'` | records (162,830 stdin bytes) | 12 | 62.968 | 126.214 | 69.215 | 0.91× | 7 |
| <a id="case-jq"></a>jq | `jq -c '[.[] &#124; select(. > 50)]'` | `jq -c '[.[] &#124; select(. > 50)]'` | array (39,109 stdin bytes) | 9 | 52.894 | — | 81.540 | 0.65× | 7 |
| <a id="case-bc"></a>bc | `bc` | `bc` | arithmetic (18 stdin bytes) | 80 | 4.644 | 64.313 | 65.473 | 0.07× | 7 |
| <a id="case-expr"></a>expr | `expr 123 '*' 456` | `expr 123 '*' 456` | No stdin; named fixtures / arguments | 154 | 4.508 | 111.572 | 102.782 | 0.04× | 7 |
| <a id="case-crypto"></a>crypto | `crypto sha256 -x` | `sha256sum` | blob (1,048,576 stdin bytes) | 12 | 74.817 | 74.245 | 50.746 | 1.47× | 7 |
| <a id="case-uname"></a>uname | `uname` | `uname` | No stdin; named fixtures / arguments | 52 | 3.349 | 36.171 | 30.490 | 0.11× | 7 |
| <a id="case-whoami"></a>whoami | `whoami` | `whoami` | No stdin; named fixtures / arguments | 134 | 3.432 | 102.193 | 84.347 | 0.04× | 7 |
| <a id="case-logname"></a>logname | `logname` | `logname` | No stdin; named fixtures / arguments | 132 | 5.290 | 107.028 | 84.809 | 0.06× | 7 |
| <a id="case-hostname"></a>hostname | `hostname` | `hostname` | No stdin; named fixtures / arguments | 143 | 3.775 | 97.378 | 75.446 | 0.05× | 7 |
| <a id="case-id-uid"></a>id-uid | `id -u` | `id -u` | No stdin; named fixtures / arguments | 148 | 4.668 | 118.863 | 111.250 | 0.04× | 7 |
| <a id="case-printenv-lcall"></a>printenv-lcall | `printenv LC_ALL` | `printenv LC_ALL` | No stdin; named fixtures / arguments | 122 | 4.182 | — | 71.297 | 0.06× | 7 |
| <a id="case-touch"></a>touch | `touch touched` | `touch touched` | No stdin; named fixtures / arguments | 118 | 3.610 | 88.410 | 77.395 | 0.05× | 7 |
| <a id="case-mkdir"></a>mkdir | `mkdir -p mdir` | `mkdir -p mdir` | No stdin; named fixtures / arguments | 139 | 5.168 | 121.505 | 131.795 | 0.04× | 7 |
| <a id="case-chmod"></a>chmod | `chmod 644 text` | `chmod 644 text` | No stdin; named fixtures / arguments | 102 | 4.484 | 90.870 | 73.351 | 0.06× | 7 |
| <a id="case-date-year"></a>date-year | `date -u +%Y` | `date -u +%Y` | No stdin; named fixtures / arguments | 114 | 3.456 | 81.956 | 66.946 | 0.05× | 7 |
| <a id="case-getconf"></a>getconf | `getconf PAGE_SIZE` | `getconf PAGE_SIZE` | No stdin; named fixtures / arguments | 152 | 3.837 | — | 83.616 | 0.05× | 7 |
| <a id="case-pathchk"></a>pathchk | `pathchk text` | `pathchk text` | No stdin; named fixtures / arguments | 120 | 3.318 | — | 68.444 | 0.05× | 7 |
| <a id="case-ln"></a>ln | `ln -f text lnout` | `ln -f text lnout` | No stdin; named fixtures / arguments | 152 | 4.918 | 104.882 | 93.018 | 0.05× | 7 |
| <a id="case-sync"></a>sync | `sync` | `sync` | No stdin; named fixtures / arguments | 20 | 5.655 | 22.431 | 18.756 | 0.30× | 7 |
| <a id="case-rm"></a>rm | `rm -f nosuch` | `rm -f nosuch` | No stdin; named fixtures / arguments | 134 | 3.660 | 89.885 | 76.418 | 0.05× | 7 |
| <a id="case-chown"></a>chown | `chown pleb text` | `chown pleb text` | No stdin; named fixtures / arguments | 144 | 5.242 | 106.276 | 91.887 | 0.06× | 7 |
| <a id="case-chgrp"></a>chgrp | `chgrp pleb text` | `chgrp pleb text` | No stdin; named fixtures / arguments | 116 | 5.311 | 86.114 | 72.067 | 0.07× | 7 |
| <a id="case-sleep"></a>sleep | `sleep 0` | `sleep 0` | No stdin; named fixtures / arguments | 94 | 9.795 | 91.824 | 74.081 | 0.13× | 7 |
| <a id="case-nice"></a>nice | `nice -n 0 /bin/true` | `nice -n 0 /bin/true` | No stdin; named fixtures / arguments | 60 | 40.315 | — | 66.109 | 0.61× | 7 |
| <a id="case-nohup"></a>nohup | `nohup /bin/true` | `nohup /bin/true` | No stdin; named fixtures / arguments | 56 | 37.776 | — | 61.629 | 0.61× | 7 |
| <a id="case-setsid"></a>setsid | `setsid /bin/true` | `setsid /bin/true` | No stdin; named fixtures / arguments | 108 | 55.379 | 102.391 | 88.526 | 0.63× | 7 |
| <a id="case-flock"></a>flock | `flock -n lockfile /bin/true` | `flock -n lockfile /bin/true` | No stdin; named fixtures / arguments | 81 | 40.423 | — | 75.590 | 0.53× | 7 |
| <a id="case-taskset"></a>taskset | `taskset -p 1` | `taskset -p 1` | No stdin; named fixtures / arguments | 140 | 3.962 | 96.418 | 79.384 | 0.05× | 7 |
| <a id="case-ionice"></a>ionice | `ionice -p 1` | `ionice -p 1` | No stdin; named fixtures / arguments | 124 | 3.740 | 91.492 | 72.305 | 0.05× | 7 |
| <a id="case-env"></a>env | `env -i FOO=bar /usr/bin/printenv FOO` | `env -i FOO=bar /usr/bin/printenv FOO` | No stdin; named fixtures / arguments | 63 | 34.064 | 65.522 | 57.376 | 0.59× | 7 |
| <a id="case-sysctl"></a>sysctl | `sysctl -n kernel.osrelease` | `sysctl -n kernel.osrelease` | No stdin; named fixtures / arguments | 120 | 5.194 | 86.868 | 69.258 | 0.07× | 7 |
| <a id="case-id-user"></a>id-user | `id -un` | `id -un` | No stdin; named fixtures / arguments | 133 | 4.917 | 102.001 | 104.991 | 0.05× | 7 |
| <a id="case-id-group"></a>id-group | `id -gn` | `id -gn` | No stdin; named fixtures / arguments | 116 | 4.865 | 86.569 | 90.369 | 0.05× | 7 |
| <a id="case-hostname-s"></a>hostname-s | `hostname -s` | `hostname -s` | No stdin; named fixtures / arguments | 150 | 3.861 | 103.044 | 81.287 | 0.05× | 7 |
| <a id="case-uname-s"></a>uname-s | `uname -s` | `uname -s` | No stdin; named fixtures / arguments | 137 | 4.551 | 98.962 | 74.415 | 0.06× | 7 |
| <a id="case-date-ymd"></a>date-ymd | `date -u +%Y-%m-%d` | `date -u +%Y-%m-%d` | No stdin; named fixtures / arguments | 82 | 3.255 | 58.465 | 46.877 | 0.07× | 7 |
| <a id="case-getconf-nproc"></a>getconf-nproc | `getconf _NPROCESSORS_ONLN` | `getconf _NPROCESSORS_ONLN` | No stdin; named fixtures / arguments | 147 | 4.461 | — | 82.935 | 0.05× | 7 |
| <a id="case-df"></a>df | `df -P /dev` | `df -P /dev` | No stdin; named fixtures / arguments | 99 | 14.781 | 94.035 | 85.720 | 0.17× | 7 |
| <a id="case-uptime"></a>uptime | `uptime -s` | `uptime -s` | No stdin; named fixtures / arguments | 84 | 6.502 | INVALID | 84.491 | 0.08× | 7 |
| <a id="case-tee"></a>tee | `tee` | `tee` | text (423,000 stdin bytes) | 80 | 7.061 | 76.696 | 52.926 | 0.13× | 7 |
| <a id="case-hostid"></a>hostid | `hostid` | `hostid` | No stdin; named fixtures / arguments | 132 | 6.507 | 137.975 | 114.184 | 0.06× | 7 |
| <a id="case-timeout"></a>timeout | `timeout 1 /bin/true` | `timeout 1 /bin/true` | No stdin; named fixtures / arguments | 79 | 45.541 | 91.302 | 84.175 | 0.54× | 7 |
| <a id="case-du-tree"></a>du-tree | `du -b tree` | `du -b tree` | No stdin; named fixtures / arguments | 80 | 24.347 | INVALID | 83.615 | 0.29× | 7 |
| <a id="case-du-file"></a>du-file | `du -b text` | `du -b text` | No stdin; named fixtures / arguments | 80 | 4.562 | 81.444 | 68.621 | 0.07× | 7 |
| <a id="case-truncate"></a>truncate | `truncate -s 4096 truncout` | `truncate -s 4096 truncout` | No stdin; named fixtures / arguments | 116 | 3.816 | 84.604 | 68.086 | 0.06× | 7 |
| <a id="case-ar"></a>ar | `ar t tiny.a` | `ar t tiny.a` | No stdin; named fixtures / arguments | 114 | 5.109 | 108.164 | 144.300 | 0.04× | 7 |
| <a id="case-zstdcat"></a>zstdcat | `zstdcat text.zst` | `zstdcat text.zst` | No stdin; named fixtures / arguments | 59 | 55.269 | — | 126.311 | 0.44× | 7 |
| <a id="case-zstd-decompress"></a>zstd-decompress | `zstd -d -c text.zst` | `zstd -d -c text.zst` | No stdin; named fixtures / arguments | 36 | 35.039 | — | 82.607 | 0.42× | 7 |
| <a id="case-zcat"></a>zcat | `zcat text.gz` | `zcat text.gz` | No stdin; named fixtures / arguments | 48 | 52.693 | 166.064 | ERROR | — | 7 |
| <a id="case-file"></a>file | `file text` | `file text` | No stdin; named fixtures / arguments | 106 | 4.289 | — | 965.361 | 0.00× | 7 |
| <a id="case-split"></a>split | `split -l 1000 text` | `split -l 1000 text` | No stdin; named fixtures / arguments | 64 | 36.133 | — | 70.925 | 0.51× | 7 |
| <a id="case-csplit"></a>csplit | `csplit text 10 20` | `csplit text 10 20` | No stdin; named fixtures / arguments | 39 | 36.451 | — | 47.426 | 0.77× | 7 |
| <a id="case-opt"></a>opt | `opt -o ab: -- -a -b x` | `getopt -o ab: -- -a -b x` | No stdin; named fixtures / arguments | 131 | 4.558 | 105.866 | 86.712 | 0.05× | 7 |
| <a id="case-uudecode"></a>uudecode | `uudecode -o -` | `uudecode -o -` | uuencoded (90,320 stdin bytes) | 55 | 37.836 | 107.568 | — | — | 7 |
| <a id="case-strftime"></a>strftime | `strftime %Y-%m-%d 0` | `date -u -d @0 +%Y-%m-%d` | No stdin; named fixtures / arguments | 140 | 3.953 | 98.357 | 83.032 | 0.05× | 7 |
| <a id="case-strptime"></a>strptime | `strptime '1970-01-01 00:00:00' '%Y-%m-%d %H:%M:%S'` | `date -u -d '1970-01-01 00:00:00' +%s` | No stdin; named fixtures / arguments | 126 | 5.318 | 86.082 | 70.941 | 0.07× | 7 |
| <a id="case-zlib"></a>zlib | `zlib -f gzip text.gz` | `gzip -dc text.gz` | No stdin; named fixtures / arguments | 50 | 48.088 | 140.978 | 112.828 | 0.43× | 7 |
| <a id="case-pax"></a>pax | `pax -f tiny.tar` | `tar tf tiny.tar` | No stdin; named fixtures / arguments | 80 | 4.829 | 74.143 | 104.667 | 0.05× | 7 |
| <a id="case-tput"></a>tput | `tput cols` | `tput cols` | No stdin; named fixtures / arguments | 141 | 4.076 | — | 95.437 | 0.04× | 7 |
| <a id="case-less"></a>less | `less text` | `less text` | No stdin; named fixtures / arguments | 23 | 53.126 | 17.116 | 99.188 | 0.54× | 7 |
| <a id="case-chrt"></a>chrt | `chrt -m` | `chrt -m` | No stdin; named fixtures / arguments | 127 | 4.115 | — | 73.644 | 0.06× | 7 |
| <a id="case-signal"></a>signal | `signal -n TERM` | `kill -l TERM` | No stdin; named fixtures / arguments | 136 | 3.605 | 93.127 | 76.166 | 0.05× | 7 |
| <a id="case-cal"></a>cal | `cal 2 2024` | `cal 2 2024` | No stdin; named fixtures / arguments | 132 | 4.032 | 95.664 | — | — | 7 |
| <a id="case-ed"></a>ed | `ed -s left` | `ed -s left` | edscript (7 stdin bytes) | 48 | 45.937 | 66.697 | — | — | 7 |
| <a id="case-finfo"></a>finfo | `finfo -s text` | `stat -c %s text` | No stdin; named fixtures / arguments | 159 | 4.191 | 117.135 | 114.933 | 0.04× | 7 |
| <a id="case-fltexpr"></a>fltexpr | `fltexpr -p '1+2*3'` | `awk 'BEGIN{print 1+2*3}'` | No stdin; named fixtures / arguments | 130 | 4.832 | 120.849 | 221.000 | 0.02× | 7 |
| <a id="case-pcre"></a>pcre | `pcre grep alpha text` | `grep -P alpha text` | No stdin; named fixtures / arguments | 10 | 46.109 | ERROR | 10.564 | 4.36× | 7 |
| <a id="case-uclampset"></a>uclampset | `uclampset -p 1` | `uclampset -p 1` | No stdin; named fixtures / arguments | 120 | 4.274 | — | 70.703 | 0.06× | 7 |
| <a id="case-tz"></a>tz | `tz convert 0 -z UTC` | `date -u -d @0 '+%Y-%m-%d %H:%M:%S UTC +0000'` | No stdin; named fixtures / arguments | 128 | 3.830 | 94.323 | 76.262 | 0.05× | 7 |
| <a id="case-ip"></a>ip | `ip -br link show lo` | `ip -br link show lo` | No stdin; named fixtures / arguments | 130 | 6.611 | ERROR | 151.618 | 0.04× | 7 |
| <a id="case-tinfo"></a>tinfo | `tinfo getnum cols` | `tput cols` | No stdin; named fixtures / arguments | 118 | 4.312 | — | 87.535 | 0.05× | 7 |
| <a id="case-tput-lines"></a>tput-lines | `tput lines` | `tput lines` | No stdin; named fixtures / arguments | 100 | 3.688 | — | 78.494 | 0.05× | 7 |
| <a id="case-signal-name"></a>signal-name | `signal -s 15` | `kill -l 15` | No stdin; named fixtures / arguments | 138 | 3.905 | 105.640 | 83.385 | 0.05× | 7 |
| <a id="case-finfo-mode"></a>finfo-mode | `finfo -o text` | `stat -c %a text` | No stdin; named fixtures / arguments | 106 | 3.729 | 87.294 | 84.916 | 0.04× | 7 |
| <a id="case-chrt-pid1"></a>chrt-pid1 | `chrt -p 1` | `chrt -p 1` | No stdin; named fixtures / arguments | 135 | 4.286 | — | 86.193 | 0.05× | 7 |
| <a id="case-zlib-xz"></a>zlib-xz | `zlib -f xz text.xz` | `xz -dc text.xz` | No stdin; named fixtures / arguments | 31 | 53.746 | 144.882 | 88.324 | 0.61× | 7 |
| <a id="case-zlib-bzip2"></a>zlib-bzip2 | `zlib -f bzip2 text.bz2` | `bzip2 -dc text.bz2` | No stdin; named fixtures / arguments | 7 | 88.770 | 88.840 | 101.980 | 0.87× | 7 |
| <a id="case-coreutils-numfmt"></a>coreutils-numfmt | `coreutils numfmt --to=iec 1024 4096` | `numfmt --to=iec 1024 4096` | No stdin; named fixtures / arguments | 66 | 3.363 | — | 42.022 | 0.08× | 7 |
| <a id="case-coreutils-tsort"></a>coreutils-tsort | `coreutils tsort chain` | `tsort chain` | No stdin; named fixtures / arguments | 147 | 5.061 | — | 92.682 | 0.05× | 7 |
| <a id="case-coreutils-factor"></a>coreutils-factor | `coreutils factor 1234567890 97` | `factor 1234567890 97` | No stdin; named fixtures / arguments | 141 | 5.827 | 102.189 | 91.381 | 0.06× | 7 |
| <a id="case-coreutils-groups"></a>coreutils-groups | `coreutils groups` | `groups` | No stdin; named fixtures / arguments | 122 | 20.074 | 154.863 | 126.393 | 0.16× | 7 |
| <a id="case-coreutils-install"></a>coreutils-install | `coreutils install -m 644 text installed` | `install -m 644 text installed` | No stdin; named fixtures / arguments | 59 | 13.985 | 61.860 | 75.621 | 0.18× | 7 |
| <a id="case-lsblk"></a>lsblk | `lsblk -d -n -o NAME` | `lsblk -d -n -o NAME` | No stdin; named fixtures / arguments | 62 | 46.983 | — | 89.697 | 0.52× | 7 |
| <a id="case-binhex"></a>binhex | `binhex` | `hexdump -ve '/1 "%02x"'` | bytes (65,536 stdin bytes) | 80 | 9.642 | 513.777 | 578.622 | 0.02× | 7 |
| <a id="case-binhex-decode"></a>binhex-decode | `binhex -d` | `xxd -r -p` | hexbytes (131,072 stdin bytes) | 80 | 31.396 | 187.850 | 167.220 | 0.19× | 7 |
| <a id="case-prlimit"></a>prlimit | `prlimit --nofile` | `prlimit -o RESOURCE,SOFT,HARD --noheadings --nofile` | No stdin; named fixtures / arguments | 119 | 3.844 | — | 92.334 | 0.04× | 7 |
| <a id="case-prlimit-cpu"></a>prlimit-cpu | `prlimit --cpu` | `prlimit -o RESOURCE,SOFT,HARD --noheadings --cpu` | No stdin; named fixtures / arguments | 110 | 4.625 | — | 104.772 | 0.04× | 7 |
| <a id="case-fincore"></a>fincore | `fincore -n text` | `fincore -n --bytes text` | No stdin; named fixtures / arguments | 118 | 5.656 | — | 90.871 | 0.06× | 7 |
| <a id="case-col"></a>col | `col -b` | `col -b` | left (120,000 stdin bytes) | 19 | 63.847 | — | 116.183 | 0.55× | 7 |
| <a id="case-coreutils-factor-big"></a>coreutils-factor-big | `coreutils factor 111111111111` | `factor 111111111111` | No stdin; named fixtures / arguments | 129 | 4.103 | 99.244 | 84.306 | 0.05× | 7 |
| <a id="case-coreutils-fmt"></a>coreutils-fmt | `coreutils fmt -w 20 left` | `fmt -w 20 left` | No stdin; named fixtures / arguments | 20 | 76.873 | — | 41.216 | 1.87× | 7 |
| <a id="case-coreutils-tac"></a>coreutils-tac | `coreutils tac left` | `tac left` | No stdin; named fixtures / arguments | 21 | 55.077 | 101.479 | 23.139 | 2.38× | 7 |
| <a id="case-bignum"></a>bignum | `bignum add 999999999999999999 1` | `expr 999999999999999999 + 1` | No stdin; named fixtures / arguments | 132 | 4.824 | 116.978 | 91.528 | 0.05× | 7 |
| <a id="case-bignum-mul"></a>bignum-mul | `bignum mul 123 456` | `expr 123 '*' 456` | No stdin; named fixtures / arguments | 121 | 4.246 | 94.127 | 95.179 | 0.04× | 7 |
| <a id="case-ncdu-print"></a>ncdu-print | `ncdu -a -p tree` | `du --apparent-size --block-size=1 tree` | No stdin; named fixtures / arguments | 98 | 28.085 | ERROR | 104.802 | 0.27× | 7 |
| <a id="case-blkid-type"></a>blkid-type | `blkid -s TYPE -o value disk.img` | `blkid -s TYPE -o value disk.img` | No stdin; named fixtures / arguments | 112 | 5.277 | INVALID | 149.470 | 0.04× | 7 |
| <a id="case-blkid-label"></a>blkid-label | `blkid -s LABEL -o value disk.img` | `blkid -s LABEL -o value disk.img` | No stdin; named fixtures / arguments | 142 | 6.064 | INVALID | 194.961 | 0.03× | 7 |
| <a id="case-man"></a>man | `man -w ls` | `man -w ls` | No stdin; named fixtures / arguments | 84 | 4.030 | — | 1248.570 | 0.00× | 7 |
<!-- END CASES -->

## Method and limits

<!-- BEGIN METHOD -->
The command measurements use the native dynamic full `out/bash` at the source above, SHA-256 `00d0345a9fda86924c6a912f9264fe8050b51068c19982bcdb8d31b4f69d6e08`. Host: Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz, x86_64 Linux 6.12.96+deb13-amd64; pinned CPUs: 11. Reference versions and fixture hashes are recorded in the measurement JSON. These are host measurements; no per-command RISC-V or appliance performance is claimed.

Every case uses 7 timed samples after output validation and warm-up. The one-minute host load was 4.3 at the start and 5.5 at the end. A shared lock serialized participating benchmarks; builds and other host activity could still contend. Use the recorded ranges for prioritization and repeat on the intended device before claiming small performance differences.
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
