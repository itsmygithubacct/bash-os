# Loadable status and benchmark work queue

Start with the repeated-input bugs in `head` and `sed`. Fixing those is more
useful than optimizing a command that silently produces incomplete output.
For performance work after that, `fold` is the strongest first candidate in
this measurement: it is slower than both BusyBox and the external reference.

This is the **2026-09-08** review of the complete
[build catalog](../config/bash-loadables.list). The
[CSV](loadables-status.csv) has one row per loadable for filtering by profile,
status, priority, counterpart and measurement. The
[measurement summary](data/loadable-benchmarks.json) retains fixture hashes,
sample counts and timing ranges. Raw run logs stay outside the repository.

Follow-up: the [tac update](tac.md) completes its selected performance work
and adds dedicated parity and sanitizer coverage. Its row now points to the
remaining memory and regex scope work. The numeric timings below retain the
original snapshot; the update has a separate before/after comparison.

<!-- BEGIN SUMMARY -->
Catalog: **278 loadables** (247 local sources, 31 stock Bash sources). Command benchmark: **49 cases covering 45 loadables**; 35 loadables passed the selected output checks, 10 have confirmed correctness findings. The other 233 have no individual command timings here; GPU transport measurements are reported separately.

| Profile | Included loadables |
| --- | --- |
| shell | 0 |
| pure | 28 |
| core | 89 |
| device | 160 |
| server | 214 |
| desktop | 153 |
| full | 278 |

Code snapshot: `af3c8c488d6b4d81025a5feab4d04f8ee5e402f5`; [baseline CI](https://github.com/itsmygithubacct/bash-os/actions/runs/34175141733) passed all nine jobs (including 48 native test groups). Those suites did not detect the repeated-input findings below. All catalog entries were built and registered in the full native and static RISC-V binaries; this is not full CLI conformance. Coverage labels describe the mapped fixtures, not a guarantee that every option works.
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
| P1 | head, sed | Repeated redirected input is wrong; common text paths. | Fix persistent-shell input handling and add regressions before any optimization. |
| P1 | bc, colrm, column, hexdump, nl, od, pr, strings | The same three-call check also produces wrong output. | Audit each command; share a fix only after establishing its cause. |
| P2 | [fold](#case-fold) | 3.58× external time; 2.30× BusyBox time; output checks pass, seven samples. | Profile input/output and allocation costs on this fixture, then measure the proposed change. |
| P2 | [expand](#case-expand) | 3.02× external time; 1.00× BusyBox time; output checks pass, seven samples. | Profile input/output and allocation costs on this fixture, then measure the proposed change. |
| P2 | [comm](#case-comm) | 2.72× external time; output checks pass, seven samples. | Profile input/output and allocation costs on this fixture, then measure the proposed change. |
| P2 | [sort-text](#case-sort-text) | 2.11× external time; 0.96× BusyBox time; output checks pass, seven samples. | Profile input/output and allocation costs on this fixture, then measure the proposed change. |
| P3 | unexpand, wc -m, diff, join, crypto sha256 | Slower than the external reference in the first five-sample run. | Confirm across input sizes before optimizing; crypto covers SHA-256 only. |
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
| [`ar`](../loadables/ar.c) | C D S T F | Build/help | ar; ar | N/M | P3 | Add behavioral fixtures, then timing. |
| `asort`* | F | [Contract](../tests/misc-smoke.py) | —; gawk asort() | N/M | P3 | Add a matched workload and timing. |
| [`at`](../loadables/at.c) | S F | [Contract](../tests/misc-smoke.py) | —; at (missing) | N/M | P3 | Add a matched workload and timing. |
| [`audit`](../loadables/audit.c) | S F | [Contract](../tests/network-smoke.py) | —; auditctl / ausearch | N/M | P3 | Add a matched workload and timing. |
| [`auth`](../loadables/auth.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`awk`](../loadables/awk.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | awk; awk | 65.226 / 146.354 / 73.818; [awk](#case-awk), 14 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `basename`* | P C D S T F | [Contract](../tests/host-smoke.sh) | basename; basename | 3.469 / 90.219 / 68.394; [basename](#case-basename), 128 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashbase64`](../loadables/bashbase64.c) | D S F | [Bench checked](#case-bashbase64) | base64; base64 | 7.893 / 62.127 / 60.144; [bashbase64](#case-bashbase64), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashclock`](../loadables/bashclock.c) | D S F | Build/help | —; Bash EPOCHREALTIME / Python time | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashdhcp`](../loadables/bashdhcp.c) | D S F | Build/help | udhcpc; dhclient / udhcpc | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashinotify`](../loadables/bashinotify.c) | D S F | Build/help | inotifyd (not in build); inotifywait (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashio`](../loadables/bashio.c) | D S F | Build/help | —; Python os.pread/os.pwrite | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashjson`](../loadables/bashjson.c) | D S F | [Bench checked](#case-bashjson) | —; jq | 32.663 / — / 263.797; [bashjson](#case-bashjson), 75 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`bashkmod`](../loadables/bashkmod.c) | D S F | Build/help | modprobe; modprobe / insmod / rmmod | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashlogger`](../loadables/bashlogger.c) | D S F | Build/help | logger; logger | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashmount`](../loadables/bashmount.c) | D S F | Build/help | mount; mount / umount / findmnt | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashpoll`](../loadables/bashpoll.c) | D S F | Build/help | —; Python selectors / socket | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashsyslogd`](../loadables/bashsyslogd.c) | D S F | Build/help | syslogd; rsyslogd / syslogd | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bashtermraw`](../loadables/bashtermraw.c) | D S F | Build/help | stty; stty | N/M | P3 | Add behavioral fixtures, then timing. |
| [`batch`](../loadables/batch.c) | S F | [Contract](../tests/misc-smoke.py) | —; batch (missing) | N/M | P3 | Add a matched workload and timing. |
| [`bc`](../loadables/bc.c) | S T F | [Repeat-input bug](#repeated-input-findings); [limited](#scope-notes); [S](../tests/large-sanitize.sh) | bc; bc | INVALID / 59.262 / 66.245; [bc](#case-bc), 80 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| [`bignum`](../loadables/bignum.c) | T F | [Contract](../tests/misc-smoke.py) | bc; Python int / bc | N/M | P3 | Add a matched workload and timing. |
| [`binhex`](../loadables/binhex.c) | D S F | Build/help | xxd; xxd | N/M | P3 | Add behavioral fixtures, then timing. |
| [`blkid`](../loadables/blkid.c) | D S F | Build/help | blkid; blkid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`blockdev`](../loadables/blockdev.c) | D S F | Build/help | blockdev; blockdev | N/M | P3 | Add behavioral fixtures, then timing. |
| [`bsdgames`](../loadables/bsdgames.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; bsdgames (missing) | N/M | P3 | Add a matched workload and timing. |
| [`buf`](../loadables/buf.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cal`](../loadables/cal.c) | T F | [Contract](../tests/misc-smoke.py) | cal; cal (missing) | N/M | P3 | Add a matched workload and timing. |
| [`caps`](../loadables/caps.c) | S F | [Smoke](../tests/system-smoke.sh) | —; capsh / setpriv | N/M | P3 | Add behavioral fixtures, then timing. |
| `cat`* | P C D S T F | [Contract](../tests/host-smoke.sh) | cat; cat | 7.802 / 53.267 / 66.240; [cat](#case-cat), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`chattr`](../loadables/chattr.c) | D S F | Build/help | —; chattr | N/M | P3 | Add behavioral fixtures, then timing. |
| [`chgrp`](../loadables/chgrp.c) | C D S T F | Build/help | chgrp; chgrp | N/M | P3 | Add behavioral fixtures, then timing. |
| `chmod`* | P C D S T F | Build/help | chmod; chmod | N/M | P3 | Add behavioral fixtures, then timing. |
| [`chown`](../loadables/chown.c) | C D S T F | Build/help | chown; chown | N/M | P3 | Add behavioral fixtures, then timing. |
| [`chrt`](../loadables/chrt.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | —; chrt | N/M | P3 | Add a matched workload and timing. |
| [`cksum`](../loadables/cksum.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; cksum | 52.015 / — / 75.268; [cksum](#case-cksum), 49 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`claude`](../loadables/claude.c) | F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`clip`](../loadables/clip.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cluster`](../loadables/cluster.c) | F | [Smoke](../tests/misc-smoke.py) | —; API fixture | N/M | P3 | Add peer membership, timeout and disconnect fixtures. |
| [`cmp`](../loadables/cmp.c) | C D S T F | [Bench checked](#case-cmp) | cmp; cmp | 34.946 / 197.742 / 43.839; [cmp](#case-cmp), 65 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`col`](../loadables/col.c) | C D S T F | Build/help | —; col | N/M | P3 | Add behavioral fixtures, then timing. |
| [`colrm`](../loadables/colrm.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | —; colrm | INVALID / — / 358.006; [colrm](#case-colrm), 71 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| [`column`](../loadables/column.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | —; column | INVALID / — / 1219.587; [column](#case-column), 28 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| [`comm`](../loadables/comm.c) | C D S T F | [Bench checked](#case-comm) | —; comm | 68.930 / — / 25.360; [comm](#case-comm), 18 passes | P2 | Profile comm: 2.72× external time. |
| [`coreutils`](../loadables/coreutils.c) | F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; Individual coreutils programs | N/M | P3 | Add a matched workload and timing. |
| [`cp`](../loadables/cp.c) | C D S T F | [Contract](../tests/host-smoke.sh) | cp; cp | 13.826 / 64.407 / 76.063; [cp](#case-cp), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`cred`](../loadables/cred.c) | S F | [Smoke](../tests/system-smoke.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`cron`](../loadables/cron.c) | S F | [Contract](../tests/large-smoke.py) | crond; cron / crond | N/M | P3 | Add a matched workload and timing. |
| [`crontab`](../loadables/crontab.c) | S F | [Contract](../tests/misc-smoke.py) | crontab; crontab | N/M | P3 | Add a matched workload and timing. |
| [`crypto`](../loadables/crypto.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | sha256sum; sha256sum / openssl | 73.100 / 86.568 / 55.292; [crypto](#case-crypto), 13 passes | P3 | Confirm crypto (1.32× external time), then profile. |
| [`csplit`](../loadables/csplit.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; csplit | N/M | P3 | Add a matched workload and timing. |
| [`curl`](../loadables/curl.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; curl | N/M | P3 | Add a matched workload and timing. |
| [`cut`](../loadables/cut.c) | P C D S T F | [Parity](../tests/cut-parity.sh) | cut; cut | 21.804 / 257.249 / 123.297; [cut](#case-cut), 61 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`date`](../loadables/date.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | date; date | N/M | P3 | Add a matched workload and timing. |
| [`dd`](../loadables/dd.c) | C D S T F | [Bench checked](#case-dd) | dd; dd | 5.771 / 59.411 / 49.247; [dd](#case-dd), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`df`](../loadables/df.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | df; df | N/M | P3 | Add a matched workload and timing. |
| [`dhcp6`](../loadables/dhcp6.c) | S F | [Contract](../tests/network-smoke.py) | udhcpc6; dhclient -6 | N/M | P3 | Add a matched workload and timing. |
| [`dhcpd`](../loadables/dhcpd.c) | S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | udhcpd; dnsmasq / dhcpd | N/M | P3 | Add a matched workload and timing. |
| [`dhcpd6`](../loadables/dhcpd6.c) | S F | [Contract](../tests/network-smoke.py) | —; kea-dhcp6 (missing) | N/M | P3 | Add a matched workload and timing. |
| [`dialog`](../loadables/dialog.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; dialog (missing) | N/M | P3 | Add a matched workload and timing. |
| [`diff`](../loadables/diff.c) | C D S T F | [Bench checked](#case-diff) | diff; diff | 57.149 / 50.077 / 37.012; [diff](#case-diff), 35 passes | P3 | Confirm diff (1.54× external time), then profile. |
| `dirname`* | P C D S T F | [Bench checked](#case-dirname) | dirname; dirname | 3.685 / 88.847 / 73.002; [dirname](#case-dirname), 127 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`dmesg`](../loadables/dmesg.c) | D S F | Build/help | dmesg; dmesg | N/M | P3 | Add behavioral fixtures, then timing. |
| [`dmsetup`](../loadables/dmsetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; dmsetup | N/M | P3 | Define required mapper mutation verbs and add isolated device fixtures. |
| [`dns`](../loadables/dns.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | nslookup; dig / drill | N/M | P3 | Add a matched workload and timing. |
| [`doas`](../loadables/doas.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; doas (missing) | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`du`](../loadables/du.c) | C D S T F | Build/help | du; du | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ed`](../loadables/ed.c) | C D S T F | Build/help | ed; ed (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`env`](../loadables/env.c) | C D S T F | [Contract](../tests/regressions.py) | env; env | N/M | P3 | Add a matched workload and timing. |
| [`escdelay`](../loadables/escdelay.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`expand`](../loadables/expand.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | expand; expand | 70.836 / 70.702 / 23.479; [expand](#case-expand), 10 passes | P2 | Profile expand: 3.02× external time. |
| [`expect`](../loadables/expect.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; expect (missing) | N/M | P3 | Add a matched workload and timing. |
| [`expr`](../loadables/expr.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | expr; expr | 4.029 / 105.943 / 83.767; [expr](#case-expr), 151 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`fail2ban`](../loadables/fail2ban.c) | S F | [Contract](../tests/network-smoke.py) | —; fail2ban-client (missing) | N/M | P3 | Add a matched workload and timing. |
| `fdflags`* | D S F | Build/help | —; Python fcntl | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fdisk`](../loadables/fdisk.c) | D S F | [Contract](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | fdisk; fdisk | N/M | P3 | Add a matched workload and timing. |
| [`fifo`](../loadables/fifo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`file`](../loadables/file.c) | T F | [Contract](../tests/misc-smoke.py) | —; file | N/M | P3 | Add a matched workload and timing. |
| [`fincore`](../loadables/fincore.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; fincore | N/M | P3 | Add behavioral fixtures, then timing. |
| [`find`](../loadables/find.c) | C D S T F | [Contract](../tests/regressions.py) | find; find | 20.666 / 66.131 / 66.175; [find](#case-find), 73 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `finfo`* | D S F | Build/help | stat; stat | N/M | P3 | Add behavioral fixtures, then timing. |
| [`flock`](../loadables/flock.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | —; flock | N/M | P3 | Add behavioral fixtures, then timing. |
| `fltexpr`* | D S F | Build/help | awk; awk / bc | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fold`](../loadables/fold.c) | C D S T F | [Bench checked](#case-fold) | fold; fold | 78.216 / 34.078 / 21.822; [fold](#case-fold), 9 passes | P2 | Profile fold: 3.58× external time. |
| [`free`](../loadables/free.c) | C D S T F | Build/help | free; free | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fsck`](../loadables/fsck.c) | D S F | [Contract](../tests/misc-smoke.py) | —; fsck | N/M | P3 | Add a matched workload and timing. |
| [`fsfreeze`](../loadables/fsfreeze.c) | D S F | Build/help | fsfreeze; fsfreeze | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fstrim`](../loadables/fstrim.c) | D S F | Build/help | fstrim; fstrim | N/M | P3 | Add behavioral fixtures, then timing. |
| [`fw`](../loadables/fw.c) | S F | [Contract](../tests/large-smoke.py) | —; nft / iptables | N/M | P3 | Add a matched workload and timing. |
| [`genl`](../loadables/genl.c) | D S F | Build/help | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| `getconf`* | D S F | Build/help | —; getconf | N/M | P3 | Add behavioral fixtures, then timing. |
| [`getfacl`](../loadables/getfacl.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; getfacl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`gpu`](../loadables/gpu.c) | T F | [Contract](../tests/gpu-smoke.py); [S](../tests/gpu-sanitize.sh) | —; API fixture | [Transport data](#graphics-metrics); no applet ratio | P3 | Measure application frame latency and driver behavior on the intended device. |
| [`grep`](../loadables/grep.c) | C D S T F | [Parity](../tests/grep-parity.sh); [limited](#scope-notes); [S](../tests/grep-host.c) | grep; grep | 45.472 / 363.332 / 43.813; [grep-lines](#case-grep-lines), 57 passes; 2 cases total | P3 | Decide required option scope; see limitations. |
| [`halt`](../loadables/halt.c) | D S F | Build/help | halt; halt | N/M | P3 | Add behavioral fixtures, then timing. |
| `head`* | P C D S T F | [Repeat-input bug](#repeated-input-findings) | head; head | INVALID / 53.222 / 43.886; [head](#case-head), 80 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| [`hexdump`](../loadables/hexdump.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | hexdump; hexdump | INVALID / 354.408 / 499.588; [hexdump](#case-hexdump), 45 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| [`hl`](../loadables/hl.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; highlight (missing) | N/M | P3 | Add a matched workload and timing. |
| [`hostid`](../loadables/hostid.c) | D S F | Build/help | hostid; hostid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`hostname`](../loadables/hostname.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | hostname; hostname | N/M | P3 | Add a matched workload and timing. |
| [`http`](../loadables/http.c) | D S F | [Contract](../tests/network-smoke.py) | wget; curl | N/M | P3 | Add a matched workload and timing. |
| [`httpd`](../loadables/httpd.c) | S F | [Contract](../tests/httpd-host.c); [S](../tests/run.sh) | httpd; HTTP server fixture | N/M | P3 | Add a matched workload and timing. |
| [`hwclock`](../loadables/hwclock.c) | D S F | Build/help | hwclock; hwclock | N/M | P3 | Add behavioral fixtures, then timing. |
| `id`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | id; id | N/M | P3 | Add a matched workload and timing. |
| [`index`](../loadables/index.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git update-index | N/M | P3 | Add a matched workload and timing. |
| [`integrity`](../loadables/integrity.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`ionice`](../loadables/ionice.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | ionice; ionice | N/M | P3 | Add a matched workload and timing. |
| [`ip`](../loadables/ip.c) | D S F | Build/help | ip; ip | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ipcctl`](../loadables/ipcctl.c) | D S F | Build/help | ipcs (not in build); ipcs / ipcrm | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ipcmk`](../loadables/ipcmk.c) | D S F | Build/help | —; ipcmk | N/M | P3 | Add behavioral fixtures, then timing. |
| [`join`](../loadables/join.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; join | 70.017 / — / 45.987; [join](#case-join), 20 passes | P3 | Confirm join (1.52× external time), then profile. |
| [`jq`](../loadables/jq.c) | S T F | [Parity](../tests/large-smoke.py); [S](../tests/large-sanitize.sh) | —; jq | 56.124 / — / 82.983; [jq](#case-jq), 10 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
| `logname`* | P C D S T F | Build/help | logname; logname | N/M | P3 | Add behavioral fixtures, then timing. |
| [`losetup`](../loadables/losetup.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | losetup; losetup | N/M | P3 | Add behavioral fixtures, then timing. |
| [`lpr`](../loadables/lpr.c) | F | [Smoke](../tests/misc-smoke.py); [limited](#scope-notes) | lpr (not in build); lpr (missing) | N/M | P3 | Decide whether real print delivery belongs in this loadable. |
| [`ls`](../loadables/ls.c) | C D S T F | [Bench checked](#case-ls) | ls; ls | 13.854 / 80.236 / 74.290; [ls](#case-ls), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
| [`mv`](../loadables/mv.c) | C D S T F | Build/help | mv; mv | N/M | P3 | Add behavioral fixtures, then timing. |
| [`nano`](../loadables/nano.c) | T F | [Contract](../tests/final-smoke.py); [limited](#scope-notes); [S](../tests/final-sanitize.sh) | —; nano | N/M | P3 | Decide required option scope; see limitations. |
| [`nano2`](../loadables/nano2.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; nano | N/M | P3 | Add a matched workload and timing. |
| [`nc`](../loadables/nc.c) | D S F | [Contract](../tests/network-smoke.py) | nc; nc | N/M | P3 | Add a matched workload and timing. |
| [`ncdu`](../loadables/ncdu.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; ncdu | N/M | P3 | Add a matched workload and timing. |
| [`netids`](../loadables/netids.c) | S F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; suricata (missing) | N/M | P3 | Add a matched workload and timing. |
| [`netstat`](../loadables/netstat.c) | D S F | Build/help | netstat; netstat (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`nice`](../loadables/nice.c) | C D S T F | [Contract](../tests/regressions.py) | —; nice | N/M | P3 | Add a matched workload and timing. |
| [`nl`](../loadables/nl.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | nl; nl | INVALID / 299.882 / 159.674; [nl](#case-nl), 76 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| [`nohup`](../loadables/nohup.c) | C D S T F | [Contract](../tests/regressions.py) | —; nohup | N/M | P3 | Add a matched workload and timing. |
| [`notify`](../loadables/notify.c) | T F | [Contract](../tests/misc-smoke.py) | —; systemd-notify | N/M | P3 | Add a matched workload and timing. |
| [`ns`](../loadables/ns.c) | S F | [Smoke](../tests/system-smoke.sh) | unshare; unshare / nsenter | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ntp`](../loadables/ntp.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | ntpd (not in build); chronyc / ntpd | N/M | P3 | Add a matched workload and timing. |
| [`obj`](../loadables/obj.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git hash-object / cat-file | N/M | P3 | Add a matched workload and timing. |
| [`od`](../loadables/od.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | od; od | INVALID / 216.360 / 510.202; [od](#case-od), 50 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| [`opt`](../loadables/opt.c) | T F | [Contract](../tests/misc-smoke.py) | getopt; getopt | N/M | P3 | Add a matched workload and timing. |
| [`pack`](../loadables/pack.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; git pack-objects / index-pack | N/M | P3 | Add a matched workload and timing. |
| [`passwd`](../loadables/passwd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | passwd; passwd | N/M | P3 | Add a matched workload and timing. |
| [`paste`](../loadables/paste.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | paste; paste | 79.457 / 410.517 / 81.696; [paste](#case-paste), 11 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
| [`pr`](../loadables/pr.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | —; pr | INVALID / — / 336.525; [pr](#case-pr), 80 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| `printenv`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | —; printenv | N/M | P3 | Add a matched workload and timing. |
| [`prlimit`](../loadables/prlimit.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | —; prlimit | N/M | P3 | Add behavioral fixtures, then timing. |
| [`procstat`](../loadables/procstat.c) | D S T F | [Contract](../tests/procstat-smoke.py); [S](../tests/procstat-sanitize.sh) | —; iostat / mpstat / sar / pidstat / pmap / pldd | N/M | P3 | Add a matched workload and timing. |
| [`ps`](../loadables/ps.c) | C D S T F | [Contract](../tests/rootfs-smoke.sh) | ps; ps | N/M | P3 | Add a matched workload and timing. |
| [`pty`](../loadables/pty.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; Python pty | N/M | P3 | Add a matched workload and timing. |
| [`readlink`](../loadables/readlink.c) | C D S T F | [Bench checked](#case-readlink) | readlink; readlink | 3.714 / 96.153 / 78.043; [readlink](#case-readlink), 134 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| `realpath`* | P C D S T F | [Bench checked](#case-realpath) | realpath; realpath | 4.632 / 98.171 / 81.636; [realpath](#case-realpath), 146 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`reboot`](../loadables/reboot.c) | D S F | Build/help | reboot; reboot | N/M | P3 | Add behavioral fixtures, then timing. |
| [`renice`](../loadables/renice.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | renice; renice | N/M | P3 | Add behavioral fixtures, then timing. |
| [`rev`](../loadables/rev.c) | C D S T F | [Bench checked](#case-rev) | rev; rev | 65.750 / 40.979 / 124.755; [rev](#case-rev), 16 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
| [`sed`](../loadables/sed.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | sed; sed | INVALID / 121.217 / 80.760; [sed](#case-sed), 14 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| [`seq`](../loadables/seq.c) | P C D S T F | [Parity](../tests/seq-parity.sh) | seq; seq | 55.641 / 1445.151 / 60.492; [seq](#case-seq), 44 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`setfacl`](../loadables/setfacl.c) | D S F | Build/help | —; setfacl (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| `setpgid`* | D S F | Build/help | —; Python os.setpgid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`setsid`](../loadables/setsid.c) | C D S T F | [Smoke](../tests/util-linux-smoke.sh) | setsid; setsid | N/M | P3 | Add behavioral fixtures, then timing. |
| [`sftp`](../loadables/sftp.c) | S F | [Contract](../tests/network-smoke.py) | —; sftp | N/M | P3 | Add a matched workload and timing. |
| [`signal`](../loadables/signal.c) | D S F | [Contract](../tests/system-smoke.sh) | kill; kill -l / Bash kill | N/M | P3 | Add a matched workload and timing. |
| [`sixel`](../loadables/sixel.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh); [Fz](../tests/fuzz-image.c) | —; img2sixel (missing) | N/M | P3 | Add a matched workload and timing. |
| [`slabtop`](../loadables/slabtop.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; slabtop | N/M | P3 | Add a matched workload and timing. |
| `sleep`* | P C D S T F | Build/help | sleep; sleep | N/M | P3 | Add behavioral fixtures, then timing. |
| [`sort`](../loadables/sort.c) | C D S T F | [Parity](../tests/sort-parity.sh) | sort; sort | 64.855 / 67.779 / 30.723; [sort-text](#case-sort-text), 11 passes; 2 cases total | P2 | Profile sort-text: 2.11× external time. |
| [`split`](../loadables/split.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | —; split | N/M | P3 | Add a matched workload and timing. |
| [`sqlite`](../loadables/sqlite.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; sqlite3 / Python sqlite3 | N/M | P3 | Add a matched workload and timing. |
| [`ss`](../loadables/ss.c) | D S F | Build/help | —; ss | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ssh`](../loadables/ssh.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; ssh | N/M | P3 | Add a matched workload and timing. |
| [`sshd`](../loadables/sshd.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sshd | N/M | P3 | Add a matched workload and timing. |
| [`stat`](../loadables/stat.c) | P C D S T F | [Parity](../tests/stat-parity.sh) | stat; stat | 3.892 / 102.510 / 109.852; [stat](#case-stat), 151 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`strace`](../loadables/strace.c) | F | [Contract](../tests/large-smoke.py) | —; strace (missing) | N/M | P3 | Add a matched workload and timing. |
| `strftime`* | P C D S T F | Build/help | date; date / Bash printf | N/M | P3 | Add behavioral fixtures, then timing. |
| [`strings`](../loadables/strings.c) | C D S T F | [Repeat-input bug](#repeated-input-findings) | strings; strings | INVALID / 72.499 / 115.510; [strings](#case-strings), 80 passes | P1 | Fix repeated redirected input, add a persistent-shell regression, then remeasure. |
| `strptime`* | P C D S T F | Build/help | —; Python datetime.strptime | N/M | P3 | Add behavioral fixtures, then timing. |
| [`su`](../loadables/su.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | su; su | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sudo`](../loadables/sudo.c) | S F | [Negative checks](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; sudo | N/M | P3 | Add credential-transition and policy fixtures before benchmarking authentication. |
| [`sv`](../loadables/sv.c) | S F | [Contract](../tests/large-smoke.py) | —; runit sv | N/M | P3 | Add a matched workload and timing. |
| [`swapoff`](../loadables/swapoff.c) | D S F | Build/help | swapoff; swapoff | N/M | P3 | Add behavioral fixtures, then timing. |
| [`swapon`](../loadables/swapon.c) | D S F | [Smoke](../tests/util-linux-smoke.sh) | swapon; swapon | N/M | P3 | Add behavioral fixtures, then timing. |
| `sync`* | P C D S T F | Build/help | sync; sync | N/M | P3 | Add behavioral fixtures, then timing. |
| [`sysctl`](../loadables/sysctl.c) | D S F | [Contract](../tests/system-smoke.sh) | sysctl; sysctl | N/M | P3 | Add a matched workload and timing. |
| [`tac`](../loadables/tac.c) | C D S T F | [Parity](../tests/tac-parity.py); [limited](#scope-notes); [S](../tests/tac-sanitize.sh) | tac; tac | 76.984 / 105.132 / 25.179; [tac](#case-tac), 26 passes | P3 | Decide bounded-memory input and GNU regex scope; see the tac follow-up. |
| [`tail`](../loadables/tail.c) | C D S T F | [Parity](../tests/wc-tail-parity.sh) | tail; tail | 4.680 / 132.095 / 44.944; [tail](#case-tail), 80 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`taskset`](../loadables/taskset.c) | D S F | [Query parity](../tests/util-linux-smoke.sh) | taskset; taskset | N/M | P3 | Add a matched workload and timing. |
| `tee`* | P C D S T F | Build/help | tee; tee | N/M | P3 | Add behavioral fixtures, then timing. |
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
| [`tr`](../loadables/tr.c) | C D S T F | [Bench checked](#case-tr) | tr; tr | 33.531 / 68.989 / 39.920; [tr](#case-tr), 50 passes | P4 | Extend sizes/options; no selected-case performance priority. |
| [`truncate`](../loadables/truncate.c) | C D S T F | Build/help | truncate; truncate | N/M | P3 | Add behavioral fixtures, then timing. |
| [`ts`](../loadables/ts.c) | T F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; tree-sitter (missing) | N/M | P3 | Add a matched workload and timing. |
| `tty`* | P C D S T F | Build/help | tty; tty | N/M | P3 | Add behavioral fixtures, then timing. |
| [`tui`](../loadables/tui.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`tz`](../loadables/tz.c) | T F | [Contract](../tests/misc-smoke.py) | date; date / Python zoneinfo | N/M | P3 | Add a matched workload and timing. |
| [`uclampset`](../loadables/uclampset.c) | D S F | [Smoke](../tests/util-linux-smoke.sh); [limited](#scope-notes) | —; uclampset | N/M | P3 | Decide whether to implement the missing setter surface. |
| `uname`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | uname; uname | N/M | P3 | Add a matched workload and timing. |
| [`undo`](../loadables/undo.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`unexpand`](../loadables/unexpand.c) | C D S T F | [Parity](../tests/text-tools-parity.sh) | unexpand; unexpand | 79.942 / 112.802 / 40.227; [unexpand](#case-unexpand), 10 passes | P3 | Confirm unexpand (1.99× external time), then profile. |
| [`uniq`](../loadables/uniq.c) | C D S T F | [Parity](../tests/paste-uniq-parity.py); [S](../tests/paste-uniq-sanitize.sh) | uniq; uniq | 66.282 / 436.165 / 89.471; [uniq](#case-uniq), 20 passes | P4 | Extend sizes/options; no selected-case performance priority. |
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
| [`wc`](../loadables/wc.c) | C D S T F | [Parity](../tests/wc-tail-parity.sh) | wc; wc | 54.422 / 143.988 / 34.417; [wc-characters](#case-wc-characters), 44 passes; 3 cases total | P3 | Confirm wc-characters (1.58× external time), then profile. |
| [`wg`](../loadables/wg.c) | S F | [Contract](../tests/final-smoke.py); [S](../tests/final-sanitize.sh) | —; wg (missing) | N/M | P3 | Add a matched workload and timing. |
| [`wget_wch`](../loadables/wget_wch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`wgetch`](../loadables/wgetch.c) | T F | [Contract](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; API fixture | N/M | P3 | Define an API workload and metric, then measure. |
| [`whatis`](../loadables/whatis.c) | T F | [Contract](../tests/misc-smoke.py) | —; whatis | N/M | P3 | Add a matched workload and timing. |
| [`whiptail`](../loadables/whiptail.c) | T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | —; whiptail | N/M | P3 | Add a matched workload and timing. |
| [`who`](../loadables/who.c) | D S T F | [Smoke](../tests/system-smoke.sh) | who; who | N/M | P3 | Add behavioral fixtures, then timing. |
| `whoami`* | P C D S T F | [Contract](../tests/rootfs-smoke.sh) | whoami; whoami | N/M | P3 | Add a matched workload and timing. |
| [`wipefs`](../loadables/wipefs.c) | D S F | Build/help | —; wipefs | N/M | P3 | Add behavioral fixtures, then timing. |
| [`write`](../loadables/write.c) | T F | [Negative checks](../tests/terminal-smoke.py); [S](../tests/terminal-sanitize.sh) | —; write (missing) | N/M | P3 | Add behavioral fixtures, then timing. |
| [`xargs`](../loadables/xargs.c) | C D S T F | [Contract](../tests/regressions.py) | xargs; xargs | N/M | P3 | Add a matched workload and timing. |
| [`xattr`](../loadables/xattr.c) | S F | [Contract](../tests/system-smoke.sh) | —; getfattr / setfattr | N/M | P3 | Add a matched workload and timing. |
| [`zcat`](../loadables/zcat.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | zcat; zcat | N/M | P3 | Add a matched workload and timing. |
| [`zlib`](../loadables/zlib.c) | S T F | [Contract](../tests/helper-smoke.py); [S](../tests/helper-sanitize.sh) | gzip; gzip / xz / zstd / bzip2 | N/M | P3 | Add a matched workload and timing. |
| [`zstd`](../loadables/zstd.c) | S T F | [Parity](../tests/zstd-check.sh); [S](../tests/zstd-host.c) | —; zstd | N/M | P3 | Add a matched workload and timing. |
| [`zstdcat`](../loadables/zstdcat.c) | S T F | [Parity](../tests/zstd-check.sh) | —; zstdcat | N/M | P3 | Add a matched workload and timing. |
<!-- END CATALOG -->

## Repeated-input findings

Ten commands return success while repeated calls with freshly redirected stdin
produce different output from fresh external commands. This matters in a shell
where builtins remain in one process. The following three-call pattern confirms
the issue even with newline-terminated text; `sed` also adds a newline to the
unterminated last line of the larger benchmark fixture.

```bash
bench_input=$(mktemp)
printf 'a\nb\nc\n' > "$bench_input"
out/bash --noprofile --norc -c '
  for ((i=0; i<3; i++)); do head -n 1 < "$1"; done
' _ "$bench_input"
# Actual: a, b, c on separate lines. Expected: a, a, a.

out/bash --noprofile --norc -c '
  for ((i=0; i<3; i++)); do /usr/bin/head -n 1 < "$1"; done
' _ "$bench_input"
# External reference: a, a, a.
rm -- "$bench_input"
```

For a fixture managed and cleaned up automatically, use:

```bash
python3 bench/loadables.py --quick --only head,sed,bc --output /tmp/loadable-check.json
```

`--quick` still validates at least three invocations in the same shell. It
reduces timed samples, not this correctness check. The harness records failures
in JSON and continues collecting other cases; exit zero means the report was
written, not that every command passed.

| Command | Three-call input | Observed behavior versus external reference |
| --- | --- | --- |
| `head -n 1` | `a\nb\nc\n` | Emits `a`, then `b`, then `c`; reference emits `a` three times. |
| `sed s/a/A/g` | `a\nb\nc\n` | Emits the transformed input once; reference emits it three times. |
| `nl -ba` | `a\nb\nc\n` | Emits numbered input once; reference emits it three times. |
| `pr -t` | `a\nb\nc\n` | Emits input once; reference emits it three times. |
| `colrm 4` | `alpha\nbeta\n` | Emits shortened lines once; reference emits them three times. |
| `column -t` | `alpha\tbeta\none\ttwo\n` | Emits aligned lines once; reference emits them three times. |
| `strings -n 4` | `hello\0world\0` | Emits the strings once; reference emits them three times. |
| `od -An -tx1` | `abc\n` | Emits the byte values once; reference emits them three times. |
| `hexdump -C` | `abc\n` | Later calls print zero end offsets instead of the input dump. |
| `bc` | `1+1\n` | Emits one `2`; reference emits three. |

These are confirmed behaviors. Stdio buffer/EOF lifetime is a candidate cause,
but a shared root cause has not been established for all ten. A fix should test
repeated file redirections, pipes, empty input, partial reads and subsequent
shell input, rather than just the first invocation of each builtin.

## Scope notes

These are specific reviewed limits or gaps, not an exhaustive option audit.
Source comments alone were not treated as proof of an unimplemented feature.

<!-- BEGIN NOTES -->
| Loadable | Scope / limitation |
| --- | --- |
| `bc` | User-defined functions and output bases are explicitly incomplete in addition to the repeat-input failure. [source](../loadables/bc.c) |
| `cluster` | Only a version smoke check is mapped here. |
| `dmsetup` | Some mutation verbs still return an explicit unimplemented-backend error. [source](../loadables/dmsetup.c) |
| `doas` | Current integration test rejects an invalid option before credential transition. |
| `gpu` | CPU/protocol, native driver and isolated Kilix checks exist. Static builds support CPU presentation; native shaders require dynamic linking. |
| `grep` | Default build disables -P; the separate pcre loadable supplies PCRE2 operations. See the source build switch. [source](../loadables/grep.c) |
| `ldap` | BER/filter fixtures and bounded fuzzing pass; live server/authentication throughput is unmeasured. |
| `lpr` | Submit copies into a spool and sleeps to simulate printing. No real printer throughput claim. [source](../loadables/lpr.c) |
| `mail` | Alias compilation/expansion fixtures exist; no SMTP delivery throughput measurement. |
| `nano` | Editor selftests pass; justify, spell and completion still report unimplemented. [source](../loadables/nano.c) |
| `payload` | Install/remove invoke a helper outside this repository; the current fixture only calls help. [source](../loadables/payload.c) |
| `pgrep` | Matching is substring-based unless exact matching is selected; not full procps regular-expression behavior. [source](../loadables/pgrep.c) |
| `pkill` | Shares pgrep matching and process traversal; validate signals only against owned child fixtures. [source](../loadables/pkill.c) |
| `rtspcat` | No command-specific fixture is mapped in the current repository suite. |
| `scp` | Companion frontend to sftp; local-copy and failure fixtures do not establish full remote scp compatibility. |
| `screen` | Metadata/control fixtures pass; the live relay path needs separate sustained traffic measurements. |
| `sed` | Also adds a newline to an unterminated last input line, unlike the GNU reference. |
| `sftp` | Local operation and failure fixtures exist; remote transfer behavior needs dedicated interop and throughput coverage. |
| `ssh` | Host-key fixtures and loopback SSH interoperability pass; no transfer throughput measurements. |
| `sshd` | Loopback interoperability and malformed setup cases pass; no concurrent-session measurements. |
| `su` | Current integration test rejects an invalid option before credential transition. |
| `sudo` | Current integration test rejects an invalid option before credential transition. |
| `tac` | Follow-up input fixes and performance work completed; the main table retains historical timings. New comparisons and tests are in docs/tac.md. Whole-file memory use and the POSIX ERE regex subset remain limits. [source](../docs/tac.md) |
| `uclampset` | Query subset; setting PID/system clamps and command mode are refused. [source](../loadables/uclampset.c) |
<!-- END NOTES -->

## Individual benchmark cases

<!-- BEGIN CASES -->
| Case | Builtin command | External command | Input | Passes | BOS ms | BB ms | External ms | BOS / external | Samples |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| <a id="case-cat"></a>cat | `cat` | `cat` | text (423,000 stdin bytes) | 80 | 7.802 | 53.267 | 66.240 | 0.12× | 5 |
| <a id="case-head"></a>head | `head -n 100` | `head -n 100` | text (423,000 stdin bytes) | 80 | INVALID | 53.222 | 43.886 | — | 5 |
| <a id="case-tail"></a>tail | `tail -n 100` | `tail -n 100` | text (423,000 stdin bytes) | 80 | 4.680 | 132.095 | 44.944 | 0.10× | 5 |
| <a id="case-wc-counts"></a>wc-counts | `wc -lwc` | `wc -lwc` | text (423,000 stdin bytes) | 28 | 37.246 | 90.065 | 45.916 | 0.81× | 7 |
| <a id="case-wc-characters"></a>wc-characters | `wc -m` | `wc -m` | text (423,000 stdin bytes) | 44 | 54.422 | 143.988 | 34.417 | 1.58× | 5 |
| <a id="case-wc-width"></a>wc-width | `wc -L` | `wc -L` | text (423,000 stdin bytes) | 43 | 57.370 | 120.449 | 77.574 | 0.74× | 5 |
| <a id="case-cut"></a>cut | `cut -d ' ' -f 1` | `cut -d ' ' -f 1` | text (423,000 stdin bytes) | 61 | 21.804 | 257.249 | 123.297 | 0.18× | 5 |
| <a id="case-grep-count"></a>grep-count | `grep -c alpha` | `grep -c alpha` | text (423,000 stdin bytes) | 72 | 43.360 | 434.483 | 59.217 | 0.73× | 5 |
| <a id="case-grep-lines"></a>grep-lines | `grep alpha` | `grep alpha` | text (423,000 stdin bytes) | 57 | 45.472 | 363.332 | 43.813 | 1.04× | 5 |
| <a id="case-sed"></a>sed | `sed s/alpha/OMEGA/g` | `sed s/alpha/OMEGA/g` | text (423,000 stdin bytes) | 14 | INVALID | 121.217 | 80.760 | — | 5 |
| <a id="case-sort-numeric"></a>sort-numeric | `sort -n` | `sort -n` | numbers (369,296 stdin bytes) | 6 | 73.136 | 549.335 | 146.969 | 0.50× | 5 |
| <a id="case-sort-text"></a>sort-text | `sort` | `sort` | text (423,000 stdin bytes) | 11 | 64.855 | 67.779 | 30.723 | 2.11× | 7 |
| <a id="case-seq"></a>seq | `seq 100000` | `seq 100000` | No stdin; named fixtures / arguments | 44 | 55.641 | 1445.151 | 60.492 | 0.92× | 5 |
| <a id="case-tr"></a>tr | `tr a-z A-Z` | `tr a-z A-Z` | text (423,000 stdin bytes) | 50 | 33.531 | 68.989 | 39.920 | 0.84× | 5 |
| <a id="case-uniq"></a>uniq | `uniq` | `uniq` | duplicates (1,680,000 stdin bytes) | 20 | 66.282 | 436.165 | 89.471 | 0.74× | 5 |
| <a id="case-paste"></a>paste | `paste duplicates duplicates` | `paste duplicates duplicates` | No stdin; named fixtures / arguments | 11 | 79.457 | 410.517 | 81.696 | 0.97× | 5 |
| <a id="case-nl"></a>nl | `nl -ba` | `nl -ba` | text (423,000 stdin bytes) | 76 | INVALID | 299.882 | 159.674 | — | 5 |
| <a id="case-rev"></a>rev | `rev` | `rev` | text (423,000 stdin bytes) | 16 | 65.750 | 40.979 | 124.755 | 0.53× | 5 |
| <a id="case-fold"></a>fold | `fold -w 40` | `fold -w 40` | text (423,000 stdin bytes) | 9 | 78.216 | 34.078 | 21.822 | 3.58× | 7 |
| <a id="case-tac"></a>tac | `tac` | `tac` | text (423,000 stdin bytes) | 26 | 76.984 | 105.132 | 25.179 | 3.06× | 7 |
| <a id="case-comm"></a>comm | `comm left right` | `comm left right` | No stdin; named fixtures / arguments | 18 | 68.930 | — | 25.360 | 2.72× | 7 |
| <a id="case-join"></a>join | `join left right` | `join left right` | No stdin; named fixtures / arguments | 20 | 70.017 | — | 45.987 | 1.52× | 5 |
| <a id="case-expand"></a>expand | `expand -t 8` | `expand -t 8` | tabs (340,000 stdin bytes) | 10 | 70.836 | 70.702 | 23.479 | 3.02× | 7 |
| <a id="case-unexpand"></a>unexpand | `unexpand -a` | `unexpand -a` | spaces (440,000 stdin bytes) | 10 | 79.942 | 112.802 | 40.227 | 1.99× | 5 |
| <a id="case-pr"></a>pr | `pr -t` | `pr -t` | text (423,000 stdin bytes) | 80 | INVALID | — | 336.525 | — | 5 |
| <a id="case-colrm"></a>colrm | `colrm 4` | `colrm 4` | text (423,000 stdin bytes) | 71 | INVALID | — | 358.006 | — | 5 |
| <a id="case-column"></a>column | `column -t` | `column -t` | tabs (340,000 stdin bytes) | 28 | INVALID | — | 1219.587 | — | 5 |
| <a id="case-strings"></a>strings | `strings -n 4` | `strings -n 4` | bytes (65,536 stdin bytes) | 80 | INVALID | 72.499 | 115.510 | — | 5 |
| <a id="case-od"></a>od | `od -An -tx1` | `od -An -tx1` | bytes (65,536 stdin bytes) | 50 | INVALID | 216.360 | 510.202 | — | 5 |
| <a id="case-hexdump"></a>hexdump | `hexdump -C` | `hexdump -C` | bytes (65,536 stdin bytes) | 45 | INVALID | 354.408 | 499.588 | — | 5 |
| <a id="case-basename"></a>basename | `basename /fixture/path/file.txt` | `basename /fixture/path/file.txt` | No stdin; named fixtures / arguments | 128 | 3.469 | 90.219 | 68.394 | 0.05× | 5 |
| <a id="case-dirname"></a>dirname | `dirname /fixture/path/file.txt` | `dirname /fixture/path/file.txt` | No stdin; named fixtures / arguments | 127 | 3.685 | 88.847 | 73.002 | 0.05× | 5 |
| <a id="case-readlink"></a>readlink | `readlink link` | `readlink link` | No stdin; named fixtures / arguments | 134 | 3.714 | 96.153 | 78.043 | 0.05× | 5 |
| <a id="case-realpath"></a>realpath | `realpath link` | `realpath link` | No stdin; named fixtures / arguments | 146 | 4.632 | 98.171 | 81.636 | 0.06× | 5 |
| <a id="case-stat"></a>stat | `stat -c %s text` | `stat -c %s text` | No stdin; named fixtures / arguments | 151 | 3.892 | 102.510 | 109.852 | 0.04× | 5 |
| <a id="case-ls"></a>ls | `ls -1 tree` | `ls -1 tree` | No stdin; named fixtures / arguments | 80 | 13.854 | 80.236 | 74.290 | 0.19× | 5 |
| <a id="case-find"></a>find | `find tree -type f` | `find tree -type f` | No stdin; named fixtures / arguments | 73 | 20.666 | 66.131 | 66.175 | 0.31× | 5 |
| <a id="case-cmp"></a>cmp | `cmp text copy` | `cmp text copy` | No stdin; named fixtures / arguments | 65 | 34.946 | 197.742 | 43.839 | 0.80× | 5 |
| <a id="case-diff"></a>diff | `diff text copy` | `diff text copy` | No stdin; named fixtures / arguments | 35 | 57.149 | 50.077 | 37.012 | 1.54× | 5 |
| <a id="case-dd"></a>dd | `dd if=text bs=64K status=none` | `dd if=text bs=64K status=none` | No stdin; named fixtures / arguments | 80 | 5.771 | 59.411 | 49.247 | 0.12× | 5 |
| <a id="case-cp"></a>cp | `cp text copied` | `cp text copied` | No stdin; named fixtures / arguments | 80 | 13.826 | 64.407 | 76.063 | 0.18× | 5 |
| <a id="case-cksum"></a>cksum | `cksum` | `cksum` | text (423,000 stdin bytes) | 49 | 52.015 | — | 75.268 | 0.69× | 5 |
| <a id="case-bashbase64"></a>bashbase64 | `bashbase64 -w 0` | `base64 -w 0` | bytes (65,536 stdin bytes) | 80 | 7.893 | 62.127 | 60.144 | 0.13× | 5 |
| <a id="case-bashjson"></a>bashjson | `bashjson get .answer` | `jq .answer` | object (39,133 stdin bytes) | 75 | 32.663 | — | 263.797 | 0.12× | 5 |
| <a id="case-awk"></a>awk | `awk '{sum += $2} END {print sum}'` | `awk '{sum += $2} END {print sum}'` | records (162,830 stdin bytes) | 14 | 65.226 | 146.354 | 73.818 | 0.88× | 5 |
| <a id="case-jq"></a>jq | `jq -c '[.[] &#124; select(. > 50)]'` | `jq -c '[.[] &#124; select(. > 50)]'` | array (39,109 stdin bytes) | 10 | 56.124 | — | 82.983 | 0.68× | 5 |
| <a id="case-bc"></a>bc | `bc` | `bc` | arithmetic (18 stdin bytes) | 80 | INVALID | 59.262 | 66.245 | — | 5 |
| <a id="case-expr"></a>expr | `expr 123 '*' 456` | `expr 123 '*' 456` | No stdin; named fixtures / arguments | 151 | 4.029 | 105.943 | 83.767 | 0.05× | 5 |
| <a id="case-crypto"></a>crypto | `crypto sha256 -x` | `sha256sum` | blob (1,048,576 stdin bytes) | 13 | 73.100 | 86.568 | 55.292 | 1.32× | 5 |
<!-- END CASES -->

## Method and limits

The command measurements use the native dynamic full `out/bash` at the code
snapshot above, SHA-256
`ade3e597987655c3831ab00870bae58c49c4137e993b636d6c5776625380c650`.
Host: Intel Core i7-9850H, x86-64 Linux 6.12.96, pinned to CPU 11. References
include GNU coreutils 9.7, grep 3.11 and Debian BusyBox 1.37.0. These are host
measurements; there are no per-command RISC-V or appliance timings here.

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

Five untraced samples follow validation and warm-up. Implementation order rotates
and reverses across samples; output goes to `/dev/null`. Pass counts calibrate
toward a roughly 75 ms batch, subject to a cap, and are identical across variants
within a case. `fold`, `expand`, `tac`, `comm`, `sort-text` and normalized
`wc-counts` were remeasured with seven samples and the original fixed pass count;
the tables use that confirmation run, not a mixture of the two runs.

The host was doing other work: load averages were approximately 4.7 at the start
and 3.6 at the end of the initial run. Medians and the ranges in the JSON support
prioritization, not small-percentage performance claims. Repeat on the intended
device and across input sizes before making a release claim.

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
and 30 updates. Five runs per mode were taken on the same native binary; these
runs were not pinned to a CPU. Byte counts exclude the initial presentation.
They can vary slightly with protocol identifiers; the JSON records their ranges.

<!-- BEGIN GPU -->
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
python3 bench/loadables.py --binary out/bash --runs 5 --output /tmp/loadables.json
python3 bench/loadables.py --only fold --passes 9 --runs 7 --output /tmp/fold.json
python3 bench/catalog.py
python3 bench/catalog.py --check
```

Choose an allowed CPU with `--cpu N` when comparing new results. Keep raw run
logs outside Git. Review changed coverage in [loadables-review.json](loadables-review.json)
and copy only sanitized summary fields into
[data/loadable-benchmarks.json](data/loadable-benchmarks.json). Record the actual
binary hash, source commit, fixture hashes, reference versions, case arguments,
pass counts, sample counts, validation status and timing ranges. Never copy a
failed validation's timing into a passing result. Update this date and method
when changing the measurement, then regenerate the Markdown and CSV together.

The generator checks exact catalog membership, source coverage, profiles,
evidence paths and measurement consistency. It does not run the benchmark or
prove that a reviewed fixture covers all paths. Adding a new loadable requires
refreshing the reviewed catalog hash; the check deliberately fails until that
snapshot is reviewed.
