# hwclock software-path qualification

`loadables/hwclock.c` implements show, hctosys, systohc and drift adjustment
through Linux RTC ioctls. This qualification uses a closed fixture around the
actual source, private adjfiles and independent Python datetime/zoneinfo
oracles. It never changes the host RTC or system clock. Physical RTC
qualification remains necessary.

`--show` retains its raw calendar format, `YYYY-MM-DDTHH:MM:SS`, without a zone
suffix. UTC/localtime select the interpretation used by setters and adjustment;
they do not convert this raw display. The supported calendar is 1900–9999,
with valid Gregorian dates and seconds 0–59. Local conversion rejects times in
DST gaps. An ambiguous repeated hour follows libc `mktime`'s choice; either
matching epoch is valid, and both epochs convert back to the same wall time.

Adjtime parsing requires three complete, bounded lines: finite drift and
remainder numbers with a representable integer adjustment timestamp, an integer
calibration timestamp, then `UTC` or `LOCAL`. Trailing whitespace is accepted;
trailing fields, overflow, NUL bytes, overlong lines and nonfinite numbers fail
before device access. A missing file supplies zero drift and UTC. Adjustment
requires a nonzero previous adjustment time. Whole seconds are truncated toward
zero and the fractional remainder is retained. Corrections outside `time_t`
range fail before a setter.

A successful systohc resets adjustment/calibration timestamps to the sampled
system time, clears the remainder and records the selected mode. `--noadjfile`
bypasses this update. Writers replace an adjfile only after successful write
and close, preserve an existing file's owner and permission bits, and follow an
existing symlink without replacing the link. New files have mode 0600. Failed
writes, closes or renames remove their temporary files and preserve the old
calibration. An RTC setter and a filesystem rename cannot form one atomic
transaction: a later adjfile failure is reported after the RTC request has
succeeded. There is no rollback, concurrent-writer lock or crash-durability
claim. Extended attributes and ACLs are not copied by replacement.

`tests/sol-hwclock-shim.c` compiles the production source with intercepted RTC
open/close/ioctl and clock get/set calls. Synthetic RTC descriptors cannot
reach a kernel ioctl. The same source is compiled into a non-PIE ASan/UBSan
host runner, including float-cast overflow checks. Only private calibration
files use normal filesystem operations. The normal shell tests load the fixture
with `enable -f`, run with empty PATH, and check operation order, flags, setter
arguments, every status, repeated calls and real descriptor counts.

Focused coverage includes:

- Show and both conversion directions against Gregorian timestamp oracles,
  including 1900/2000/2100/2400 leap rules, UTC/local epoch −1, 2038 and year 9999.
- UTC/local mode defaults and overrides, DST transitions, rejected gaps,
  repeated hours, non-hour offsets, a half-hour DST gap, and local adjustment across a DST jump.
- Malformed adjtime, positive/negative/fractional/zero/overflow drift,
  symlink and new-file updates, and denied temporary-file creation.
- Missing RTC, read/write/open/close and system getter/setter failures;
  adjfile fdopen/write/close/rename failures; repeated failure cleanup.
- Output failure on `/dev/full`, recovery, invalid options and persistent
  option/mode state across calls in one shell.
- Safe util-linux `--predict` comparisons of whole-second calendar formatting
  and valid UTC/LOCAL adjtime parsing. No util-linux setter runs. Its zoned
  microsecond display is normalized only for these calendar comparisons;
  this does not establish general output or option parity.

Build selection is `--include hwclock`; no companion loadable or common-helper
change is required. The build system also stages its default `_jsmn` helper.
The family smoke test's existing hwclock assertions are help/presence checks;
they remain intact. Register the task-owned behavioral driver separately.

With the campaign gate path in `$GATE` and evidence directory in
`$BASHOS_TASK_DIR`, reproduction is:

```sh
python3 "$GATE" build -- bash tests/sol-hwclock-build.sh
python3 tests/sol-hwclock-check.py --binary out/bash-sol-hwclock \
  --module "$BASHOS_TASK_DIR/artifacts/hwclock.so" \
  --report "$BASHOS_TASK_DIR/correctness.json"
python3 tests/sol-hwclock-check.py --binary out/bash-sol-hwclock \
  --module "$BASHOS_TASK_DIR/artifacts/hwclock.so" \
  --host "$BASHOS_TASK_DIR/artifacts/hwclock-sanitize" \
  --report "$BASHOS_TASK_DIR/sanitizer.json"
python3 "$GATE" bench -- python3 bench/sol-hwclock.py \
  --binary out/bash-sol-hwclock --module "$BASHOS_TASK_DIR/artifacts/hwclock.so" \
  --output "$BASHOS_TASK_DIR/timing.json"
```

The benchmark fixes RTC calendars, system timestamps and adjfile bytes. It
performs a warm-up plus at least seven samples on one recorded CPU. Every call
checks status and cumulative syscall counts; setters also check independently
computed calendar/epoch fields. Show output is validated in full on every
sample. Mutating file cases rewrite the identical input before every call and
check every calibration before the next reset. Timings include shell startup/loops, shim checks,
and private filesystem work. Reports record distributions, input and source
hashes, binary/module hashes, versions, affinity and validation details. These
are syscall-shim measurements, with no external ratio or hardware-latency
claim. No historical measured hwclock workload existed to reproduce or optimize.

Physical qualification must cover the intended RTC driver/device, permissions,
update-edge and subsecond synchronization, observed clock accuracy, and recovery
when a real setter succeeds but metadata persistence fails. Kernel timezone and
NTP/eleven-minute-mode coordination, util-linux's wider option set, drift-factor
recalibration, and 32-bit `time_t` builds are outside this fixture scope.

Validation on 2026-10-20 UTC passed 172 behavioral cases and 169 sanitizer
cases. The three additional native cases exercise shell output recovery, real
FD counts, and the util-linux reference. All eight focused regressions fail
against the original source, which is identical at both assigned baselines.
Earlier failed build/test logs remain with the task evidence.

The measured shell is Bash 5.3.15, GCC 14.2.0, glibc 2.41, on Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz,
with affinity fixed to CPU 11. Each cell below summarizes seven timed samples
after one validated warm-up; every case passed all repeated-call checks.

| Transaction | Calls/sample | Median ms | Min–max ms |
|---|---:|---:|---:|
| read-show | 2000 | 27.423 | 23.491–40.748 |
| hctosys-utc | 2000 | 16.605 | 15.701–17.072 |
| hctosys-local | 2000 | 17.379 | 17.027–18.235 |
| hctosys-adjtime | 2000 | 103.788 | 96.796–114.870 |
| systohc-utc | 2000 | 23.086 | 20.879–24.985 |
| systohc-local | 2000 | 22.661 | 21.311–25.299 |
| systohc-adjtime | 200 | 41.472 | 39.265–47.486 |
| adjust-noop | 2000 | 107.153 | 95.877–123.742 |
| adjust-write | 200 | 40.426 | 39.834–42.094 |

Raw distributions and validation records are in `timing.json` in the task
evidence directory; correctness reports are `correctness-final.json` and
`sanitizer-final.json`. Source and binary hashes in that report identify the
measured inputs; it records the working tree before the delivery commit.
The measured native shell SHA-256 is
`2a1163fdd9b0411699fa09af7d3771c4b8d17ee01082955c21d93ee48d7ccce7`.
These timings include per-call validation and private file resets where
applicable; they do not estimate physical RTC latency or clock-setting accuracy.
