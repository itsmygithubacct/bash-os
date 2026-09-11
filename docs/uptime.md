# uptime

`uptime` prints how long the system has been running. Default output includes
the wall clock, a user count and load averages, so a repeated batch is not
stable. `uptime -s` prints the boot time as `YYYY-MM-DD HH:MM:SS` from
`/proc/stat` `btime`, the same integer GNU `uptime -s` uses.

`BASHOS_PROC_ROOT` redirects `uptime`, `stat` and `loadavg`.
`tests/uptime-check.sh` drives the shipped builtin with an empty `PATH` and a
disposable fixture: `-s` matches the fixture btime and is not the live host
boot time; `-p` pretty-prints a known duration; missing `proc/uptime` fails.

```sh
./build.sh --include uptime --name uptime
out/bash-uptime -c 'PATH=; uptime -s'
```

## Measurements, 2026-09-11

This is a follow-up to the [catalog snapshot](loadables-status.md), not a
replacement of it. The binary is the catalog full build: SHA-256
`9b2c69c9b8dc1c8cb437904afeacc51919fc4db31fc676d0c41137a2c8caad73`, Bash
5.3.15, pinned to CPU 10. Host: Intel Core i7-9850H, Linux 6.12.96, x86-64.
procps-ng 4.0.4. Raw JSON stays outside Git.

Seven samples followed whole-batch exact-output validation. Builtin and GNU
ran from the same bash-os shell with startup files disabled, `LC_ALL=C`,
`TZ=UTC` and an empty `PATH`. GNU is an absolute path. Output went to
`/dev/null`. Builtin and GNU had JSON `status=ok`. 142 calls per batch.

Debian BusyBox 1.37.0 `uptime -s` is one second behind GNU on this host
(now-uptime vs `btime`) and is `output-mismatch`; it has no ratio.

All times are **median milliseconds per batch**. Ratio is builtin ÷ GNU.

| Case | Calls | Builtin ms | GNU ms | BusyBox | Ratio |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| `uptime -s` | 142 | 7.525 (7.070–7.908) | 113.707 (111.536–119.360) | mismatch | **0.07×** |

```sh
python3 bench/loadables.py --binary out/bash --only uptime --cpu 10 \
  --runs 7 --output /tmp/uptime.json
```

Re-measure on a rebuilt full catalog binary before folding these numbers
into the snapshot JSON. This does not time default `uptime`, `-p`, or a
fixture-backed invocation.
