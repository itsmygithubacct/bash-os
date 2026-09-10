# hostid

`hostid` prints the 32-bit host identifier as eight lowercase hex digits.
GNU `hostid(1)` and BusyBox `hostid` use `gethostid(3)`. On Linux that is
`/etc/hostid` when present, otherwise an address-derived value.

The earlier builtin preferred the first eight hex digits of
`/etc/machine-id`. That is a different identifier; there is no `hostid(1)`
operand that reads machine-id. The default path is now `gethostid(3)`.
`BASHHOSTID_MACHINE_ID_PATH` may name a test file of eight hex digits;
anything else in that file falls back to `gethostid(3)`.

```sh
./build.sh --include hostid --name hostid
out/bash-hostid -c 'PATH=; hostid'
```

## Compatibility

`tests/hostid-check.sh` checks identity with `hostid(1)`, the override file,
invalid-override fallback, extra-operand failure, and that the default is
not the machine-id prefix. On `out/bash-hostid` that suite is **5/5**.

## Measurements, 2026-09-10

This is a follow-up to the [catalog snapshot](loadables-status.md). The
catalog full binary still carries the earlier default; these numbers use
`out/bash-hostid` (one injected builtin), SHA-256
`8013db5361b36df35625624db342b8ba1a5bd32340ae4a9de8d6816aa7ca8855`, pinned
to CPU 11. Host: Intel Core i7-9850H, Linux 6.12.96, x86-64. The
[measurement summary](data/hostid-benchmarks.json) records fixture hashes,
pass counts and timing ranges.

Seven samples followed output validation. Builtin, GNU and BusyBox ran from
the same bash-os shell with startup files disabled, `LC_ALL=C`, `TZ=UTC`
and an empty `PATH`. GNU and BusyBox are absolute paths. Output went to
`/dev/null`. Every side had JSON `status=ok`.

All times are **median milliseconds per batch**. Ratio is builtin ÷ GNU.

| Case | Calls | Builtin ms | GNU ms | BusyBox ms | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| `hostid` | 58 | 11.410 (9.571–13.287) | 118.248 (92.899–137.350) | 131.253 (119.859–159.225) | **0.10×** |

```sh
python3 bench/loadables.py --binary out/bash-hostid --only hostid --cpu 11 \
  --runs 7 --output /tmp/hostid.json
```

Raw logs stay outside Git. Re-measure on a rebuilt full catalog binary
before folding these numbers into the snapshot JSON.
