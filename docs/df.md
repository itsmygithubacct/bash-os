# df

`df -P` prints POSIX disk-space rows: filesystem, 1024-byte blocks, used,
available, capacity, mount point. GNU `df(1)`, BusyBox `df` and the builtin
agree on whitespace-separated fields for a given sample; column padding
differs.

`df -P /` is not a stable batch: used and available counts move between
invocations, so concatenated output fails the harness. A private tmpfs could
not be mounted without root. The timed operand is `df -P /dev` (udev,
used=0). GNU, BusyBox and the builtin matched on fields for that path,
including a 97-call batch.

```sh
./build.sh --include df --name df
out/bash-df -c 'PATH=; df -P /dev'
```

## Measurements, 2026-09-10

This is a follow-up to the [catalog snapshot](loadables-status.md), not a
replacement of it. The binary is the catalog full build: SHA-256
`9b2c69c9b8dc1c8cb437904afeacc51919fc4db31fc676d0c41137a2c8caad73`, Bash
5.3.15, pinned to CPU 10. Host: Intel Core i7-9850H, Linux 6.12.96, x86-64.
GNU coreutils 9.7, BusyBox 1.37.0. Raw JSON stays outside Git.

Seven samples followed whole-batch field validation. Builtin, GNU and
BusyBox ran from the same bash-os shell with startup files disabled,
`LC_ALL=C`, `TZ=UTC` and an empty `PATH`. GNU and BusyBox are absolute
paths. Output went to `/dev/null`. Every side had JSON `status=ok`.
97 calls per batch.

All times are **median milliseconds per batch**. Ratio is builtin ÷ GNU.

| Case | Calls | Builtin ms | GNU ms | BusyBox ms | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| `df -P /dev` | 97 | 12.605 (10.566–15.598) | 67.792 (66.548–69.960) | 73.916 (72.724–77.799) | **0.19×** |

```sh
python3 bench/loadables.py --binary out/bash --only df --cpu 10 \
  --runs 7 --output /tmp/df.json
```

Re-measure on a rebuilt full catalog binary before folding these numbers
into the snapshot JSON. This does not time `df` with no operand (all
mounts), `-h`/`-i`, or a spinning root filesystem.
