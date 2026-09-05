# Provenance

bash-os is MIT-licensed (`LICENSE`, "bash_linux contributors"). It is assembled
from three sources, all MIT or bash-native:

- **GNU bash 5.3**, pinned by sha256 in `config/versions.sh` and fetched at
  build time. Its own `examples/loadables/*.c` supply the stock builtins the
  list names but this repo does not carry (`cat`, `chmod`, `cut`, …).
- **An upstream bash-os loadables collection** (MIT). The busybox-replacement
  loadables — `ls cp mv find sed sort grep ip ps` and the rest — and the
  injection technique originate there. This repo carries a curated subset.
- **Loadables written for the `lichee-nano-bashos` appliance** (MIT), generic
  enough to belong here: `httpd` (an HTTP server primitive), `rngseed` (credits
  a saved kernel random seed), `rtspcat` (an RTSP/RTP H.264 client),
  `reboot`/`halt`/`poweroff`/`chown`/`chgrp`, and an enhanced `stat` (a
  derivative of bash's stock `stat` loadable).

## What deliberately stays out

The appliance's four board-coupled managers — `bashnpu`, `bashyolox`,
`bashrtsp`, `detectlog` — depend on NPU/video/detection ABIs and remain in that
project, not here. bash-os is the board-agnostic layer it builds on.

## Local adaptations

Small fixes to stock/upstream loadables, applied at build time in `build.sh`
(so the sources stay as taken) or carried in the source and noted there:

- `cut`: the output buffer was sized with `strlen()` *after* `strsep` had
  overwritten the field delimiters with NULs, so a multi-field range overflowed
  the heap. Sized from the line length taken before the split.
- `mkdir -p`: only `chmod` the components it actually created, not existing
  parents.
- `fltexpr`: initialise NaN/Inf at compile time (its runtime `_builtin_load`
  hook never fires for a static builtin). Needs `libm`, linked via `LOCAL_LIBS`.
