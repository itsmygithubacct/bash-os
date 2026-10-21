# GPU application frame validation

Fresh review builds and runtime checks now pass: all 12 frame cases with the
injected driver, all 12 with ASan/UBSan instrumentation, and all 12 on the
available host render device. Error injection and oracle negative controls pass;
the native smoke suite passes 86 checks. The original unrun status is retained
in the campaign evidence. Live terminal importing and intended-device deployment
remain unqualified; these checks use an isolated protocol peer.

The frame fixture creates its private socket directory under `/tmp`. Unix socket
addresses have a 108-byte bound; inheriting a long campaign `TMPDIR` previously
forced shared-memory fallback before the DMA-BUF assertions could be exercised.
The correction preserves the exact transport, pixel and lifecycle assertions.

`tests/sol-gpu-frames.py` adds application frame oracles to the existing
`tests/gpu-smoke.py` terminal peer. Each presentation is replayed independently
and checked at its synchronization end. CPU frames must match every RGBA byte;
shader gradients allow one quantization level per channel. Expected frames come
from Python geometry and color formulas, rather than from `gpu save` or an
earlier run of the command. A negative-control test rejects corrupt pixels,
wrong dimensions, extra frames and truncated synchronization markers.

The default work unit is one initial 640×360 frame followed by 16 updates in
one shell, with an empty `PATH`. The cases are:

| Case | Work and expected behavior |
| --- | --- |
| `inline-full`, `shm-full` | Alternate solid red and blue; 17 full frames. |
| `inline-patch` | Move a 4×3 red rectangle one pixel each update, retaining prior pixels; one full frame and 16 patches. The first patch is 4×3, later patches are 1×3. |
| `shm-scroll` | Scroll left two pixels, fill exposed edges and draw a 2×3 marker; one full frame, 16 compositions and 16 edge patches. |
| `shm-resize` | Alternate 656×368 and 640×360, preserve overlap, black-fill new pixels, then change one pixel; 17 full frames. |
| `auto-fallback` | Reject the shared-memory probe, validate inline full redraws. |
| `driver-fallback` | Inject an unavailable GBM library, validate fallback to shared-memory full redraws. |
| `shader-shm` | Render a gradient with alternating blue channel, retaining the original CPU shader input; one upload and 17 readbacks. |
| `shader-dmabuf` | Render the same gradient and pass the exported buffer using `SCM_RIGHTS`; one upload, 17 handoffs, no readbacks. |
| `shader-reject` | Reject the first handoff, validate readback and shared-memory fallback; retirement requires another upload on the next render. |
| `shader-abandon` | Retain the exported FD without acknowledging it; validate fallback and that all original buffer pixels survive subsequent renders. |
| `shader-resize` | Recreate rendering buffers at each alternating size; 17 uploads and 17 readbacks. |

The harness also checks packet grammar, decoded payload lengths, byte counters
against the received stream, exact pixel traffic budgets, transport selection,
frame/patch/compose/fallback/upload/readback counts, terminal state restoration,
image deletion, shared-memory unlinking and private socket directory cleanup.
The existing smoke tests retain input, drawing, repeated-session, module unload,
shader input, overlays and abandoned-handoff coverage.

`tests/sol-gpu-driver.c` is an injectable GBM/EGL/GLES ABI model. The production
builtin still opens the selected device file, loads entry points dynamically,
creates a context and buffer, uploads textures, renders, reads pixels and
exports file descriptors. The fixture supplies known copy, half-intensity and
gradient operations in host memory; it does not compile arbitrary GLSL, execute
kernel DRM ioctls or qualify hardware. Exported buffers have padded rows and a
64-byte plane offset. The peer checks their identity before omitting the
kernel DMA-BUF synchronization ioctl for this explicit memfd fixture. Real
devices retain the synchronization ioctl.

The fixture records driver calls on library unload. Their upload, draw,
readback and allocation counts must agree with the command's counters and the
workload. `tests/sol-gpu-errors.py` covers missing entry points, missing device
files, initialization/allocation/import/framebuffer failures, failed shader
compile/link, failed draw/readback, retry, shader disable, `/dev/full`, missing
output directories and repeated FD cleanup. Invalid shader replacement must
preserve the previous program and its pixels.

Build the executable and fixtures separately from measurement:

```bash
./build.sh --include gpu --name gpu-frames
bash tests/sol-gpu-build-fixture.sh out/gpu-driver.so
touch out/gpu-render-node.fixture
python3 tests/sol-gpu-oracle-check.py
python3 tests/gpu-smoke.py out/bash-gpu-frames
python3 tests/sol-gpu-errors.py out/bash-gpu-frames out/gpu-driver.so
python3 tests/sol-gpu-frames.py out/bash-gpu-frames \
  --device out/gpu-render-node.fixture --driver-fixture out/gpu-driver.so
```

GPU needs the selected `_soft_raster` helper and `-ldl -lm`, with no companion
loadables. Bash builtins suffice for the examples and frame scripts. Native
shader execution still requires a dynamically linked Bash. The fixture does
not remove that production restriction.

`bench/gpu.py` uses these same independent oracles. It runs one untimed warm-up
and at least seven measured batches per selected case, checking every frame and
all counters on every batch. A fresh shell, PTY, private session directory and empty private driver shader
cache reset each sample. Driver cache writes stay in the temporary directory. A private pipe acknowledges each validated frame before the
next update, so Python pixel validation cannot accidentally exhaust the shared
memory ring. The command still uses the production presentation protocol. It fails the command when any case fails and retains a
per-case failure in JSON without publishing latency summaries for that case.

```bash
python3 bench/gpu.py out/bash-gpu-frames --cpu 11 \
  --output /tmp/gpu-cpu-frames.json
python3 bench/gpu.py out/bash-gpu-frames --cpu 11 \
  --device /dev/dri/renderD128 --output /tmp/gpu-native-frames.json
python3 bench/gpu.py out/bash-gpu-frames --cpu 11 \
  --device out/gpu-render-node.fixture --driver-fixture out/gpu-driver.so \
  --only shader-shm,shader-dmabuf,shader-reject,shader-abandon,shader-resize \
  --output /tmp/gpu-fixture-frames.json
```

Campaign builds and measurements must additionally use their respective
resource gates. The benchmark itself never compiles.

Each raw report records source and binary hashes, driver/library identities,
renderer, transport, kernel, Python/compiler/Bash versions, affinity, fixture and
script hashes, options, work counts, all samples, median/p95/range, and shell
peak RSS from `/proc`. It separates setup plus first-frame cost from the 16
subsequent frame latencies, drawing/rendering and presentation components, and
completion at the validating peer. Frame latency surrounds drawing/rendering and
presentation inside Bash; it includes synchronous driver completion and terminal
write backpressure. Batch wall time also includes shell startup, the Python
peer, validation and cleanup. These are host protocol-fixture timings, with no
external-tool ratio or claim about terminal display latency.

Traffic fields distinguish terminal stream bytes for the 16 updates from total
decoded inline/shared pixel bytes including the initial frame. Exported pixel
bytes describe referenced image content, not bytes copied over the terminal;
referenced storage sizes include stride and offset. Four CPU canvas buffers use
16 bytes per pixel. Upload/readback byte estimates combine validated counts
with frame dimensions. Protocol hashes normalize random image IDs and private
shared-memory/socket names; actual wire bytes retain their metadata length
variation and are validated against the byte counter on each pass. Shell peak RSS includes Bash and resident driver memory;
it does not measure total device memory, terminal memory or the Python peer.
Real deployment memory and display latency need qualification on the intended
device and terminal.

## Fresh review measurements

The corrected fixture completed seven measured batches after one warm-up for
all 12 cases, plus all five shader cases on the host i915 render node (PCI
8086:3e9b). Each batch has 16 updates after its initial frame. The benchmark gate
pinned the processes to CPU 11. The native shader frame distributions were:

| Case | Median ms | p95 ms |
| --- | ---: | ---: |
| `shader-shm` | 5.437 | 6.754 |
| `shader-dmabuf` | 140.734 | 277.783 |
| `shader-reject` | 4.573 | 45.058 |
| `shader-abandon` | 5.076 | 43.819 |
| `shader-resize` | 58.124 | 68.741 |

These are 112 frame samples per case. DMA-BUF presentation waits for the test
peer to map and convert the exported pixels before acknowledging the handoff;
that Python work contributes to its reported latency. The table therefore does
not compare renderer throughput or establish that one transport is faster in
a real terminal. The raw campaign reports retain every batch and source,
binary and driver identity.

The legacy headless GPU case also passed seven 30-iteration batches: median
102.194 ms per batch. That work includes session reset, raster drawing and PPM
saving. Its rectangle is filled, despite the older shared catalog description
calling it stroked. No external comparator or speedup is claimed.

Integration note: the catalog retains the historical 30-update graphics table separately from this 16-update frame harness. Current CPU and ABI-fixture checks do not imply native-device coverage. Timed headless batches include reset, rasterization, and save; DMA-BUF frame timings remain peer-bound.
