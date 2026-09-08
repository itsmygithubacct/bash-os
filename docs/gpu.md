# Graphics from Bash

`gpu` keeps a pixel canvas inside the shell. Drawing commands call native C
routines; `present` displays the result in a terminal that supports Kitty
graphics. A dashboard can update a graph without spawning a process or passing
pixel arrays through shell variables. The same canvas can produce image files
without a terminal or graphics driver. Optional GLES2 shaders run on a local GPU.

The `desktop` and `full` profiles include the builtin:

```bash
./build.sh
out/bash examples/gpu-dashboard.sh       # live CPU and memory; q to quit
out/bash examples/gpu-shader.sh          # animated shader; q to quit
```

The dashboard reads Linux `/proc` files and samples five times per second.
Space pauses it; resizing the terminal resets the graph. Both examples accept
a frame count as their first argument for finite runs. The shader example also
accepts `auto`, `shm`, `inline`, or `dmabuf` as its second argument.

## First canvas

Run this inside `out/bash` in a Kitty-compatible terminal:

```bash
gpu start 640 360 --fullscreen
trap 'gpu stop' EXIT
gpu clear 111827
gpu text 24 24 ffffff 'Hello from Bash' 2
gpu rect 24 80 280 120 2563eb
gpu circle 450 140 60 fbbf24
gpu plot 34d399 3 24 300 100 270 180 290 260 230 340 255 430 200
gpu present
gpu input event 5000 || :
gpu stop
```

There is one canvas per shell process. Invoke state-changing commands directly;
pipelines and `$(...)` create a child that cannot update its parent's canvas.
Bash 5.3's `${ command; }` substitution stays in the current shell:

```bash
read -r columns rows pixel_width pixel_height <<<"${ gpu size; }"
stats=${ gpu info; }
```

`--fullscreen` uses the alternate screen, hides the cursor, and enables mouse
button reporting. Graphics appear at the cursor position; fullscreen starts at
the upper left. Canvas dimensions are pixels and need not match terminal size.
`stop` deletes the session's images and restores the screen and cursor. Normal
shell exit and runtime module unload also clean up. Scripts should trap `EXIT`
and handle `INT`/`TERM` as the examples do. Input restores the terminal settings
before returning. The loadable creates no worker threads; GPU drivers may do so.

## Commands

Coordinates start at the top left. Shapes clip to the canvas. Colors are six
hex digits (`336699`, `#336699`, or `0x336699`); output is opaque. Canvas limits
are 10,000 pixels per dimension and 16,777,216 pixels total. Four full-size CPU
buffers cost about 16 bytes per pixel, plus any driver and terminal storage.

| Command | Behavior |
| --- | --- |
| `start W H [OPTIONS]` | Allocate a canvas and probe presentation support. |
| `stop` | Release the session; safe to repeat. |
| `info` | Print dimensions, transport, frame and byte counts, patch/compose counts, fallbacks, GPU uploads/readbacks, and renderer or fallback reason. |
| `size` | Print terminal columns, rows, pixel width, pixel height. Pixel sizes may be zero. |
| `resize W H` | Preserve the overlapping area, fill new pixels black, recreate rendering buffers, and force a full presentation. |
| `clear COLOR` | Fill the canvas. |
| `pixel X Y COLOR` | Set one pixel. Use bulk operations for substantial drawing. |
| `rect X Y W H COLOR [LINE_WIDTH]` | Filled rectangle, or outline when a width is supplied. |
| `line X1 Y1 X2 Y2 COLOR [LINE_WIDTH]` | Antialiased line; default width 1. |
| `circle X Y R COLOR [LINE_WIDTH]` | Filled circle, or ring when a width is supplied. |
| `text X Y COLOR STRING [SCALE]` | Built-in bitmap text, integer scale 1–16. This is not a general font shaping engine. |
| `plot COLOR LINE_WIDTH X Y X Y ...` | Draw an entire polyline in one call. |
| `scroll DX DY COLOR [X Y W H]` | Move pixels within the canvas or a viewport; fill exposed edges. Positive directions are right and down. |
| `present [X Y W H]` | Display changes. The optional rectangle hints where to update; changes elsewhere are retained for a subsequent unrestricted presentation. |
| `input VARIABLE TIMEOUT_MS` | Bind an event to a shell variable, waiting 0–60,000 ms. |
| `load PPM_FILE` | Read a binary P6 image matching the canvas dimensions. |
| `blit PPM_FILE X Y` | Read and copy a P6 image with clipping. |
| `load-rgba FILE` | Read exactly `W*H*4` bytes, RGBA in row order from top to bottom; ignore input alpha. |
| `save FILE [ppm\|rgba]` | Export the current image. Default is P6 PPM, maximum sample value 255. |
| `shader FRAGMENT_FILE` | Compile a GLES2 fragment shader, preserving the previous shader on a compile error. |
| `shader off` | Keep the last rendered image as the CPU canvas and disable the shader. |
| `render TIME_SECONDS` | Render the shader using the canvas and supplied finite time. |

`start` options are `--headless`, `--fullscreen`, `--tty PATH`,
`--transport auto|shm|inline|dmabuf`, and `--device /dev/dri/renderD…`.
`BASHOS_GPU_DEVICE` supplies the default device. Without a device selection,
the renderer tries accessible render nodes. `--headless` skips terminal setup
and probing; it cannot be combined with `--fullscreen`.

Commands return 0 on success, 1 on runtime failure, or 2 for invalid arguments.
`input` also returns 1 on timeout and clears its destination variable. Use it
in an `if` when running with `set -e`. It reports literal UTF-8 text or:

* `UP`, `DOWN`, `LEFT`, `RIGHT`, `HOME`, `END`, `INSERT`, `DELETE`, `PAGEUP`, `PAGEDOWN`;
* `ENTER`, `TAB`, `BACKSPACE`, `ESC`, `CTRL-C`, and other `CTRL-…` characters;
* `MOUSE:down:BUTTON:X:Y` or `MOUSE:up:BUTTON:X:Y`, using SGR button codes and
  one-based terminal cell coordinates;
* `RESIZE:COLUMNS:ROWS:PIXEL_WIDTH:PIXEL_HEIGHT` when terminal size changes.

Escape sequences have a short completion timeout. This input decoder covers
ordinary terminal keys and mouse buttons; it does not enable the extended
Kitty keyboard protocol. Applications decide whether and how to resize.

## Presentation and fallback

| Transport | Use |
| --- | --- |
| `auto` (default) | Probe local POSIX shared memory; use inline graphics if unavailable. Under SSH or tmux, start with inline graphics. |
| `shm` | Require a successful shared-memory probe. Full RGBA frames travel through private shared-memory objects. Small edits still use inline patches. |
| `inline` | Probe and send base64 RGBA through the terminal stream. Works through compatible remote connections, with higher bandwidth cost. |
| `dmabuf` | Try the Kilix fork's GPU buffer handoff, then fall back to probed shared memory or inline presentation on failure. |

For CPU canvases, `present` compares pixels with the last displayed image. It
sends a rectangle patch for damage smaller than half the canvas and a full
frame otherwise. An unchanged canvas sends no image data. Full frames alternate
two image IDs; small edits update the displayed root frame. The terminal must
support Kitty frame updates as well as initial image transmission.

With `KITTY_KILIX_RENDERING=1`, a single `scroll` between presentations uses the
fork's overlap-safe compose operation followed by edge/drawing patches. Other
terminals receive ordinary pixel updates. Multiple queued scrolls remain correct
but skip that optimization. Synchronization uses terminal mode 2026. The
presenter creates only its own images and deletes them at cleanup.

Shared memory uses random names, mode 0600, and at most three outstanding objects.
The terminal unlinks each after consuming it. If the ring remains busy after
two short retries or `/dev/shm` is full, a frame uses inline transmission.
Cleanup waits up to one second for
outstanding readers, then unlinks remaining objects. A terminal that stalls
longer may miss that final frame. No userspace cleanup runs after `SIGKILL`;
its abandoned objects have the `/bashos-gpu-…` prefix. Large inline frames are
uncompressed and consume approximately `W*H*4*4/3` stream bytes.

Inside tmux, graphics commands use DCS passthrough. Enable `allow-passthrough`
in tmux and use a terminal supporting Kitty graphics. Graphics and keyboard
query handling still depend on the multiplexer and terminal; unsupported
probes fail within a bounded timeout. Output goes to `/dev/tty` (or `--tty`),
leaving stdout available for application data and diagnostics.

If a probe receives no reply or the terminal rejects it, `start` reports the
failed transport, `TERM` and `TERM_PROGRAM`, and suggests how to proceed.
`XTERM_VERSION`, `TMUX`, and SSH variables add environment-specific guidance.
These are hints only: names such as `xterm-256color` are shared by different
terminals, and nested terminals can inherit another terminal's variables.
The graphics probe decides whether presentation can start. XTerm ignores Kitty
graphics commands, including when launched with `kilix run xterm`; run the
examples directly in a Kitty or Kilix shell tab. For drawing and image export
without terminal graphics, use `gpu start W H --headless`.

## GPU shaders and DMA-BUF

Rendering loads `libgbm.so.1`, `libEGL.so.1`, and `libGLESv2.so.2` on demand.
It needs access to a Linux render node, a surfaceless GLES2 context, and a
renderable linear XRGB8888 buffer. No graphics SDK headers or mandatory driver
link dependencies are added to the Bash build. Software drawing, image export,
shared-memory presentation, and inline presentation work without those drivers.
Use the dynamically linked `out/bash` for GPU rendering. The fully static
binary supports the software canvas and ordinary presentation, and reports a
driver-unavailable error for shaders or falls back when DMA-BUF is requested.

The shader receives `varying vec2 uv` with a top-left origin, plus uniforms
`vec2 resolution`, `float time`, and `sampler2D canvas`. For example:

```glsl
precision mediump float;
varying vec2 uv;
uniform float time;
void main() {
    gl_FragColor = vec4(uv.x, uv.y, 0.5 + 0.5 * sin(time), 1.0);
}
```

`render` preserves the CPU canvas as shader input across frames. That texture
is uploaded again only after drawing changes it. `present` and `save` expose
the rendered result. A subsequent CPU drawing command first reads back the
rendered image so overlays apply to what was displayed. `clear` replaces it
without a readback. Shader input is therefore explicit; there is no automatic
feedback loop. Shader files are bounded to 1 MiB and errors include the driver
compiler log. Driver initialization or shader compilation failure is an error;
transport fallback does not replace shader execution with a CPU implementation.

DMA-BUF presentation requires the matching Kilix fork launched with
`KILIX_GPU_DMABUF_IMPORT=1` and its EGL backend. The handoff socket must live
under the launching session's private, owned `KILIX_SESSION_HOME` directory.
Merely setting the variable in a shell inside an already running terminal does
not enable its importer. It is local IPC and cannot cross SSH.

The presenter exports one GBM buffer through a private Unix `SOCK_SEQPACKET`
socket using `SCM_RIGHTS`. Its v2 record describes dimensions, stride, offset,
format, modifier, and vertical orientation. It finishes GPU work before handoff
and waits for the terminal's acknowledgment before reusing the buffer. The
buffer is retired after a failed acknowledgment, so later renders cannot alter
storage that the receiver may still hold. The
terminal imports and copies into its own GPU image, so this avoids CPU pixel
readback and base64 encoding while still doing GPU work. `gpu info` exposes
`readbacks`, `uploads`, and any transport fallback to make that behavior visible.

CPU-drawn DMA-BUF frames still need a CPU-to-GPU upload. For a small scrolling
dashboard, ordinary shared-memory/patch presentation is often the better fit.
For shader animation, DMA-BUF can keep each successive frame off the CPU.

## Export and verification

```bash
out/bash -c '
  gpu start 640 360 --headless
  gpu clear 111827
  gpu text 24 24 ffffff "Build metrics" 2
  gpu plot 60a5fa 3 24 300 150 220 260 250 400 130 600 80
  gpu save out/metrics.ppm
  gpu stop
'
python3 tests/gpu-smoke.py out/bash
bash tests/gpu-sanitize.sh out/bash
GPU_TEST_DEVICE=/dev/dri/renderD129 python3 tests/gpu-smoke.py out/bash
```

Select an accessible render node for the optional last command. The ordinary
suite uses an independent terminal peer on a pseudo-terminal to replay frames,
patches, scrolling, input, fallback, and cleanup. Native tests compare shader
pixels and exported DMA-BUF bytes with the CPU readback, including rejected
handoffs. The sanitizer harness instruments both the builtin and raster helper.
`python3 bench/gpu.py out/bash` measures full-frame and retained-update traffic
against the same peer; its timing includes that Python peer and is not terminal
frame-rate or GPU performance evidence.

An optional live check launches its own Kilix windows and compares screenshots
for full frames, patches, and scrolling. It exercises inline/shared-memory
presentation, a rejected DMA-BUF handoff, and the enabled EGL importer:

```bash
KILIX_TEST_BINARY=/path/to/kilix/src/kitty/launcher/kitty \
BASHOS_GPU_DEVICE=/dev/dri/renderD129 python3 tests/gpu-live.py out/bash
```

This check needs X11 (`DISPLAY`), Pillow, and the matching Kilix fork. It captures
the test terminal's rendered framebuffer through a private control socket, saves
images under `out/gpu-live-*.png`, and closes its windows afterwards.

For an existing configured Bash tree, `bash tests/gpu-module.sh out/gpu.so`
builds a runtime loadable. Enable it in the matching Bash with
`enable -f /absolute/path/to/gpu.so gpu`. `GPU_BASH_TREE` selects a different
configured source tree. Compiled-in and runtime forms use the same implementation.
