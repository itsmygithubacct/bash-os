#!/usr/bin/env python3
"""Independent application-frame oracles, shared by correctness and bench/gpu.py.
No compilation or timing experiments in this entry point. --device enables native
GBM/EGL/GLES execution; --driver-fixture labels the injected ABI model explicitly.
"""
import argparse
import hashlib
from functools import lru_cache
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gpu_peer', ROOT/'tests/gpu-smoke.py')
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
WIDTH, HEIGHT, FRAMES = 640, 360, 16
SHADER = ('precision mediump float; varying vec2 uv; uniform float time; '
          'void main(){gl_FragColor=vec4(uv.x,uv.y,time,1.0);}')
HALF = ('precision mediump float; varying vec2 uv; uniform sampler2D canvas; '
        'void main(){gl_FragColor=vec4(texture2D(canvas,uv).rgb*0.5,1.0);}')


def solid(w, h, rgb):
    return bytes((*rgb, 255)) * (w*h)


@lru_cache(maxsize=8)
def gradient(w, h, blue):
    return bytes(c for y in range(h) for x in range(w)
                 for c in (round((x+.5)/w*255), round((y+.5)/h*255), blue, 255))


def resize(pixels, w, h, nw, nh):
    result = bytearray(solid(nw, nh, (0, 0, 0)))
    for y in range(min(h, nh)):
        result[y*nw*4:(y*nw+min(w, nw))*4] = pixels[y*w*4:(y*w+min(w, nw))*4]
    return bytes(result)


def cases(native=False):
    result = ['inline-full', 'shm-full', 'inline-patch', 'shm-scroll',
              'shm-resize', 'auto-fallback', 'driver-fallback']
    if native:
        result += ['shader-shm', 'shader-dmabuf', 'shader-reject', 'shader-abandon', 'shader-resize']
    return result


def workload(name, frames=FRAMES):
    """Return shell steps and independent expected displayed RGBA per step."""
    native = name.startswith('shader-')
    transport = {'auto-fallback':'auto', 'driver-fallback':'dmabuf',
                 'shader-dmabuf':'dmabuf', 'shader-reject':'dmabuf', 'shader-abandon':'dmabuf'}.get(name,
                 'inline' if name.startswith('inline') else 'shm')
    w, h = WIDTH, HEIGHT
    pixels = solid(w, h, (17, 24, 39))
    initial = 'gpu clear 111827'
    if native:
        initial += '\ngpu shader "$GPU_FRAME_DIR/gradient.frag"\ngpu render 0.25'
        pixels = gradient(w, h, 64)
    expected = [(w, h, pixels)]
    steps = []
    for i in range(frames):
        if native:
            step = f'gpu render {"0.75" if i % 2 == 0 else "0.25"}'
            if name == 'shader-resize':
                w, h = (WIDTH+16, HEIGHT+8) if i % 2 == 0 else (WIDTH, HEIGHT)
                step = f'gpu resize {w} {h}\n' + step
            pixels = gradient(w, h, 191 if i % 2 == 0 else 64)
        elif name.endswith('full') or name in ('auto-fallback', 'driver-fallback'):
            step = 'gpu clear ' + ('ff0000' if i % 2 == 0 else '0000ff')
            pixels = solid(w, h, (255, 0, 0) if i % 2 == 0 else (0, 0, 255))
        elif name.endswith('patch'):
            step = f'gpu rect {20+i} 30 4 3 ff0000'
            edited = bytearray(pixels)
            for y in range(30, 33):
                edited[(y*w+20+i)*4:(y*w+24+i)*4] = solid(4, 1, (255, 0, 0))
            pixels = bytes(edited)
        elif name.endswith('scroll'):
            step = 'gpu scroll -2 0 111827\ngpu rect 638 170 2 3 60a5fa'
            edited = bytearray()
            for y in range(h):
                edited.extend(pixels[(y*w+2)*4:(y+1)*w*4] + solid(2, 1, (17, 24, 39)))
            for y in range(170, 173):
                edited[(y*w+638)*4:(y*w+640)*4] = solid(2, 1, (96, 165, 250))
            pixels = bytes(edited)
        elif name.endswith('resize'):
            nw, nh = (WIDTH+16, HEIGHT+8) if i % 2 == 0 else (WIDTH, HEIGHT)
            step = f'gpu resize {nw} {nh}\ngpu pixel 10 10 ' + ('ff0000' if i % 2 == 0 else '0000ff')
            edited = bytearray(resize(pixels, w, h, nw, nh))
            edited[(10*nw+10)*4:(10*nw+11)*4] = solid(1, 1, (255, 0, 0) if i % 2 == 0 else (0, 0, 255))
            pixels, w, h = bytes(edited), nw, nh
        steps.append(step)
        expected.append((w, h, pixels))
    return transport, initial, steps, expected


class FrameTerminal(peer.Terminal):
    """Check the peer's replay at each synchronization end, including no-op frames."""
    def __init__(self, expected, native=False, fixture=False, acknowledge=False, **kwargs):
        super().__init__(**kwargs)
        self.expected, self.native, self.fixture = expected, native, fixture
        self.ends, self.pending_frame = [], b''
        self.ack_read, self.ack_write = os.pipe() if acknowledge else (None, None)
        self.payload_bytes = self.shared_bytes = self.exported_pixel_bytes = 0

    def receive(self, data):
        # Keep only a potential split synchronization terminator; probes must
        # continue flowing so the shell can receive their replies.
        data = self.pending_frame + data
        marker = b'\x1b[?2026l'
        while marker in data:
            chunk, data = data.split(marker, 1)
            super().receive(chunk + marker)
            index = len(self.ends)
            assert index < len(self.expected), 'extra presented frame'
            w, h, wanted = self.expected[index]
            assert self.last_size == (w, h), (index, self.last_size, (w, h))
            actual = self.last_frame
            assert len(actual) == len(wanted)
            if self.native:
                assert all(abs(a-b) <= 1 for a, b in zip(actual, wanted)), (index, 'shader pixel mismatch')
            else:
                assert actual == wanted, (index, 'CPU pixel mismatch')
            self.ends.append(len(self.stream))
            if self.ack_write is not None: os.write(self.ack_write, b'frame\n')
        keep = max((n for n in range(1, len(marker)) if data.endswith(marker[:n])), default=0)
        if len(data) > keep:
            super().receive(data[:-keep] if keep else data)
        self.pending_frame = data[-keep:] if keep else b''

    def command(self, control, payload):
        action = control.get(b'a', b't')
        if action in (b't', b'T', b'f'):
            if control.get(b't') == b's':
                self.shared_bytes += int(control[b's'])*int(control[b'v'])*4
            else:
                self.payload_bytes += len(payload)
        if action == b'g':
            self.exported_pixel_bytes += self.expected[len(self.ends)][0]*self.expected[len(self.ends)][1]*4
        super().command(control, payload)


def normalize_protocol(wire):
    normalized = re.sub(rb'i=[0-9]+', b'i=ID', wire)
    return re.sub(rb'(\x1b_G[^;]*\bt=[sg]\b[^;]*;)[^\x1b]*(\x1b\\)',
                  rb'\1PATH\2', normalized)


def parse_info(text):
    return {key: (int(value) if value.isdigit() else value)
            for key, value in (word.split('=', 1) for word in text.split())}


def execute(binary, name, *, frames=FRAMES, device=None, fixture=None, measure=False):
    peer.binary = str(Path(binary).resolve())
    transport, initial, steps, expected = workload(name, frames)
    with tempfile.TemporaryDirectory(prefix='gpu-frame-') as tmp:
        directory = Path(tmp)
        session = directory/'session'
        session.mkdir(mode=0o700)
        cache = directory/'driver-cache'
        cache.mkdir(mode=0o700)
        (directory/'gradient.frag').write_text(SHADER)
        env = {'GPU_FRAME_DIR':tmp, 'XDG_CACHE_HOME':str(cache),
               'MESA_SHADER_CACHE_DIR':str(cache), '__GL_SHADER_DISK_CACHE_PATH':str(cache), 'KILIX_SESSION_HOME':str(session),
               'KITTY_KILIX_RENDERING':'1', 'BASHOS_GPU_DEVICE':device,
               'BASHOS_GPU_GBM_LIB':None, 'BASHOS_GPU_EGL_LIB':None, 'BASHOS_GPU_GLES_LIB':None}
        if fixture:
            env['GPU_FIXTURE_TRACE'] = str(directory/'driver-trace.jsonl')
            env.update({key:str(Path(fixture).resolve()) for key in
                        ('BASHOS_GPU_GBM_LIB','BASHOS_GPU_EGL_LIB','BASHOS_GPU_GLES_LIB')})
        if name == 'driver-fallback': env['BASHOS_GPU_GBM_LIB'] = '/nonexistent-gpu-frame-library'
        terminal = FrameTerminal(expected, native=name.startswith('shader'), fixture=bool(fixture),
                                 shm=name != 'auto-fallback', dmabuf_ack=(None if name == 'shader-abandon' else name != 'shader-reject'), acknowledge=True)
        env['GPU_FRAME_ACK_FD'] = str(terminal.ack_read)
        # The explicit ABI fixture exports memfd storage, not a kernel DMA-BUF.
        original_ioctl = peer.fcntl.ioctl
        def fixture_ioctl(fd, request, *args):
            if fixture and request == 0x40086200:
                assert os.readlink(f'/proc/self/fd/{fd}').startswith('/memfd:sol-gpu-fixture')
                return 0
            return original_ioctl(fd, request, *args)
        peer.fcntl.ioctl = fixture_ioctl
        script = ('session_begin=${EPOCHREALTIME/./}\n' if measure else '')
        script += f'gpu start {WIDTH} {HEIGHT} --tty "$GPU_TEST_TTY" --transport {transport}\n'
        script += initial + '\ngpu present\nread -r ack <&"$GPU_FRAME_ACK_FD"; [[ $ack == frame ]]\n'
        if measure:
            script += 'session_end=${EPOCHREALTIME/./}\nprintf "INITIAL %s\\n" "$((session_end-session_begin))"\n'
        script += 'printf "BEFORE "\ngpu info\n'
        # Timestamps surround drawing + presentation, without subprocesses.
        for step in steps:
            script += ('begin=${EPOCHREALTIME/./}\n' if measure else '') + step + '\n'
            if measure: script += 'ready=${EPOCHREALTIME/./}\n'
            script += 'gpu present\n'
            if measure:
                script += 'end=${EPOCHREALTIME/./}\nprintf "LATENCY %s\\nUPDATE %s\\nPRESENT %s\\n" "$((end-begin))" "$((ready-begin))" "$((end-ready))"\n'
            script += 'read -r ack <&"$GPU_FRAME_ACK_FD"; [[ $ack == frame ]]\n'
            if measure:
                script += 'completed=${EPOCHREALTIME/./}\nprintf "COMPLETION %s\\n" "$((completed-begin))"\n'
        script += '''printf 'AFTER '; gpu info
while read -r key value unit; do
    if [[ $key == VmHWM: ]]; then printf 'RSS_KIB %s\n' "$value"; fi
done </proc/$$/status
declare -A seen_libraries=()
while read -r range perms offset dev inode path; do
    case $path in
        *libgbm*|*libEGL*|*libGLES*|*_dri.so|*libgallium*|*libdrm*|*libnvidia*|*/driver.so)
            if [[ ! ${seen_libraries[$path]:-} ]]; then
                seen_libraries[$path]=1
                printf 'LIBRARY %s\n' "$path"
            fi ;;
    esac
done </proc/$$/maps
gpu stop
gpu stop
'''
        try:
            started = time.monotonic() if measure else None
            output = terminal.run(script, env=env, pass_fds=(terminal.ack_read,)).decode()
            batch_ms = (time.monotonic()-started)*1000 if measure else None
            if terminal.pending_frame: peer.Terminal.receive(terminal, terminal.pending_frame)
        finally:
            peer.fcntl.ioctl = original_ioctl
            os.close(terminal.ack_read); os.close(terminal.ack_write)
        assert len(terminal.ends) == frames+1, (name, len(terminal.ends))
        assert not list(session.iterdir()), 'DMA-BUF socket directory leaked'
        before = parse_info(re.search(r'^BEFORE (.*)$', output, re.M)[1])
        after = parse_info(re.search(r'^AFTER (.*)$', output, re.M)[1])
        assert before['frames'] == 1 and after['frames'] == frames+1
        assert after['bytes'] == terminal.ends[-1], (after['bytes'], terminal.ends[-1])
        native = name.startswith('shader')
        patch = name.endswith('patch') or name.endswith('scroll')
        assert after['patches'] == (frames if patch else 0), after
        assert after['composes'] == (frames if name.endswith('scroll') else 0), after
        expected_transport = 'dmabuf' if name == 'shader-dmabuf' else ('inline' if name.startswith('inline') or name == 'auto-fallback' else 'shm')
        assert after['transport'] == expected_transport, after
        assert after['fallbacks'] == int(name in ('driver-fallback','shader-reject','shader-abandon')), after
        uploads = frames+1 if name == 'shader-resize' else 2 if name in ('shader-reject','shader-abandon') else int(native)
        readbacks = frames+1 if native and name != 'shader-dmabuf' else 0
        assert (after['uploads'], after['readbacks']) == (uploads, readbacks), after
        assert terminal.counts['patch'] == after['patches'] and terminal.counts['compose'] == after['composes']
        assert terminal.counts['dmabuf'] == (frames+1 if name == 'shader-dmabuf' else int(name in ('shader-reject','shader-abandon')))
        assert terminal.counts['full'] == (0 if name == 'shader-dmabuf' else (1 if patch else frames+1))
        total_rgba = sum(w*h*4 for w,h,_ in expected)
        if name == 'shader-dmabuf':
            assert terminal.exported_pixel_bytes == total_rgba
            assert terminal.payload_bytes == terminal.shared_bytes == 0
        elif name.endswith('patch'):
            assert terminal.payload_bytes == WIDTH*HEIGHT*4 + 4*3*4 + (frames-1)*3*4
            assert terminal.shared_bytes == 0
        elif name.endswith('scroll'):
            assert terminal.payload_bytes == frames*2*HEIGHT*4
            assert terminal.shared_bytes == WIDTH*HEIGHT*4
        else:
            assert terminal.payload_bytes + terminal.shared_bytes == total_rgba
        if name == 'shader-abandon':
            assert len(terminal.held_frames) == 1 and len(terminal.dmabuf_records) == 1
            raw = terminal.held_frames[0]
            stride = terminal.dmabuf_records[0][4]
            original = expected[0][2]
            for y in range(HEIGHT):
                row = raw[y*stride:y*stride+WIDTH*4]
                wanted = original[(HEIGHT-1-y)*WIDTH*4:(HEIGHT-y)*WIDTH*4]
                actual = bytearray(len(row))
                actual[0::4],actual[1::4],actual[2::4],actual[3::4] = row[2::4],row[1::4],row[0::4],bytes([255])*WIDTH
                assert all(abs(a-b)<=1 for a,b in zip(actual,wanted)), 'abandoned buffer changed after retirement'
        latencies = [int(x)/1000 for x in re.findall(r'^LATENCY (\d+)$', output, re.M)]
        assert len(latencies) == (frames if measure else 0)
        driver_trace = []
        trace_path = directory/'driver-trace.jsonl'
        if fixture and native:
            driver_trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
            assert sum(row['uploads'] for row in driver_trace) == uploads, driver_trace
            assert sum(row['readbacks'] for row in driver_trace) == readbacks, driver_trace
            assert sum(row['draws'] for row in driver_trace) == frames+1, driver_trace
            expected_upload_bytes = sum(w*h*4 for w,h,_ in expected) if name == 'shader-resize' else uploads*WIDTH*HEIGHT*4
            expected_readback_bytes = sum(w*h*4 for w,h,_ in expected) if readbacks else 0
            assert sum(row['upload_bytes'] for row in driver_trace) == expected_upload_bytes
            assert sum(row['readback_bytes'] for row in driver_trace) == expected_readback_bytes
            assert sum(row['allocations'] for row in driver_trace) == (frames+1 if name == 'shader-resize' else 2 if name in ('shader-reject','shader-abandon') else 1)
        wire = bytes(terminal.stream[terminal.ends[0]:terminal.ends[-1]])
        normalized = normalize_protocol(wire)
        return dict(status='ok',  name=name, width=WIDTH, height=HEIGHT, updates=frames,
                    renderer=re.findall(r'^renderer=(.*)$',output,re.M)[-1:] or ['CPU soft raster'],
                    transport=after['transport'], counters_before=before, counters_after=after,
                    tty_bytes=after['bytes']-before['bytes'],
                    tty_normalized_bytes=len(normalized),
                    protocol_normalized_sha256=hashlib.sha256(normalized).hexdigest(),
                    inline_rgba_bytes=terminal.payload_bytes, shared_rgba_bytes=terminal.shared_bytes,
                    exported_pixel_bytes=terminal.exported_pixel_bytes,
                    dmabuf_record_bytes=40*len(terminal.dmabuf_records),
                    dmabuf_ack_bytes=(0 if name == 'shader-abandon' else len(terminal.dmabuf_records)),
                    frame_latency_ms=latencies,
                    update_ms=[int(x)/1000 for x in re.findall(r'^UPDATE (\d+)$',output,re.M)],
                    present_ms=[int(x)/1000 for x in re.findall(r'^PRESENT (\d+)$',output,re.M)],
                    peer_completion_ms=[int(x)/1000 for x in re.findall(r'^COMPLETION (\d+)$',output,re.M)],
                    host_peer_batch_ms=batch_ms,
                    setup_and_first_frame_ms=(int(re.search(r'^INITIAL (\d+)$',output,re.M)[1])/1000 if measure else None), shell_peak_rss_kib=int(re.search(r'^RSS_KIB (\d+)$', output, re.M)[1]),
                    cpu_canvas_bytes_peak=max(w*h*16 for w,h,_ in expected),
                    expected_sha256=hashlib.sha256(b''.join(p for _,_,p in expected)).hexdigest(),
                    script_sha256=hashlib.sha256(script.encode()).hexdigest(),
                    graphics_libraries={p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
                                        for p in re.findall(r'^LIBRARY (.*)$', output, re.M)},
                    upload_rgba_bytes_from_counters=(sum(w*h*4 for w,h,_ in expected) if name == 'shader-resize' else uploads*WIDTH*HEIGHT*4),
                    readback_rgba_bytes_from_counters=(sum(w*h*4 for w,h,_ in expected) if readbacks else 0),
                    exported_referenced_storage_bytes=sum(r[4]*r[3]+r[5] for r in terminal.dmabuf_records),
                    terminal_counts=terminal.counts, driver_fixture_trace=driver_trace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--device')
    parser.add_argument('--driver-fixture')
    parser.add_argument('--frames', type=int, default=FRAMES)
    args = parser.parse_args()
    for name in cases(bool(args.device)):
        result = execute(args.binary, name, frames=args.frames, device=args.device, fixture=args.driver_fixture)
        # Correctness entry point deliberately emits no timing measurements.
        print(name, result['status'], result['transport'], result['counters_after'])
    if not args.device: print('UNAVAILABLE native driver: pass --device (or an explicitly labelled ABI fixture)')


if __name__ == '__main__':
    main()
