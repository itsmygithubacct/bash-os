#!/usr/bin/env python3
"""State preservation, output failures and injected native initialization errors.
Requires a separately built ABI fixture; never compiles or measures latency.
"""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('frames', ROOT/'tests/sol-gpu-frames.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
peer = f.peer
peer.binary = str(Path(sys.argv[1]).resolve())
fixture = str(Path(sys.argv[2]).resolve())

with tempfile.TemporaryDirectory(prefix='gpu-error-') as tmp:
    d = Path(tmp)
    (d/'node').touch()
    (d/'half.frag').write_text(f.HALF)
    (d/'invalid.frag').write_text('INVALID')
    (d/'link.frag').write_text('precision mediump float; void main(){gl_FragColor=vec4(1.0);} // LINK_FAIL')
    env = {'GPU_ERROR_DIR':tmp, 'BASHOS_GPU_DEVICE':str(d/'node'),
           **{k:fixture for k in ('BASHOS_GPU_GBM_LIB','BASHOS_GPU_EGL_LIB','BASHOS_GPU_GLES_LIB')}}
    for override, reason in (
            ({'BASHOS_GPU_GBM_LIB':fixture+'.missing.so'}, 'missing graphics entry point: gbm_create_device'),
            ({'BASHOS_GPU_DEVICE':str(d/'missing-node')}, 'cannot open render node')):
        peer.run('''gpu start 8 8 --headless
if gpu shader "$GPU_ERROR_DIR/half.frag" 2>"$GPU_ERROR_DIR/error"; then exit 90; fi
gpu stop
''', env={**env,**override})
        assert reason in (d/'error').read_text()
    peer.run('''gpu start 8 8 --headless
gpu clear ff0000
for format in rgba ppm; do
    if gpu save /dev/full "$format"; then exit 91; fi
    if gpu save "$GPU_ERROR_DIR/missing/image" "$format"; then exit 92; fi
done
gpu save "$GPU_ERROR_DIR/preserved.rgba" rgba
gpu stop
if gpu info >/dev/full; then exit 93; fi
gpu info >"$GPU_ERROR_DIR/info-after-error"
''',env=env)
    assert b'active=0 width=0 height=0' in (d/'info-after-error').read_bytes()
    assert (d/'preserved.rgba').read_bytes() == f.solid(8,8,(255,0,0))
    reasons = dict(device='cannot initialize GBM device', initialize='cannot initialize EGL',
                   context='surfaceless GLES2 context unavailable', buffer='linear renderable buffer unavailable',
                   export='linear renderable buffer unavailable', image='EGL cannot import render buffer',
                   framebuffer='render buffer is not framebuffer-complete')
    for stage, reason in reasons.items():
        # Each failed attempt is followed by successful reuse in the same shell.
        # Comparing FD counts catches leaks during partially initialized cleanup.
        output = peer.run(f'''before=(/proc/$$/fd/*)
for ((i=0;i<4;i++)); do
    gpu start 8 8 --headless
    export GPU_FIXTURE_FAIL={stage}
    if gpu shader "$GPU_ERROR_DIR/half.frag" 2>"$GPU_ERROR_DIR/error"; then exit 94; fi
    unset GPU_FIXTURE_FAIL
    gpu shader "$GPU_ERROR_DIR/half.frag"
    gpu clear ff0000
    gpu render 0
    gpu save "$GPU_ERROR_DIR/recovered.rgba" rgba
    gpu stop
done
after=(/proc/$$/fd/*)
[[ ${{#before[@]}} == ${{#after[@]}} ]]
''',env=env)
        assert reason in (d/'error').read_text(), (stage, (d/'error').read_text())
        assert (d/'recovered.rgba').read_bytes() == f.solid(8,8,(128,0,0)),stage
        print(stage, 'cleanup/retry ok', reason)
    state = peer.run('''gpu start 8 8 --headless
gpu clear ff0000
gpu shader "$GPU_ERROR_DIR/half.frag"
gpu render 0
for fragment in invalid link; do
    if gpu shader "$GPU_ERROR_DIR/$fragment.frag"; then exit 95; fi
    gpu render 0
    gpu save "$GPU_ERROR_DIR/$fragment.rgba" rgba
done
export GPU_FIXTURE_FAIL=draw
if gpu render 0; then exit 96; fi
unset GPU_FIXTURE_FAIL
gpu render 0
export GPU_FIXTURE_FAIL=read
if gpu save "$GPU_ERROR_DIR/read-error.rgba" rgba; then exit 97; fi
unset GPU_FIXTURE_FAIL
gpu save "$GPU_ERROR_DIR/retry.rgba" rgba
gpu shader off
gpu pixel 0 0 00ff00
gpu save "$GPU_ERROR_DIR/off.rgba" rgba
gpu info
gpu stop
''',env=env)
    assert b'uploads=2' in state and b'readbacks=3' in state, state
    for name in ('invalid','link','retry'):
        assert (d/(name+'.rgba')).read_bytes() == f.solid(8,8,(128,0,0)),name
    assert (d/'off.rgba').read_bytes() == f.solid(1,1,(0,255,0)) + f.solid(63,1,(128,0,0))
    print('shader compile/link/draw/read failure and shader off: preserved pixels')
print(f'sol-gpu-errors: {peer.checks} shell sessions passed, empty PATH')
