#!/usr/bin/env python3
"""Live graphics checks in an isolated Kilix process, using its framebuffer.

Set KILIX_TEST_BINARY to the fork's kitty executable. Needs DISPLAY and Pillow.
The test connects only to the private control socket of the process it starts.
"""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from PIL import Image

root = Path(__file__).resolve().parents[1]
binary = str(Path(sys.argv[1] if len(sys.argv)>1 else root/'out/bash').resolve())
kitty = os.environ.get('KILIX_TEST_BINARY')
if not kitty or not os.environ.get('DISPLAY'):
    sys.exit('Set KILIX_TEST_BINARY and DISPLAY for this optional live check.')
with tempfile.TemporaryDirectory(prefix='bashos-gpu-live-') as tmp:
    d = Path(tmp)
    (d/'session').mkdir(mode=0o700)
    (d/'copy.frag').write_text('precision mediump float; varying vec2 uv; uniform sampler2D canvas; '
                              'void main(){gl_FragColor=texture2D(canvas,uv);}')
    capture_helper = d/'capture.py'
    capture_helper.write_text("""
from pathlib import Path
from kittens.tui.handler import result_handler
from kitty.fast_data_types import request_callback_with_thumbnail, png_from_32bit_rgba_data

def main(args):
    pass

@result_handler(no_ui=True)
def handle_result(args, data, target_window_id, boss):
    window = boss.window_id_map[target_window_id]
    def capture(os_window_id, window_id, pixels, width, height):
        target = Path(args[1])
        temporary = target.with_suffix('.partial')
        # The terminal's thumbnail shader already produces top-down rows.
        temporary.write_bytes(png_from_32bit_rgba_data(pixels, width, height, False))
        temporary.replace(target)
    boss.gpu_test_capture = capture
    request_callback_with_thumbnail('gpu_test_capture', window.os_window_id, window.id, False, 1.0, 10000)
    return 'scheduled'
""")
    base_env = {k:v for k,v in os.environ.items() if k not in ('TMUX','SSH_CONNECTION')
                and not k.startswith(('KITTY_','KILIX_','GPU_TERMINAL_'))}
    base_env.update(GPU_LIVE_DIR=tmp, KILIX_SESSION_HOME=str(d/'session'),
                    KITTY_KILIX_RENDERING='1')
    script = '''
set -euo pipefail
if [[ -n ${GPU_MODULE:-} ]]; then enable -f "$GPU_MODULE" gpu; fi
trap 'gpu stop' EXIT
trap 'exit 143' TERM
gpu start 320 240 --fullscreen --transport "$GPU_LIVE_TRANSPORT"
gpu clear ff0000
gpu rect 160 0 160 120 00ff00
gpu rect 0 120 160 120 0000ff
gpu rect 160 120 160 120 ffff00
if [[ $GPU_LIVE_TRANSPORT == dmabuf ]]; then
    gpu shader "$GPU_LIVE_DIR/copy.frag"
    gpu render 0
fi
gpu present
gpu info >"$GPU_LIVE_DIR/info"
printf ready >"$GPU_LIVE_DIR/ready"
while [[ ! -e $GPU_LIVE_DIR/update ]]; do gpu input event 50 || :; done
gpu pixel 8 16 ff00ff
gpu present
gpu scroll -8 0 111827
gpu present
gpu save "$GPU_LIVE_DIR/reference.ppm"
gpu info >"$GPU_LIVE_DIR/updated-info"
printf ready >"$GPU_LIVE_DIR/updated"
while [[ ! -e $GPU_LIVE_DIR/refresh ]]; do gpu input event 50 || :; done
gpu present 0 0 320 240
printf ready >"$GPU_LIVE_DIR/refreshed"
while [[ ! -e $GPU_LIVE_DIR/finish ]]; do gpu input event 50 || :; done
gpu stop
printf done >"$GPU_LIVE_DIR/done"
'''
    for transport, gate in [('inline',False),('shm',False),('dmabuf',False),('dmabuf',True)]:
        label = transport+('-egl' if gate else '')
        for name in ('ready','finish','info','done','update','updated','updated-info','refresh','refreshed'):
            (d/name).unlink(missing_ok=True)
        for path in d.glob('control*'): path.unlink()
        env = {**base_env, 'GPU_LIVE_TRANSPORT':transport}
        if gate: env['KILIX_GPU_DMABUF_IMPORT']='1'
        with (d/'terminal.log').open('wb') as log:
            p = subprocess.Popen([kitty,'--config','NONE','--title','bash-os graphics validation',
                                  '--class','bash-os-gpu-test','--listen-on','unix:'+str(d/'control'),
                                  '-o','allow_remote_control=socket-only',
                                  '-o','initial_window_width=480','-o','initial_window_height=320',
                                  '-o','remember_window_size=no','-o','background_opacity=1',
                                  '-o','window_padding_width=0','-o','window_margin_width=0',
                                  '-o','confirm_os_window_close=0',binary,'-c',script],
                                 env=env,stdout=log,stderr=log,start_new_session=True)
            def wait_file(name):
                deadline = time.monotonic()+15
                while not (d/name).exists():
                    assert p.poll() is None and time.monotonic()<deadline, (
                        label,name,p.poll(),(d/'terminal.log').read_text())
                    time.sleep(0.05)

            def snapshot(suffix=''):
                shot = root/'out'/('gpu-live-'+label+suffix+'.png')
                shot.unlink(missing_ok=True)
                control = next(path for path in d.glob('control*') if stat.S_ISSOCK(path.stat().st_mode))
                result = subprocess.run([kitty,'@','--to','unix:'+str(control),'kitten',
                                         str(capture_helper),str(shot)],env=base_env,
                                        capture_output=True,timeout=10)
                assert result.returncode == 0,(result.stdout,result.stderr)
                deadline = time.monotonic()+10
                while not shot.exists():
                    assert p.poll() is None and time.monotonic()<deadline,(label,'capture timed out',(d/'terminal.log').read_text())
                    time.sleep(0.05)
                return Image.open(shot).convert('RGB')

            try:
                wait_file('ready')
                image = snapshot()
                colors = [(255,0,0),(0,255,0),(0,0,255),(255,255,0)]
                pixels = image.load()
                red = [(x,y) for y in range(image.height) for x in range(image.width) if pixels[x,y] == colors[0]]
                assert red,(label,'no red quadrant')
                ox,oy = max(0,min(x for x,y in red)-1),max(0,min(y for x,y in red)-1)
                assert ox+320 <= image.width and oy+240 <= image.height,(label,'frame bounds',ox,oy)
                # The terminal's capture shader filters a quarter pixel around
                # each sample even at scale 1. Check uniform interiors here;
                # incremental/full redraw equality below includes every pixel.
                for y in range(2,238):
                    if 118 <= y <= 121: continue
                    for x in range(2,318):
                        if 158 <= x <= 161: continue
                        assert pixels[ox+x,oy+y] == colors[(y//120)*2+x//160],(label,x,y)
                info = (d/'info').read_text()
                expected = 'dmabuf' if gate else 'shm' if transport=='dmabuf' else transport
                assert 'transport='+expected in info,(label,info)
                if gate: assert 'readbacks=0 uploads=1' in info,info
                print(label+': pixels and transport verified; '+info.splitlines()[0])
                (d/'update').touch()
                wait_file('updated')
                actual = snapshot('-updated')
                (d/'refresh').touch()
                wait_file('refreshed')
                reference = snapshot('-full')
                assert actual.tobytes() == reference.tobytes(),(label,'updated pixels differ')
                updated_info = (d/'updated-info').read_text()
                if expected != 'dmabuf':
                    assert 'composes=1' in updated_info and 'patches=2' in updated_info,updated_info
                print(label+': patch and scroll pixels verified')
                (d/'finish').touch()
                wait_file('done')
                assert not list((d/'session').glob('gpu-*'))
            finally:
                (root/'out'/('gpu-live-'+label+'.log')).write_text((d/'terminal.log').read_text())
                if (d/'info').exists():
                    (root/'out'/('gpu-live-'+label+'.info')).write_text((d/'info').read_text())
                if p.poll() is None: p.terminate()
                try: p.wait(timeout=5)
                except subprocess.TimeoutExpired: p.kill(); p.wait()
