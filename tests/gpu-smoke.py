#!/usr/bin/env python3
"""Check canvas pixels with an independent Kitty protocol peer on a PTY.
GPU_MODULE selects a runtime module. GPU_TEST_DEVICE enables real driver tests.
"""
import array
import base64
import fcntl
import mmap
import os
from pathlib import Path
import pty
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time

binary = str(Path(sys.argv[1] if len(sys.argv)>1 else 'out/bash').resolve())
checks = 0
prefix = 'if [[ -n ${GPU_MODULE:-} ]]; then enable -f "$GPU_MODULE" gpu; fi\nPATH=\n'

def environment(extra=None):
    env = {**os.environ, **(extra or {})}
    env = {key:value for key,value in env.items() if value is not None}
    if env.get('GPU_ASAN_LIB'):
        env['LD_PRELOAD'] = env['GPU_ASAN_LIB']
        env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    return env

def run(script, rc=0, env=None):
    global checks
    p = subprocess.run([binary,'-e','-o','pipefail','-c',prefix+script],
                       capture_output=True,timeout=20,env=environment(env))
    assert p.returncode == rc, (script,p.returncode,p.stdout,p.stderr)
    assert b'runtime error:' not in p.stderr and b'AddressSanitizer' not in p.stderr,p.stderr
    checks += 1
    return p.stdout

class Terminal:
    def __init__(self, *, shm=True, respond=True, retain=False, keys=b'', resize=None,
                 dmabuf_ack=True, partial_reply=False, input_only=False, slow_keys=False,
                 late_shm=False, inline=True, tmux=False):
        self.master,self.slave = pty.openpty()
        self.tty = os.ttyname(self.slave)
        fcntl.ioctl(self.slave,termios.TIOCSWINSZ,struct.pack('HHHH',30,100,800,480))
        self.saved = termios.tcgetattr(self.slave)
        self.buffer = b''
        self.stream = bytearray()
        self.images = {}
        self.transfer = None
        self.last_frame = self.last_size = None
        self.shm_names = []
        self.counts = dict(full=0,patch=0,compose=0,query=0,dmabuf=0)
        self.shm,self.respond,self.retain = shm,respond,retain
        self.keys,self.resize = keys,resize
        self.dmabuf_ack,self.partial_reply = dmabuf_ack,partial_reply
        self.input_only = input_only
        self.slow_keys,self.late_shm,self.inline,self.tmux = slow_keys,late_shm,inline,tmux
        self.late_reply = b''
        self.outer = b''
        self.dmabuf_records = []
        self.held_fds = []
        self.held_frames = []

    def receive(self,data):
        self.stream.extend(data)
        if self.tmux:
            self.outer += data
            while True:
                start = self.outer.find(b'\x1bPtmux;')
                if start < 0:
                    self.outer = self.outer[-6:]
                    return
                at = start+7
                decoded = bytearray()
                complete = False
                while at < len(self.outer):
                    if self.outer[at] != 27:
                        decoded.append(self.outer[at]); at += 1
                    elif at+1 == len(self.outer): break
                    elif self.outer[at+1] == 27:
                        decoded.append(27); at += 2
                    else:
                        assert self.outer[at+1] == 92,'invalid tmux escaping'
                        self.outer = self.outer[at+2:]
                        self.parse(bytes(decoded))
                        complete = True
                        break
                if not complete: return
        self.parse(data)

    def parse(self,data):
        self.buffer += data
        while True:
            start = self.buffer.find(b'\x1b_G')
            if start < 0:
                self.buffer = self.buffer[-2:]
                return
            end = self.buffer.find(b'\x1b\\',start)
            if end < 0:
                self.buffer = self.buffer[start:]
                return
            header,_,payload = self.buffer[start+3:end].partition(b';')
            self.buffer = self.buffer[end+2:]
            control = dict(part.split(b'=',1) for part in header.split(b',') if part)
            assert len(payload) <= 4096
            decoded = base64.b64decode(payload,validate=True)
            if self.transfer:
                original,pixels = self.transfer
                assert set(control) <= {b'm',b'q',b'a'},control
                if original.get(b'a') == b'f': assert control.get(b'a') == b'f'
                pixels.extend(decoded)
                if control.get(b'm') == b'1': continue
                self.transfer = None
                self.command(original,bytes(pixels))
            elif control.get(b'm') == b'1': self.transfer = control,bytearray(decoded)
            else: self.command(control,decoded)

    def command(self,c,payload):
        action = c.get(b'a',b't')
        image_id = int(c.get(b'i',b'0'))
        if action == b'q':
            self.counts['query'] += 1
            if not self.respond: return
            success = self.inline
            if c.get(b't') == b's':
                path = Path('/dev/shm')/payload.decode().lstrip('/')
                self.shm_names.append(path)
                assert path.stat().st_mode & 0o777 == 0o600
                assert path.read_bytes() == b'\x00\x00\x00\xff'
                success = self.shm
                if success: path.unlink()
            if self.resize:
                fcntl.ioctl(self.slave,termios.TIOCSWINSZ,struct.pack('HHHH',*self.resize))
                self.resize = None
            response = b'\x1b_Gi='+str(image_id).encode()+b';'+(b'OK' if success else b'ENOENT')+b'\x1b\\'
            if c.get(b't') == b's' and self.late_shm:
                self.late_reply = response
                return
            if self.late_reply:
                os.write(self.master,self.late_reply)
                self.late_reply = b''
            if self.keys and not self.input_only:
                os.write(self.master,self.keys)
                self.keys = b''
            if self.partial_reply:
                os.write(self.master,response[:5]); time.sleep(0.01)
                os.write(self.master,response[5:])
            else: os.write(self.master,response)
            return
        if action == b'g':
            self.counts['dmabuf'] += 1
            path = Path(payload.decode())
            assert path.stat().st_mode & 0o777 == 0o600
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
                peer.settimeout(2); peer.connect(str(path))
                record,ancillary,flags,_ = peer.recvmsg(40,socket.CMSG_SPACE(4))
                assert not flags
                values = struct.unpack('=10I',record)
                self.dmabuf_records.append(values)
                magic,version,w,h,stride,offset,fourcc,hi,lo,transform = values
                assert (magic,version,fourcc,transform) == (0x4b444d41,2,0x34325258,6)
                assert stride >= w*4
                fds = array.array('i')
                for level,kind,raw in ancillary:
                    assert level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS
                    fds.frombytes(raw)
                assert len(fds) == 1
                fd = fds[0]
                try:
                    if self.dmabuf_ack:
                        # CPU access independently checks the exported pixels.
                        fcntl.ioctl(fd,0x40086200,struct.pack('Q',1))
                        with mmap.mmap(fd,offset+stride*h,access=mmap.ACCESS_READ) as buf:
                            rgba = bytearray()
                            for y in reversed(range(h)):
                                row = buf[offset+y*stride:offset+y*stride+w*4]
                                for x in range(w):
                                    b,g,r,_ = row[x*4:x*4+4]
                                    rgba.extend((r,g,b,255))
                        fcntl.ioctl(fd,0x40086200,struct.pack('Q',5))
                        self.images[image_id] = w,h,rgba
                    if self.dmabuf_ack is None:
                        self.held_fds.append((os.dup(fd),values))
                    else: peer.send(bytes([int(self.dmabuf_ack)]))
                finally: os.close(fd)
            return
        if action in (b't',b'T',b'f'):
            assert c.get(b'f') == b'32'
            w,h = int(c[b's']),int(c[b'v'])
            if c.get(b't') == b's':
                path = Path('/dev/shm')/payload.decode().lstrip('/')
                self.shm_names.append(path)
                assert path.stat().st_mode & 0o777 == 0o600
                payload = path.read_bytes()
                if not self.retain: path.unlink()
            assert len(payload) == w*h*4,(len(payload),w,h)
            if action == b'f':
                self.counts['patch'] += 1
                assert c.get(b'r') == b'1' and c.get(b'X') == b'1'
                fw,fh,pixels = self.images[image_id]
                x,y = int(c[b'x']),int(c[b'y'])
                assert 0 <= x <= fw-w and 0 <= y <= fh-h
                for row in range(h):
                    at = ((y+row)*fw+x)*4
                    pixels[at:at+w*4] = payload[row*w*4:(row+1)*w*4]
                self.snapshot(image_id)
            else:
                self.counts['full'] += 1
                self.images[image_id] = w,h,bytearray(payload)
            return
        if action == b'p':
            assert c.get(b'C') == b'1'
            self.snapshot(image_id)
        elif action == b'd': self.images.pop(image_id,None)
        elif action == b'c':
            self.counts['compose'] += 1
            assert c.get(b'N') == b'2' and c.get(b'C') == b'1'
            fw,fh,pixels = self.images[image_id]
            before = bytes(pixels)
            x,y,dx,dy,w,h = (int(c[key]) for key in (b'X',b'Y',b'x',b'y',b'w',b'h'))
            for row in range(h):
                start,dest = ((y+row)*fw+x)*4,((dy+row)*fw+dx)*4
                pixels[dest:dest+w*4] = before[start:start+w*4]
            self.snapshot(image_id)
        else: raise AssertionError(c)

    def snapshot(self,image_id):
        w,h,pixels = self.images[image_id]
        self.last_frame,self.last_size = bytes(pixels),(w,h)

    def run(self,script,*,rc=0,env=None,controlling=False,signal_input=False):
        global checks
        child_env = environment({'GPU_TEST_TTY':self.tty,'TERM':'xterm-256color',
                                 'TERM_PROGRAM':None,'XTERM_VERSION':None,'TMUX':None,
                                 'SSH_CONNECTION':None,'SSH_TTY':None,**(env or {})})
        def acquire_tty():
            os.setsid()
            fcntl.ioctl(0,termios.TIOCSCTTY,0)
        p = subprocess.Popen([binary,'-e','-o','pipefail','-c',prefix+script],
                             stdin=self.slave if controlling else subprocess.DEVNULL,
                             preexec_fn=acquire_tty if controlling else None,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=child_env)
        deadline = time.monotonic()+20
        try:
            while p.poll() is None:
                assert time.monotonic()<deadline,'terminal test timed out'
                if signal_input and not (termios.tcgetattr(self.slave)[3] & termios.ISIG):
                    p.send_signal(signal.SIGTERM)
                    signal_input = False
                if self.keys and self.input_only and not (termios.tcgetattr(self.slave)[3] & termios.ISIG):
                    os.write(self.master,self.keys[:1] if self.slow_keys else self.keys)
                    self.keys = self.keys[1:] if self.slow_keys else b''
                if select.select([self.master],[],[],0.005 if self.slow_keys else 0.02)[0]:
                    self.receive(os.read(self.master,65536))
            while select.select([self.master],[],[],0)[0]: self.receive(os.read(self.master,65536))
            stdout,stderr = p.communicate(timeout=1)
            self.stderr = stderr
            assert p.returncode == rc,(p.returncode,stdout,stderr,script)
            assert b'runtime error:' not in stderr and b'AddressSanitizer' not in stderr,stderr
            assert self.transfer is None
            assert termios.tcgetattr(self.slave) == self.saved,'terminal settings leaked'
            assert not self.images,'session image survived cleanup'
            assert not any(path.exists() for path in self.shm_names),'shared memory survived cleanup'
            for fd,record in self.held_fds:
                _,_,w,h,stride,offset,_,_,_,_ = record
                fcntl.ioctl(fd,0x40086200,struct.pack('Q',1))
                with mmap.mmap(fd,offset+stride*h,access=mmap.ACCESS_READ) as buf:
                    self.held_frames.append(bytes(buf[offset:offset+stride*h]))
                fcntl.ioctl(fd,0x40086200,struct.pack('Q',5))
            checks += 1
            return stdout
        finally:
            if p.poll() is None: p.kill(); p.wait()
            os.close(self.master); os.close(self.slave)
            for path in self.shm_names: path.unlink(missing_ok=True)
            for fd,_ in self.held_fds: os.close(fd)

def main():
    with tempfile.TemporaryDirectory(prefix='bashos-gpu-tests-') as tmp:
        d = Path(tmp)
        env = {'GPU_TEST_DIR':tmp}
        run('gpu --help'); run('gpu stop; gpu stop'); run('gpu pixel 1 1 ff0000',rc=1)
        for args in ('0 1','10000 10000','1 nope','4 4 --transport wrong','4 4 --headless --fullscreen','4 4 --device'):
            run('gpu start '+args,rc=2)
        run('gpu start 4 4 --headless; gpu start 4 4 --headless',rc=1)
        run('gpu start 4 4 --headless; gpu present',rc=1)
        run('gpu start 4 4 --headless; gpu clear abc',rc=2)
        run('gpu start 4 4 --headless; gpu clear +00000',rc=2)
        for args in ('rect 0 0 -1 2 ff0000','plot ff0000 1 2 3','render nan','present 0 0 9 9','text 0 0 ff0000 hello 0'):
            run('gpu start 4 4 --headless; gpu '+args,rc=2)
        out = run('''gpu start 16 12 --headless
    gpu clear 102030
    gpu rect -2 -2 6 6 ff0000
    gpu pixel 15 11 00ff00
    gpu pixel 1000 -1000 ffffff
    gpu save "$GPU_TEST_DIR/pixels.rgba" rgba
    gpu save "$GPU_TEST_DIR/pixels.ppm"
    gpu info
    gpu stop
    ''',env=env)
        expected = bytearray(bytes((0x10,0x20,0x30,255))*(16*12))
        for y in range(4):
            for x in range(4): expected[(y*16+x)*4:(y*16+x+1)*4] = bytes((255,0,0,255))
        expected[-4:] = bytes((0,255,0,255))
        assert (d/'pixels.rgba').read_bytes() == expected
        assert b'width=16 height=12' in out
        run('''gpu start 16 12 --headless
    gpu load "$GPU_TEST_DIR/pixels.ppm"
    gpu save "$GPU_TEST_DIR/loaded.rgba" rgba
    gpu clear 000000
    gpu load-rgba "$GPU_TEST_DIR/pixels.rgba"
    gpu save "$GPU_TEST_DIR/raw.rgba" rgba
    gpu resize 20 14
    gpu save "$GPU_TEST_DIR/resized.rgba" rgba
    gpu stop
    ''',env=env)
        assert (d/'loaded.rgba').read_bytes() == expected == (d/'raw.rgba').read_bytes()
        resized = (d/'resized.rgba').read_bytes()
        assert len(resized) == 20*14*4 and resized[:16*4] == expected[:16*4]
        (d/'truncated.ppm').write_bytes(b'P6\n2 2\n255\n\x00')
        (d/'oversize.ppm').write_bytes(b'P6\n10000 10000\n255\n')
        (d/'trailing.rgba').write_bytes(bytes(16*12*4+1))
        for command in ('load truncated.ppm','load oversize.ppm','load-rgba trailing.rgba'):
            name,file = command.split()
            run(f'gpu start 16 12 --headless; gpu {name} "$GPU_TEST_DIR/{file}"',rc=1,env=env)
        run('''gpu start 96 64 --headless
    gpu clear 101018
    gpu line -10000 20 10000 20 00ff00 2
    gpu rect 4 4 70 48 336699 2
    gpu circle 40 30 14 ff9900
    gpu circle 40 30 18 ffffff 2
    gpu plot 88aaff 2 0 63 12 50 24 60 36 44 48 48
    gpu text 4 4 ffffff 'Bash $literal; text'
    gpu blit "$GPU_TEST_DIR/pixels.ppm" 80 52
    gpu save "$GPU_TEST_DIR/drawing.ppm"
    gpu stop
    ''',env=env)
        assert (d/'drawing.ppm').stat().st_size > 96*64*3
        run('''before=(/proc/$$/fd/*)
    for ((i=0;i<80;i++)); do gpu start 8 8 --headless; gpu resize 9 9; gpu stop; done
    after=(/proc/$$/fd/*)
    [[ ${#before[@]} == ${#after[@]} ]]
    gpu start 8 8 --headless
    if (gpu clear ff0000); then exit 9; fi
    gpu clear 00ff00
    gpu save "$GPU_TEST_DIR/parent.rgba" rgba
    ''',env=env)
        assert (d/'parent.rgba').read_bytes() == bytes((0,255,0,255))*64
        if os.environ.get('GPU_MODULE'):
            run('''for ((i=0;i<8;i++)); do
    enable -f "$GPU_MODULE" gpu
    gpu start 8 8 --headless
    enable -d gpu
    done
    enable -f "$GPU_MODULE" gpu
    gpu stop
    ''')
        start = 'gpu start 32 24 --tty "$GPU_TEST_TTY" '
        for transport in ('inline','shm','auto'):
            term = Terminal(partial_reply=True)
            term.run(start+f'--transport {transport}\n'+'''gpu clear 102030
    gpu present
    gpu rect 2 3 4 5 ff0000
    gpu present
    gpu present
    gpu save "$GPU_TEST_DIR/present.rgba" rgba
    gpu info
    gpu stop
    ''',env=env)
            assert term.last_frame == (d/'present.rgba').read_bytes()
            assert term.counts['full'] == 1 and term.counts['patch'] == 1,term.counts
        for fork in ('0','1'):
            for dx,dy in ((0,-2),(0,2),(2,0),(-2,0),(2,2),(-2,-2),(32,0)):
                term = Terminal()
                term.run(start+'--transport inline\n'+f'''gpu clear 102030
    gpu rect 4 5 10 11 aaccff
    gpu present
    gpu scroll {dx} {dy} 778899 1 1 30 22
    gpu pixel 15 15 ff0000
    gpu present
    gpu save "$GPU_TEST_DIR/scroll.rgba" rgba
    gpu stop
    ''',env={**env,'KITTY_KILIX_RENDERING':fork})
                assert term.last_frame == (d/'scroll.rgba').read_bytes(),(fork,dx,dy)
                assert term.counts['compose'] == int(fork=='1' and abs(dx)<30 and abs(dy)<22)
        term = Terminal()
        term.run(start+'--transport shm\n'+'''gpu clear 123456
gpu present
gpu pixel 3 4 ff0000
gpu pixel 28 21 00ff00
gpu present 3 4 1 1
gpu present
gpu scroll -3 0 333333
gpu scroll 0 4 555555
gpu present
gpu resize 40 30
gpu present
gpu save "$GPU_TEST_DIR/multiple.rgba" rgba
''',env={**env,'KITTY_KILIX_RENDERING':'1'})
        assert term.last_size == (40,30)
        assert term.last_frame == (d/'multiple.rgba').read_bytes()
        assert term.counts['patch'] >= 2 and term.counts['compose'] == 0
        term = Terminal(retain=True)
        term.run(start+'--transport shm\n'+'''for ((i=0;i<7;i++)); do
    if ((i%2)); then gpu clear ff0000; else gpu clear 00ff00; fi
    gpu present
    done
    gpu info
    ''')
        assert term.counts['full'] == 7 and len(term.shm_names) == 4
        term = Terminal(shm=False)
        out = term.run(start+'--transport auto\ngpu clear ff0000; gpu present; gpu info')
        assert b'transport=inline' in out and term.last_frame == bytes((255,0,0,255))*768
        term = Terminal(shm=False)
        term.run(start+'--transport shm',rc=1)
        assert b'terminal rejected the request, shm transport' in term.stderr
        assert b'--transport auto or --transport inline' in term.stderr
        term = Terminal(respond=False)
        before = time.monotonic()
        term.run(start+'--transport inline',rc=1)
        assert time.monotonic()-before < 3,'probe timeout is no longer bounded'
        assert b'no reply from terminal, inline transport' in term.stderr
        assert b'TERM=xterm-256color, TERM_PROGRAM=(unset)' in term.stderr
        assert b'Kitty graphics support' in term.stderr and b'--headless' in term.stderr
        assert b'Connection timed out' not in term.stderr
        term = Terminal(late_shm=True,inline=False)
        term.run(start+'--transport auto',rc=1)
        assert b'terminal rejected the request, inline transport' in term.stderr
        nested_env = {'TERM':'xterm','TERM_PROGRAM':'kitty','XTERM_VERSION':'XTerm(398)',
                      'KITTY_WINDOW_ID':'42','KITTY_KILIX_RENDERING':'1'}
        term = Terminal(respond=False)
        term.run(start+'--transport auto',rc=1,env=nested_env)
        assert term.counts['query'] == 2
        assert b'XTERM_VERSION is set' in term.stderr
        assert b'run directly in Kitty or Kilix' in term.stderr
        assert b'nested XTerm does not support Kitty graphics' in term.stderr
        for hints in (nested_env,{'TERM':'xterm-256color'},{'TERM':'dumb'},{'TERM':None}):
            term = Terminal()
            term.run('gpu start 4 4 --headless; gpu stop\n'+start+'--transport inline',env=hints)
            assert term.counts['query'] == 1 and not term.stderr
        term = Terminal(respond=False,tmux=True)
        term.run(start+'--transport auto',rc=1,env={'TMUX':'gpu-test'})
        assert term.counts['query'] == 1 and b'allow-passthrough' in term.stderr
        term = Terminal(respond=False)
        term.run(start+'--transport auto',rc=1,env={'SSH_CONNECTION':'gpu-test'})
        assert term.counts['query'] == 1 and b'the local terminal must support Kitty graphics' in term.stderr
        term = Terminal(respond=False)
        term.run(start+'--transport inline',rc=1,
                 env={'TERM':'bad\n\x1b]2;title\x07'+100*'x','TERM_PROGRAM':'bad\r\x1b[31m'})
        assert b'TERM=bad??]2;title?' in term.stderr and b'...' in term.stderr
        assert b'\x1b' not in term.stderr and b'\x07' not in term.stderr and b'\r' not in term.stderr
        assert term.stderr.count(b'\n') == 2 and len(term.stderr) < 512
        term = Terminal(tmux=True)
        term.run(start+'--transport inline\ngpu clear 123456; gpu present; gpu pixel 3 4 ff0000; gpu present',
                 env={'TMUX':'gpu-test'})
        assert term.counts['full'] == 1 and term.counts['patch'] == 1
        term = Terminal()
        out = term.run(start+'--transport dmabuf\ngpu clear 0000ff; gpu present; gpu info',
                       env={'BASHOS_GPU_GBM_LIB':'/nonexistent-bashos-gpu-library'})
        assert b'transport=shm' in out and b'fallbacks=1' in out
        assert term.last_frame == bytes((0,0,255,255))*768
        term = Terminal(keys=b'q\x1b[A\xc3\xa9\x1b[<0;10;12M')
        out = term.run(start+'--transport inline --fullscreen\n'+'''for ((i=0;i<4;i++)); do
    gpu input key 100
    printf '%s\n' "$key"
    done
    if gpu input key 5; then exit 9; fi
    [[ -z $key ]]
    gpu stop
    ''')
        assert out.splitlines() == [b'q',b'UP','é'.encode(),b'MOUSE:down:0:10:12'],out
        assert b'\x1b[?1049h' in term.stream and b'\x1b[?1049l' in term.stream
        control = Terminal(keys=b'\x03',input_only=True)
        out = control.run(start+'--transport inline\ngpu input key 500; printf "%s\\n" "$key"')
        assert out == b'CTRL-C\n',out
        term = Terminal(keys=b'\x1b[A\xc3\xa9\x1b',input_only=True,slow_keys=True)
        out = term.run(start+'--transport inline\nfor ((i=0;i<3;i++)); do gpu input key 500; printf "%s\\n" "$key"; done')
        assert out.splitlines() == [b'UP','é'.encode(),b'ESC'],out
        term = Terminal(keys=b'x',input_only=True)
        term.run(start+'--transport inline\nreadonly key=old; gpu input key 500',rc=1)
        term = Terminal(resize=(40,120,960,640))
        out = term.run(start+'--transport inline\ngpu input event 5; printf "%s\\n" "$event"; gpu size')
        assert out == b'RESIZE:120:40:960:640\n120 40 960 640\n',out
        term = Terminal()
        term.run(start+'--transport inline --fullscreen\ngpu clear ff0000; gpu present; exit 7',rc=7)
        assert b'\x1b[?1049l' in term.stream
        term = Terminal()
        term.run(start+'--transport shm --fullscreen\n'+'''trap 'gpu stop' EXIT
trap 'exit 143' TERM
gpu clear ff0000
gpu present
gpu input event 5000 || :
''',rc=143,signal_input=True)
        assert b'\x1b[?1049l' in term.stream
        term = Terminal()
        term.run('source examples/gpu-dashboard.sh 3',controlling=True)
        assert term.last_size == (800,480) and term.counts['full']+term.counts['patch'] >= 4
        if os.environ.get('GPU_MODULE'):
            term = Terminal()
            term.run(start+'--transport inline --fullscreen\ngpu present; enable -d gpu')
            assert b'\x1b[?1049l' in term.stream
        if os.environ.get('GPU_TEST_DEVICE'):
            shader = d/'shader.frag'
            shader.write_text('precision mediump float; varying vec2 uv; uniform float time; '
                              'void main(){gl_FragColor=vec4(uv.x,uv.y,time,1.0);}')
            gpu_env = {**env,'BASHOS_GPU_DEVICE':os.environ['GPU_TEST_DEVICE']}
            run('''gpu start 32 24 --headless
    gpu shader "$GPU_TEST_DIR/shader.frag"
    gpu render 0.25
    gpu save "$GPU_TEST_DIR/shader.rgba" rgba
    gpu info
    gpu stop
    ''',env=gpu_env)
            reference = (d/'shader.rgba').read_bytes()
            for y in range(24):
                for x in range(32):
                    pixel = reference[(y*32+x)*4:(y*32+x+1)*4]
                    expected_pixel = (round((x+0.5)/32*255),round((y+0.5)/24*255),64,255)
                    assert all(abs(a-b)<=1 for a,b in zip(pixel,expected_pixel)),(x,y,pixel,expected_pixel)
            for ack in (False,True):
                session = d/'session'
                session.mkdir(mode=0o700,exist_ok=True)
                term = Terminal(dmabuf_ack=ack)
                out = term.run(start+'--transport dmabuf\n'+'''gpu shader "$GPU_TEST_DIR/shader.frag"
    gpu render 0.25
    gpu present
    gpu info
    gpu stop
    ''',env={**gpu_env,'KILIX_SESSION_HOME':str(session)})
                assert term.last_frame == reference
                assert term.counts['dmabuf'] == 1 and not list(session.iterdir())
                assert (b'readbacks=0' if ack else b'readbacks=1') in out,out
            term = Terminal(dmabuf_ack=None)
            term.run(start+'--transport dmabuf\n'+'''gpu shader "$GPU_TEST_DIR/shader.frag"
gpu render 0.25
gpu present
gpu render 0.75
gpu present
''',env={**gpu_env,'KILIX_SESSION_HOME':str(session)})
            assert term.last_frame[2] in (191,192)
            # A receiver may retain its FD after abandoning the ACK channel.
            # Later renders must use a new allocation, leaving its pixels intact.
            assert len(term.held_frames) == 1 and term.held_frames[0][0] in (63,64)
            shader.write_text('precision mediump float; varying vec2 uv; uniform sampler2D canvas; '
                              'void main(){gl_FragColor=vec4(texture2D(canvas,uv).rgb*0.5,1.0);}')
            term = Terminal()
            out = term.run(start+'--transport shm\n'+'''gpu clear ff0000
    gpu shader "$GPU_TEST_DIR/shader.frag"
    gpu render 0
    gpu present
    gpu render 0
    gpu present
gpu save "$GPU_TEST_DIR/consistent.rgba" rgba
gpu info
''',env=gpu_env)
            assert term.last_frame == (d/'consistent.rgba').read_bytes()
            assert term.last_frame[0] in (127,128) and term.last_frame[1:4] == b'\x00\x00\xff'
            assert b'uploads=1' in out,out
            run('''gpu start 32 24 --headless
gpu clear ff0000
gpu shader "$GPU_TEST_DIR/shader.frag"
gpu render 0
for command in 'pixel no 0 000000' 'plot ffffff 1 0 0 no 1' 'rect 0 0 -1 4 ffffff' 'unknown' 'circle 0 0 -1 ffffff'; do
read -ra words <<<"$command"
if gpu "${words[@]}"; then exit 9; fi
done
if gpu load "$GPU_TEST_DIR/truncated.ppm"; then exit 9; fi
if gpu load-rgba "$GPU_TEST_DIR/trailing.rgba"; then exit 9; fi
gpu render 0
gpu save "$GPU_TEST_DIR/invalid-preserved.rgba" rgba
''',env=gpu_env)
            preserved = (d/'invalid-preserved.rgba').read_bytes()
            assert preserved[0] in (127,128) and preserved[1:4] == b'\x00\x00\xff'
            run('''gpu start 32 24 --headless
gpu clear ff0000
gpu shader "$GPU_TEST_DIR/shader.frag"
gpu render 0
gpu pixel 0 0 00ff00
gpu render 0
gpu save "$GPU_TEST_DIR/overlay.rgba" rgba
gpu resize 40 30
gpu clear 0000ff
gpu render 0
gpu save "$GPU_TEST_DIR/resize-shader.rgba" rgba
gpu shader off
gpu stop
''',env=gpu_env)
            overlay = (d/'overlay.rgba').read_bytes()
            assert overlay[:4] == bytes((0,128,0,255)) and overlay[4] == 64
            assert (d/'resize-shader.rgba').read_bytes() == bytes((0,0,128,255))*1200
            term = Terminal()
            term.run('source examples/gpu-shader.sh 3 shm',env=gpu_env,controlling=True)
            assert term.counts['full'] == 3 and term.last_size == (800,480)
            run('''gpu start 8 8 --headless
gpu shader "$GPU_TEST_DIR/shader.frag"
gpu stop
before=(/proc/$$/fd/*)
for ((i=0;i<5;i++)); do
gpu start 8 8 --headless
gpu shader "$GPU_TEST_DIR/shader.frag"
gpu render 0
gpu stop
done
after=(/proc/$$/fd/*)
[[ ${#before[@]} == ${#after[@]} ]]
''',env=gpu_env)
            if os.environ.get('GPU_MODULE'):
                run('''gpu start 8 8 --headless
gpu shader "$GPU_TEST_DIR/shader.frag"
gpu render 0
enable -d gpu
enable -f "$GPU_MODULE" gpu
gpu start 8 8 --headless
gpu shader "$GPU_TEST_DIR/shader.frag"
gpu render 0
gpu stop
''',env=gpu_env)
        else: print('SKIP native GPU: set GPU_TEST_DEVICE for shader/DMA-BUF checks')
    print(f'gpu-smoke: {checks} checks passed')

if __name__ == '__main__':
    main()
