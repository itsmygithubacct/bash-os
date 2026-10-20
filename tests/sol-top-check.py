#!/usr/bin/env python3
"""Deterministic production-top checks. Build the proc shim separately under a build gate."""
import argparse
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import pwd
import re
import select
import shlex
import signal
import struct
import subprocess
import tempfile
import termios
import time


def stat(pid, ticks, rss, start=100, comm=None):
    # Linux stat fields 3..24; explicit positions, independent of C sscanf.
    fields = ['S', '1', '1', '1', '0', '0', '0', '0', '0', '0', '0',
              str(ticks), '0', '0', '0', '20', '0', '1', '0', str(start),
              '1048576', str(rss)]
    return f'{pid} ({comm or "task"}) ' + ' '.join(fields) + '\n'


def fixture(root, count=None):
    root = Path(root)
    uid = os.getuid()
    for frame in (0, 1):
        d = root / str(frame)
        d.mkdir(parents=True)
        idle = 800 + (max(0, count*5-200) if count is not None else 0)
        (d/'stat').write_text('cpu ' + ('100 20 80 700 50 10 20 20 25 5' if frame == 0
                             else f'150 20 100 {idle} 60 10 30 30 45 5') + '\ncpu0 1 1 1 1\n')
        (d/'meminfo').write_text('MemTotal: 100000 kB\nMemFree: 999 kB\nMemAvailable: 40000 kB\nSwapTotal: 20000 kB\nSwapFree: 15000 kB\n')
        (d/'loadavg').write_text(f'{frame+1}.00 0.50 0.25 1/999 999\n')
        if count is None:
            records = ([(101,15,10,100,'alpha'), (202,20,50,100,'beta'),
                        (303,20,50,100,'gamma'), (404,10,5,100,'reused'),
                        (505,10,1,100,'gone'), (707,100,1,100,'reset'),
                        (909,0,1,100,'odd) name')]
                       if frame == 0 else
                       [(101,35,25,100,'alpha'), (202,60,50,100,'beta'),
                        (303,60,50,100,'gamma'), (404,110,5,200,'reused'),
                        (606,0,2,300,'new'), (707,90,1,100,'reset'),
                        (909,0,1,100,'odd) name')])
        else:
            records = [(1000+i, i+frame*(i%5), i%100+1, 100, f'proc{i:05}') for i in range(count)]
        for pid, ticks, rss, start, comm in records:
            p = d/str(pid); p.mkdir()
            (p/'stat').write_text(stat(pid,ticks,rss,start,comm))
            (p/'status').write_text(f'Name:\ttask\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
            (p/'cmdline').write_bytes(b'' if pid == 909 else comm.encode()+b'\0--fixture\0')
        if count is None:
            (d/'808').mkdir(); (d/'808/stat').write_text('808 (short) S 1 0 0 0 0 0 0 0 0 0 10 0\n')
            (d/'999').mkdir()  # vanished before stat could be opened
    switch(root, 0)


def switch(root, frame):
    root = Path(root)
    (root/'next').symlink_to(str(frame))
    (root/'next').replace(root/'current')


def digest(root):
    h = hashlib.sha256()
    for p in sorted(Path(root).rglob('*')):
        if p.is_file() and not p.is_symlink():
            h.update(str(p.relative_to(root)).encode()+b'\0'+p.read_bytes())
    return h.hexdigest()


def row(pid, cpu, rss, cmd):
    return f'{pid:5d} {pwd.getpwuid(os.getuid()).pw_name[:8]:8s} {cpu:5.1f} {rss * (os.sysconf("SC_PAGE_SIZE") // 1024):6d} S {cmd}'


def expected(sort='cpu', cap=0, count=None):
    if count is None:
        data = [(101,10.,25,'alpha --fixture',35), (202,20.,50,'beta --fixture',60),
                (303,20.,50,'gamma --fixture',60), (404,0.,5,'reused --fixture',110),
                (606,0.,2,'new --fixture',0), (707,0.,1,'reset --fixture',90),
                (909,0.,1,'[odd) name]',0)]
    else:
        data = [(1000+i, (i%5)*100/max(200,count*5), i%100+1, f'proc{i:05} --fixture', i+i%5) for i in range(count)]
    keys = {'cpu':lambda p:(-p[1],-p[0]), 'mem':lambda p:(-p[2],-p[0]),
            'pid':lambda p:p[0], 'time':lambda p:(-p[4],-p[0])}
    data.sort(key=keys[sort])
    lines = [f'top - load 2.00 0.50 0.25  procs {len(data)}  sort {sort.upper()}  every 0s',
             'Mem: 100000 kB total, 60000 kB used, 40000 kB avail',
             'Swap: 20000 kB total, 5000 kB used, 15000 kB free',
             '(--once snapshot)', '  PID USER     %CPU    RSS S COMMAND']
    lines += [row(*p[:4]) for p in data[:cap or None]]
    return ('\n'.join(lines)+'\n').encode()


class Runner:
    def __init__(self, binary, shim, root, loader=None, asan=None):
        self.binary = str(Path(binary).resolve())
        self.env = {**os.environ, 'LC_ALL':'C', 'TERM':'xterm-256color', 'COLORTERM':'truecolor',
                    'TOP_FIXTURE':str(root), 'TOP_FIXTURE_MODE':'pair',
                    'TOP_MUTATION_LOG':str(Path(root)/'mutations'),
                    'LD_PRELOAD':':'.join(filter(None,[asan,str(Path(shim).resolve())]))}
        if loader:
            self.env.update(BASH_ENV=str(Path(loader).resolve()),
                            ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                            UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    def command(self, script):
        return [self.binary,'--noprofile','--norc','-c','PATH=; '+script]
    def run(self, script, rc=0):
        p = subprocess.run(self.command(script), capture_output=True, env=self.env,
                           start_new_session=True, timeout=20)
        assert p.returncode == rc, (script,p.returncode,p.stdout,p.stderr)
        assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
        return p.stdout


class Screen:
    """Small independent ECMA-48 cell oracle for the helper's emitted subset."""
    def __init__(self, rows=12, cols=100):
        self.resize(rows,cols); self.pending=b''
    def resize(self, rows, cols):
        self.rows=rows; self.cols=cols; self.cells=[[' ']*cols for _ in range(rows)]; self.y=self.x=0
    def feed(self, data):
        data=self.pending+data; self.pending=b''; i=0
        while i < len(data):
            if data[i:i+2]==b'\x1b[':
                m=re.match(rb'\x1b\[([0-9;?]*)([A-Za-z])',data[i:])
                if not m: self.pending=data[i:]; break
                raw,op=m.groups(); i+=m.end()
                vals=[int(v or 0) for v in raw.lstrip(b'?').split(b';')]
                if op in (b'H',b'f'):
                    self.y=(vals[0] or 1)-1; self.x=(vals[1] if len(vals)>1 else 1)-1
                elif op==b'J' and vals[0]==2:
                    self.cells=[[' ']*self.cols for _ in range(self.rows)]
                elif op==b'K':
                    if 0 <= self.y < self.rows:
                        for x in range(max(0,self.x),self.cols): self.cells[self.y][x]=' '
                continue
            if data[i]==27:
                raise AssertionError(('unexpected escape',data[i:i+30]))
            if data[i]<32:
                if data[i]==13: self.x=0
                elif data[i]==10: self.y+=1
                i+=1; continue
            n=1
            if data[i]>=0xc0: n=2 if data[i]<0xe0 else 3 if data[i]<0xf0 else 4
            if i+n>len(data): self.pending=data[i:]; break
            ch=data[i:i+n].decode('utf8'); i+=n
            if 0<=self.y<self.rows and 0<=self.x<self.cols: self.cells[self.y][self.x]=ch
            self.x+=1
    def text(self): return '\n'.join(''.join(r).rstrip() for r in self.cells)
    def pids(self):
        return [int(m.group(1)) for line in self.text().splitlines()
                if (m:=re.match(r'^\s*(\d+)\s+\S+\s+[\d.]+\s+\d+\s+[A-Z]\s',line))]


class Terminal:
    def __init__(self, runner, script='top -d 3599 -o pid', rows=12, cols=100):
        self.master,self.slave=pty.openpty()
        self.before=termios.tcgetattr(self.slave)
        fcntl.ioctl(self.slave,termios.TIOCSWINSZ,struct.pack('HHHH',rows,cols,0,0))
        self.screen=Screen(rows,cols); self.raw=bytearray()
        def attach():
            os.setsid(); fcntl.ioctl(0,termios.TIOCSCTTY,0)
        env={**runner.env,'TOP_FIXTURE_MODE':'manual'}
        self.proc=subprocess.Popen(runner.command(script),stdin=self.slave,stdout=self.slave,
                                   stderr=self.slave,env=env,preexec_fn=attach)
    def read(self, timeout=.05):
        if select.select([self.master],[],[],timeout)[0]:
            try: data=os.read(self.master,65536)
            except OSError as e:
                if e.errno==errno.EIO: return b''
                raise
            self.raw.extend(data); self.screen.feed(data); return data
        return b''
    def until(self, predicate, timeout=5):
        end=time.monotonic()+timeout
        while not predicate():
            assert time.monotonic()<end, ('PTY timeout',self.screen.text(),bytes(self.raw[-1000:]))
            self.read()
        # Finish any already queued diff writes before testing complete cell rows.
        while self.read(.01): pass
    def send(self, data): os.write(self.master,data)
    def resize(self, rows, cols):
        self.screen.resize(rows,cols)
        fcntl.ioctl(self.slave,termios.TIOCSWINSZ,struct.pack('HHHH',rows,cols,0,0))
        os.kill(self.proc.pid,signal.SIGWINCH)
    def finish(self, key=b'q', rc=0):
        if key: self.send(key)
        self.until(lambda:self.proc.poll() is not None)
        assert self.proc.wait(timeout=2)==rc, bytes(self.raw)
        assert termios.tcgetattr(self.slave)==self.before, 'termios not restored'
        assert b'\x1b[?25h\x1b[?1049l' in self.raw, 'cursor/alternate screen not restored'
        assert b'AddressSanitizer' not in self.raw and b'runtime error:' not in self.raw,bytes(self.raw)
    def close(self):
        if self.proc.poll() is None: self.proc.kill(); self.proc.wait()
        os.close(self.master); os.close(self.slave)
    def __enter__(self): return self
    def __exit__(self,*args): self.close()


def checks(r, root):
    n=0
    for alias in ['--once','-b','--batch']:
        for sort in ['cpu','mem','pid','time']:
            for cap in [0,3,100]:
                actual=r.run(f'top {alias} -o {sort} -r {cap}')
                assert actual==expected(sort,cap),(sort,cap,actual,expected(sort,cap)); n+=1
    assert r.run('top --once; top --once')==expected()*2; n+=1
    for option in ['-n','-r','-d']:
        for value in ['', 'junk','1x','1.5',' 1','1 ','+1','-1','0x10','2147483648','99999999999999999999999999999']:
            r.run(f'top --once {option} {shlex.quote(value)}',rc=2); n+=1
    for args in ['-d 0','-d 3600','-n','-r','-d','-o','-o bad','--wat','operand','-- operand']:
        r.run('top --once '+args,rc=2); n+=1
    r.run('top -n 1',rc=1); n+=1  # no controlling terminal
    r.run('top --once >/dev/full',rc=1); n+=1
    r.run('top --once >&-',rc=1); n+=1
    assert r.run('top --once >/dev/full; [[ $? == 1 ]] || exit 9; top --once')==expected(); n+=1
    # FD count and state cleanup in one shell; no host /proc data used as oracle.
    r.run('before=(/dev/fd/*); for ((i=0;i<8;i++)); do top --once >/dev/null || exit; done; after=(/dev/fd/*); [[ ${#before[@]} == ${#after[@]} ]]'); n+=1
    # System clock/counter rollback or no tick: never invent a nonzero denominator.
    saved=(root/'1/stat').read_bytes()
    for cpu_line in [(root/'0/stat').read_bytes(), b'cpu 1 0 0 0 0 0 0 0 0 0\n']:
        (root/'1/stat').write_bytes(cpu_line)
        out=r.run('top --once -o pid')
        assert all(float(line.split()[2])==0 for line in out.decode().splitlines()[5:]); n+=1
    (root/'1/stat').write_bytes(saved)
    for key in [b'q',b'Q',b'\x1b',b'\x03']:
        switch(root,0)
        with Terminal(r) as t:
            t.until(lambda:len(t.screen.pids())==7)
            assert t.screen.pids()==[101,202,303,404,505,707,909]
            t.finish(key); n+=1
    for sig in [signal.SIGTERM,signal.SIGHUP]:
        with Terminal(r) as t:
            t.until(lambda:len(t.screen.pids())==7)
            os.kill(t.proc.pid,sig)
            t.finish(key=None,rc=-sig); n+=1
    switch(root,0)
    with Terminal(r,'top -d 3599 -o pid -r 3') as t:
        t.until(lambda:len(t.screen.pids())==3)
        assert t.screen.pids()==[101,202,303]
        for key,want in [(b'\x1b[B',[202,303,404]),(b'\x1b[A',[101,202,303]),
                         (b'\x1b[6~',[303,404,505]),(b'\x1b[5~',[101,202,303]),
                         (b'\x1b[F',[909]),(b'\x1b[H',[101,202,303])]:
            t.send(key); t.until(lambda:t.screen.pids()==want); n+=1
        switch(root,1); t.send(b' ')
        t.until(lambda:'load 2.00' in t.screen.text())
        assert t.screen.pids()==[101,202,303]
        assert row(101,10.,25,'alpha --fixture') in t.screen.text(); n+=1
        t.send(b'o'); t.until(lambda:'sort TIME' in t.screen.text())
        assert t.screen.pids()==[404,707,303]; n+=1
        t.send(b'n'); t.until(lambda:'delay (s):' in t.screen.text()); t.send(b'2junk\r')
        t.until(lambda:'invalid delay' in t.screen.text()); assert 'every 3599s' in t.screen.text(); n+=1
        t.send(b'n'); t.until(lambda:'delay (s):' in t.screen.text()); t.send(b'3\r')
        t.until(lambda:'every 3s' in t.screen.text()); n+=1
        # Production kill/renice request construction, all intercepted by shim.
        for key,a,b,want in [(b'k',b'202',b'15','kill -15 202 ok'),
                             (b'k',b'202junk',b'15','invalid PID or signal'),
                             (b'r',b'303',b'-2','renice 303 → 3'),
                             (b'r',b'0',b'2','invalid PID or nice delta')]:
            t.send(key); t.until(lambda:('kill PID:' if key==b'k' else 'renice PID:') in t.screen.text())
            t.send(a+b'\r'); t.until(lambda:('signal [TERM]:' if key==b'k' else 'delta:') in t.screen.text())
            t.send(b+b'\r'); t.until(lambda:want in t.screen.text()); n+=1
        t.finish()
    assert (root/'mutations').read_text()=='kill 202 15\ngetpriority 0 303\nsetpriority 303 3\n'; n+=1
    switch(root,0)
    # Shrink, grow, and redraw immediately using new dimensions.
    with Terminal(r,rows=8,cols=90) as t:
        t.until(lambda:len(t.screen.pids())==4)
        t.resize(6,60); t.until(lambda:len(t.screen.pids())==2)
        assert t.screen.pids()==[101,202]; n+=1
        t.resize(14,110); t.until(lambda:len(t.screen.pids())==7); n+=1
        t.finish()
    # Empty-list churn while scrolled, followed by repopulation.
    empty=root/'empty'; empty.mkdir()
    for name in ['stat','meminfo','loadavg']:
        (empty/name).write_bytes((root/'0'/name).read_bytes())
    with Terminal(r,'top -d 3599 -o pid -r 3') as t:
        t.until(lambda:len(t.screen.pids())==3)
        t.send(b'\x1b[F'); t.until(lambda:t.screen.pids()==[909])
        switch(root,'empty'); t.send(b' ')
        t.until(lambda:'procs 0' in t.screen.text()); assert not t.screen.pids(); n+=1
        switch(root,1); t.send(b' ')
        t.until(lambda:'procs 7' in t.screen.text())
        assert t.screen.pids()==[101,202,303]; n+=1
        t.finish()
    # Repeated calls restore both terminal settings and Bash's trap handlers.
    script="trap 'printf TERM_OK' TERM; trap 'printf HUP_OK' HUP; top -n 1; top -n 1; printf READY; while [[ $done != finish ]]; do read -r done; done"
    with Terminal(r,script) as t:
        t.until(lambda:b'READY' in t.raw)
        assert termios.tcgetattr(t.slave)==t.before
        os.kill(t.proc.pid,signal.SIGTERM); t.until(lambda:b'TERM_OK' in t.raw)
        os.kill(t.proc.pid,signal.SIGHUP); t.until(lambda:b'HUP_OK' in t.raw)
        t.finish(b'finish\n'); n+=1
    # Genuine refresh timeout and redraw count, no injected clock.
    with Terminal(r,'top -n 2 -d 1 -o pid') as t:
        t.until(lambda:len(t.screen.pids())==7)
        switch(root,1)
        t.finish(key=None); assert 'load 2.00' in t.screen.text(); n+=1
    # Missing proc directory fails and restores a private terminal.
    env=r.env.copy(); r.env['TOP_FIXTURE']=str(root/'missing')
    r.run('top --once',rc=1); n+=1
    with Terminal(r) as t: t.finish(key=None,rc=1); n+=1
    r.env=env
    print(f'sol-top: {n} independent batch/PTY checks passed')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary'); p.add_argument('shim'); p.add_argument('--loader'); p.add_argument('--asan')
    args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='sol-top-') as d:
        root=Path(d); fixture(root)
        r=Runner(args.binary,args.shim,root,args.loader,args.asan)
        checks(r,root)

if __name__=='__main__': main()
