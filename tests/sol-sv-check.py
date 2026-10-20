#!/usr/bin/env python3
"""Private sv lifecycle and byte-integrity fixtures; never uses host services."""
import argparse
import ctypes
import fcntl
import hashlib
import os
from pathlib import Path
import re
import signal
import select
import subprocess
import sys
import tempfile
import threading
import time

PREFIX = re.compile(rb'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z ')


def unframe(data):
    rows = data.split(b'\n')
    result = []
    for i, row in enumerate(rows):
        if i == len(rows)-1 and not row:
            break
        assert PREFIX.match(row), ('missing timestamp', row[:80])
        result.append(row[31:] + (b'\n' if i < len(rows)-1 else b''))
    return b''.join(result)


class Fixture:
    def __init__(self, binary, root):
        self.binary = str(Path(binary).resolve())
        self.root = Path(root)
        for name in ('services', 'run', 'logs'):
            (self.root/name).mkdir(exist_ok=True)
        self.env = {**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC',
                    'BASHSV_DIR': str(self.root/'services'),
                    'BASHSV_RUNDIR': str(self.root/'run'),
                    'BASHSV_LOGDIR': str(self.root/'logs'),
                    'BASHSV_LOG_MAX_BYTES': '0', 'SV_TEST_ROOT': str(self.root)}
        self.pids = set()
        # Adopt only descendants created by this harness, and reap supervisors.
        assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0

    def run(self, *args, rc=0, script=None, timeout=20):
        p = subprocess.run([self.binary, '-c', script or 'PATH=; sv "$@"', '_', *args],
                           env=self.env, capture_output=True, timeout=timeout)
        assert p.returncode == rc, (args, p.returncode, p.stdout, p.stderr)
        assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
        return p

    def service(self, name, body, directives='', config=''):
        d = self.root/'services'/name
        d.mkdir(exist_ok=True)
        run = d/'run'
        run.write_text('#!'+self.binary+'\n'+directives+body+'\n')
        run.chmod(0o700)
        if config:
            (d/'log').mkdir(exist_ok=True)
            (d/'log/config').write_text(config)
        return d

    def producer(self, name, payload, timestamp=True):
        (self.root/(name+'.input')).write_bytes(payload)
        d = self.service(name, 'exec '+sys.executable+' "$SV_TEST_ROOT/'+name+'.py"',
                         '# restart: never\n', 't\ns0\n' if timestamp else 's0\n')
        (self.root/(name+'.py')).write_text('''import os, pathlib, hashlib
r = pathlib.Path(os.environ['SV_TEST_ROOT'])
p = r / %r
b = p.read_bytes()
o = 0
while o < len(b):
    o += os.write(1, b[o:o+8192])
(r / %r).write_text(str(o)+' '+hashlib.sha256(b).hexdigest())
''' % (name+'.input', name+'.receipt'))
        return d

    def wait(self, predicate, description, timeout=12):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.01)
        raise AssertionError('timeout: '+description)

    def text(self, name, leaf):
        try:
            return (self.root/'run'/name/leaf).read_text()
        except FileNotFoundError:
            return ''

    def up(self, name):
        self.run('up', name)
        self.wait(lambda: self.text(name, 'super-pid') or self.text(name, 'status') not in ('', 'starting\n'), 'supervisor '+name)
        if self.text(name, 'super-pid'):
            self.pids.add(int(self.text(name, 'super-pid')))

    def reap(self):
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                break
            self.pids.discard(pid)

    def cleanup(self):
        # Walk actual descendants, not stale PID files (PIDs can be reused).
        def children(pid):
            try:
                return [int(x) for x in Path('/proc',str(pid),'task',str(pid),'children').read_text().split()]
            except FileNotFoundError:
                return []
        owned = children(os.getpid())
        for pid in owned:
            try:
                os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError:
                pass
        pending = list(owned)
        while pending:
            pid = pending.pop()
            for child in children(pid):
                try:
                    os.kill(child, signal.SIGSTOP)
                except ProcessLookupError:
                    continue
                owned.append(child)
                pending.append(child)
        for pid in reversed(owned):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while True:
            try:
                os.waitpid(-1, 0)
            except ChildProcessError:
                break


def checks(binary):
    with tempfile.TemporaryDirectory(prefix='sol-sv-') as root:
        f = Fixture(binary, root)
        try:
            for args in [(), ('log',), ('up',), ('once',), ('unknown',), ('log','../escape')]:
                f.run(*args, rc=2)
            f.run('once', 'missing', rc=1)
            # Tail output oracle uses LF only, including NUL, long and unterminated rows.
            for payload in (b'', b'one', b'one\n', b'\n\n', b'a\0b\xff\n'+b'x'*100000+b'\nlast',
                            b''.join(bytes([i%256])+b' row\n' for i in range(1000))):
                (f.root/'logs/fixture').write_bytes(payload)
                for n in (1, 2, 20, 200, 2000):
                    expected = subprocess.check_output(['/usr/bin/tail','-n',str(n),str(f.root/'logs/fixture')])
                    assert f.run('log','fixture','-n',str(n)).stdout == expected
            print('tail: 30 binary/long/empty/unterminated parity checks', flush=True)
            for name in ('.', '..'):
                f.run('log', name, rc=2)
            for value in ('-1', 'abc', '1x', '2147483648', '9999999999999999999999'):
                f.run('log','fixture','-n',value,rc=2)
            f.run('log','fixture','-n',rc=2)
            f.run('log','fixture','--bad',rc=2)
            assert f.run('log','fixture','-n','0').stdout == b''
            (f.root/'logs/directory').mkdir()
            f.run('log','directory',rc=1)
            # Nonseekable fallback must count whole, byte-preserved LF records.
            fifo = f.root/'logs/stream'
            os.mkfifo(fifo)
            data = b'old\n'+b'x'*100000+b'\0\xff\nlast\0'
            def writer():
                with fifo.open('wb') as stream:
                    stream.write(data)
            thread = threading.Thread(target=writer)
            thread.start()
            assert f.run('log','stream','-n','2').stdout == data[4:]
            thread.join(5)
            assert not thread.is_alive()
            # A large stdout pipe must apply backpressure without losing bytes.
            data = b'backpressure\0\xff record\n'*16384+b'last'
            (f.root/'logs/backpressure').write_bytes(data)
            proc = subprocess.Popen([f.binary,'-c','PATH=; sv log backpressure -n 20000'],
                                    env=f.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                capacity = fcntl.fcntl(proc.stdout.fileno(), fcntl.F_GETPIPE_SZ)
                f.wait(lambda: len(select.select([proc.stdout],[],[],0)[0]) > 0,
                       'tail output pipe')
                assert capacity < len(data)
                output, errors = proc.communicate(timeout=10)
                assert proc.returncode == 0 and output == data and not errors
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
            print('tail: invalid options, zero lines, failed input, binary FIFO and stdout backpressure', flush=True)
            # Repeated same-shell calls, FD balance and a write error followed by recovery.
            f.run(script='''PATH=
a=(/proc/$$/fd/*); before=${#a[@]}
for ((i=0;i<100;i++)); do sv log fixture -n 2 > /dev/null || exit; done
a=(/proc/$$/fd/*); [[ ${#a[@]} == "$before" ]] || exit 90
sv log fixture > /dev/full; [[ $? == 1 ]] || exit 91
sv log fixture 1>&-; [[ $? == 1 ]] || exit 93
sv log fixture > /dev/null''')
            payload = (b'hello\0\xff\n\n'+b'x'*100003+b'\n')*3+b'unterminated\0'
            for timestamp in (False, True):
                name = 'capture'+str(int(timestamp))
                f.producer(name, payload, timestamp)
                f.run('once',name)
                actual = (f.root/'logs'/name).read_bytes()
                assert (unframe(actual) if timestamp else actual) == payload
                for n in (2, 200):
                    expected = subprocess.check_output(['/usr/bin/tail','-n',str(n),str(f.root/'logs'/name)])
                    assert f.run('log',name,'-n',str(n)).stdout == expected
                assert (f.root/(name+'.receipt')).read_text() == str(len(payload))+' '+hashlib.sha256(payload).hexdigest()
            f.run(script='PATH=\na=(/proc/$$/fd/*); before=${#a[@]}\nfor ((i=0;i<4;i++)); do\n  : > "$BASHSV_LOGDIR/capture1"\n  sv once capture1 > /dev/null || exit\n  sv once capture0 > /dev/null || exit\ndone\na=(/proc/$$/fd/*); [[ ${#a[@]} == "$before" ]] || exit 92\n(exit 7) & child=$!; wait "$child"; [[ $? == 7 ]]\n')
            print('capture: binary, long, unterminated, pipe backpressure and FD balance', flush=True)
            # Rotation occurs when opening a service log, not mid-stream.
            f.service('rotate', 'printf 12345678', config='s8\nn3\n')
            f.run(script='PATH=; for ((i=0;i<5;i++)); do sv once rotate || exit; done')
            for suffix in ('','.1','.2','.3'):
                assert (f.root/'logs'/('rotate'+suffix)).read_bytes() == b'12345678'
            assert not (f.root/'logs/rotate.4').exists()
            print('rotation: threshold, generations and repeated calls', flush=True)
            f.service('oneshot', 'printf x >> "$SV_TEST_ROOT/oneshot.count"', '# type: oneshot\n')
            f.run('up','oneshot')
            f.wait(lambda: f.text('oneshot','status') == 'oneshot-ok\n', 'oneshot')
            f.run('up','oneshot')
            assert (f.root/'oneshot.count').read_bytes() == b'x'
            f.run('down','oneshot')
            f.run('up','oneshot')
            f.wait(lambda: (f.root/'oneshot.count').read_bytes() == b'xx', 'oneshot reenable')
            f.wait(lambda: not f.text('oneshot','pid') and not f.text('oneshot','super-pid'), 'oneshot cleanup')
            f.service('badpolicy','exit 0','# restart: invalid\n')
            f.run('once','badpolicy',rc=1)
            f.up('badpolicy')
            f.wait(lambda: f.text('badpolicy','status') == 'policy-error rc=2\n', 'bad policy')
            print('lifecycle: oneshot idempotence, down/up and invalid policy',flush=True)
            # Exit policy and finish arguments, including a signal.
            for name, mode, body, count, status in (
                ('never','never','exit 7',1,'exited rc=7'),
                ('success','on-failure','exit 0',1,'exited rc=0'),
                ('failure','on-failure','exit 7',3,'restart-limit rc=7'),
                ('always','always','exit 0',3,'restart-limit rc=0'),
                ('signalled','never','kill -TERM $$',1,'signal=15')):
                d = f.service(name, 'printf x >> "$SV_TEST_ROOT/'+name+'.count"\n'+body,
                              '# restart: '+mode+'\n# restart-delay: 0\n# restart-max: 2\n')
                finish = d/'finish'
                finish.write_text('#!'+f.binary+'\nprintf "%s\\n" "$1" >> "$SV_TEST_ROOT/'+name+'.finish"\n')
                finish.chmod(0o700)
                f.up(name)
                f.wait(lambda: status in f.text(name,'status'), 'exit policy '+name)
                f.wait(lambda: (f.root/(name+'.finish')).exists() and len((f.root/(name+'.finish')).read_text().splitlines()) == count, 'finish '+name)
                assert (f.root/(name+'.count')).read_bytes() == b'x'*count
                expected = '143' if name == 'signalled' else ('7' if name in ('never','failure') else '0')
                assert (f.root/(name+'.finish')).read_text().splitlines() == [expected]*count
                f.wait(lambda: not f.text(name,'pid') and not f.text(name,'super-pid'), 'PID cleanup '+name)
                f.reap()
            print('lifecycle: never/on-failure/always, limits, finish exit/signal policy', flush=True)
            # Native held service and explicit restart/down, no PATH needed.
            f.service('held', 'printf "%s" "$$" > "$SV_TEST_ROOT/held.started"\ntrap "exit 0" TERM\nwhile :; do read -t .05 -u 9 || :; done',
                      '# restart: never\n')
            # A private FIFO keeps read blocking without using a sleep loadable.
            os.mkfifo(f.root/'held.fifo')
            run = f.root/'services/held/run'
            run.write_text(run.read_text().replace('trap ', 'exec 9<> "$SV_TEST_ROOT/held.fifo"\ntrap '))
            f.up('held')
            f.wait(lambda: (f.root/'held.started').exists(), 'held start')
            old = (f.root/'held.started').read_text()
            f.run('up','held')
            assert (f.root/'held.started').read_text() == old
            f.run('signal','held','not-a-signal',rc=2)
            f.run('restart','held')
            f.wait(lambda: (f.root/'held.started').read_text() != old, 'held restart')
            f.pids.add(int(f.text('held','super-pid')))
            f.run('shutdown')
            f.wait(lambda: f.text('held','status') == 'down\n', 'shutdown')
            f.reap()
            print('lifecycle: idempotent up, explicit restart, private shutdown', flush=True)
            os.mkfifo(f.root/'ready.fifo')
            d=f.service('ready', 'exec 9<> "$SV_TEST_ROOT/ready.fifo"\ntrap "exit 0" TERM\n'
                        'while :; do read -t .05 -u 9 || :; done',
                        '# restart: never\n# readiness: ./check\n', 't\ns0\n')
            check=d/'check'
            check.write_text('#!'+f.binary+'\nprintf "probe\\n"\n')
            check.chmod(0o700)
            f.up('ready')
            f.wait(lambda: f.text('ready','status').startswith('ready pid='), 'ready probe')
            old=f.text('ready','pid')
            bundle=f.root/'services/ready-bundle'
            bundle.mkdir()
            (bundle/'type').write_text('bundle\n')
            (bundle/'contents').write_text('ready\n')
            f.run('restart','ready-bundle')
            assert f.text('ready','status').startswith('ready pid=')
            assert f.text('ready','pid') != old
            f.run('down','ready')
            f.wait(lambda: not f.text('ready','super-pid'), 'ready stop')
            assert unframe((f.root/'logs/ready').read_bytes()) == b'probe\nprobe\n'
            print('lifecycle: timestamped readiness probe and restart barrier',flush=True)
            # Failed log output must be reported, while the child still drains and exits.
            f.producer('failed', b'row\n'*10000)
            (f.root/'logs/failed').symlink_to('/dev/full')
            f.run('once','failed',rc=1)
            assert (f.root/'failed.receipt').exists()
            f.up('failed')
            f.wait(lambda: 'log-failed errno=' in f.text('failed','status'), 'supervised log error')
            f.wait(lambda: not f.text('failed','pid') and not f.text('failed','super-pid'), 'failed PID cleanup')
            f.producer('directfailed', b'row\n'*10000, timestamp=False)
            (f.root/'logs/directfailed').symlink_to('/dev/full')
            f.run('once','directfailed',rc=1)
            assert not (f.root/'directfailed.receipt').exists()
            # An open failure must not execute the service or leak its output.
            f.producer('noopen', b'nope')
            (f.root/'logs/noopen').mkdir()
            f.run('once','noopen',rc=1)
            assert not (f.root/'noopen.receipt').exists()
            f.producer('noopen-direct',b'nope',timestamp=False)
            (f.root/'logs/noopen-direct').mkdir()
            f.run('once','noopen-direct',rc=1)
            assert not (f.root/'noopen-direct.receipt').exists()
            if os.environ.get('SV_TEST_WRITE_SHIM'):
                f.producer('shortwrite', b'short\0record\n'*1000)
                saved_preload = f.env.get('LD_PRELOAD')
                f.env['LD_PRELOAD'] = os.environ['SV_TEST_WRITE_SHIM']
                f.env['SV_TEST_WRITE_TARGET'] = str(f.root/'logs/shortwrite')
                f.run('once','shortwrite')
                assert unframe((f.root/'logs/shortwrite').read_bytes()) == b'short\0record\n'*1000
                f.env.pop('SV_TEST_WRITE_TARGET')
                if saved_preload is None:
                    f.env.pop('LD_PRELOAD')
                else:
                    f.env['LD_PRELOAD'] = saved_preload
                print('capture: injected EINTR and seven-byte short writes',flush=True)
            print('capture: failed writes reported after draining child; failed opens prevent launch', flush=True)
            # Shutdown drains a large TERM-handler record and escalates an owned
            # TERM-ignoring child; both paths must remove live PID state.
            for name, handler in [('termflush','emit() or sys.exit(0)'), ('stubborn','None')]:
                f.service(name, 'exec '+sys.executable+' "$SV_TEST_ROOT/'+name+'.py"', '# restart: never\n', 't\ns0\n')
                (f.root/(name+'.py')).write_text("import os, signal, sys\n"
                    "def emit():\n"
                    " b=b'Q'*131072+b'\\n'\n"
                    " while b: b=b[os.write(1,b):]\n"
                    "signal.signal(signal.SIGTERM, lambda *a: "+handler+")\n"
                    "open(os.environ['SV_TEST_ROOT']+'/"+name+".ready','w').write(str(os.getpid()))\n"
                    "while True: signal.pause()\n")
                f.up(name)
                f.wait(lambda: (f.root/(name+'.ready')).exists(), 'shutdown fixture '+name)
                supervisor=int(f.text(name,'super-pid'))
                child=int((f.root/(name+'.ready')).read_text())
                if name == 'termflush':
                    os.kill(supervisor, signal.SIGTERM)
                else:
                    old=(f.root/(name+'.ready')).read_text()
                    f.run('restart',name)
                    f.wait(lambda: (f.root/(name+'.ready')).read_text() != old, 'slow restart')
                    assert not Path('/proc',str(child)).exists(), 'old child survived restart'
                    child=int((f.root/(name+'.ready')).read_text())
                    f.run('down',name)
                f.wait(lambda: not f.text(name,'super-pid') and not f.text(name,'pid'), 'shutdown cleanup '+name)
                assert f.text(name,'status') == 'down\n'
                assert not Path('/proc',str(child)).exists(), 'child survived shutdown'
                if name == 'termflush':
                    assert unframe((f.root/'logs'/name).read_bytes()) == b'Q'*131072+b'\n'
                f.reap()
            print('shutdown: drains TERM output, escalates ignored TERM and cleans PID state',flush=True)
            f.reap()
            subroot=f.root/'ordered'
            subroot.mkdir()
            ordered=Fixture(f.binary,subroot)
            try:
                for name, directives in [('base',''),('app','# requires: base\n'),('disabled','')]:
                    os.mkfifo(ordered.root/(name+'.fifo'))
                    d=ordered.service(name, 'exec 9<> "$SV_TEST_ROOT/'+name+'.fifo"\n'
                        'trap "exit 0" TERM\nwhile :; do read -t .05 -u 9 || :; done',
                        '# restart: never\n'+directives)
                    finish=d/'finish'
                    finish.write_text('#!'+f.binary+'\nprintf "%s\\n" "$SV_NAME" >> "$SV_TEST_ROOT/order"\n')
                    finish.chmod(0o700)
                (ordered.root/'services/disabled/disabled').touch()
                ordered.run('boot')
                ordered.wait(lambda: 'running' in ordered.text('app','status'), 'ordered boot')
                assert not ordered.text('disabled','super-pid')
                ordered.run('shutdown')
                assert (ordered.root/'order').read_text().splitlines() == ['app','base']
                assert not list((ordered.root/'run').glob('*/pid'))
                assert not list((ordered.root/'run').glob('*/super-pid'))
                ordered.reap()
                print('lifecycle: dependency boot, disabled skip and reverse shutdown/finish order',flush=True)
            finally:
                ordered.cleanup()
        finally:
            f.cleanup()
    print('sol-sv: all checks passed')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary')
    checks(p.parse_args().binary)
