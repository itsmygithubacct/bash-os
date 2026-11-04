#!/usr/bin/env python3
"""Guest-only PTY barrier for stale passwd-change authentication."""
import errno, os, pathlib, pty, select, signal, subprocess, sys, time

assert os.geteuid()==2000 and pathlib.Path.cwd()==pathlib.Path('/tmp/parity-case')
assert os.environ.get('HOME')=='/tmp/parity-home'
assert pathlib.Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert pathlib.Path('/etc/bashos-parity-vm').is_file()
bash=sys.argv[1]
assert bash.startswith('/opt/bashos-parity/')

def run_case(kind):
    pathlib.Path('db/shadow').write_bytes(pathlib.Path('seed/shadow').read_bytes())
    os.chmod('db/shadow',0o600)
    pid,master=pty.fork()
    if pid==0:
        os.execv(bash,[bash,'--noprofile','--norc','-c','passwd change alice'])
    reaped=False
    buf=bytearray()
    def wait_for(wanted):
        deadline=time.monotonic()+15
        while wanted not in buf:
            timeout=deadline-time.monotonic()
            if timeout<=0: raise RuntimeError('prompt timeout '+repr(wanted))
            readable,_,_=select.select([master],[],[],timeout)
            if not readable: raise RuntimeError('prompt timeout '+repr(wanted))
            try: data=os.read(master,4096)
            except OSError as e:
                if e.errno==errno.EIO: raise RuntimeError('child exited before prompt') from e
                raise
            if not data: raise RuntimeError('pty closed before prompt')
            buf.extend(data)
        pos=buf.index(wanted)+len(wanted)
        del buf[:pos]
    try:
        wait_for(b'Current password: ')
        os.write(master,b'old-secret-r3\r')
        wait_for(b'New password: ')
        prior=None
        if kind=='lock':
            contender='passwd lock alice'
        elif kind=='set':
            contender='passwd set-fd alice 3 3<pw.rival'
        else:
            contender=None
        if contender:
            result=subprocess.run([bash,'--noprofile','--norc','-c',contender],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
            if result.returncode!=0: raise RuntimeError('competing '+kind+' failed: '+str(result.returncode))
            prior=pathlib.Path('db/shadow').read_bytes()
            seed=pathlib.Path('seed/shadow').read_bytes()
            if kind=='lock' and prior != b'alice:!' + seed[len(b'alice:'):]: raise RuntimeError('lock control not applied exactly')
            if kind=='set':
                if prior==seed: raise RuntimeError('set control unchanged')
                subprocess.run(['/usr/bin/python3','-I','/opt/bashos-parity/harness/helpers/runtime06-phc-oracle-r3.py','db/shadow','alice','pw.rival'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
        os.write(master,b'next-secret-r3\r')
        wait_for(b'Retype new password: ')
        os.write(master,b'next-secret-r3\r')
        deadline=time.monotonic()+20
        while True:
            ended,status=os.waitpid(pid,os.WNOHANG)
            if ended: reaped=True; break
            if time.monotonic()>deadline: raise RuntimeError('change did not exit')
            time.sleep(.02)
        rc=os.waitstatus_to_exitcode(status)
        after=pathlib.Path('db/shadow').read_bytes()
        if kind=='unchanged':
            if rc!=0 or after==pathlib.Path('seed/shadow').read_bytes(): raise RuntimeError('unchanged control failed')
            subprocess.run(['/usr/bin/python3','-I','/opt/bashos-parity/harness/helpers/runtime06-phc-oracle-r3.py','db/shadow','alice','pw.next'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
            print('unchanged=success-independent-kdf')
        else:
            if rc==0 or after!=prior: raise RuntimeError('stale '+kind+' accepted or winner changed')
            print('stale-'+kind+'=rejected-winner-unchanged')
    finally:
        if not reaped:
            try: os.kill(pid,signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(pid,0)
            except ChildProcessError: pass
        os.close(master)
for scenario in ('unchanged','set','lock'):
    run_case(scenario)
