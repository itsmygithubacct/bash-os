#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent terminfo/termios controls for 0.1.4; no physical-hardware claim."""
import argparse
import fcntl
import os
from pathlib import Path
import select
import subprocess
import struct
import tempfile
import termios
from guest import clean_env, digest, entrypoint, guard, require_bash_5320, run, save


def modes(fd):
    a=termios.tcgetattr(fd)
    return a[:6]+[[c if isinstance(c,int) else c[0] for c in a[6]]]


def observe(argv, env, reset):
    master,slave=os.openpty()
    original=termios.tcgetattr(slave)
    p=None
    try:
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',6,16,0,0))
        dirty=termios.tcgetattr(slave)
        for name in (('VINTR','VQUIT','VERASE','VKILL','VEOF','VSUSP') if reset else ('VINTR','VERASE','VKILL')):
            dirty[6][getattr(termios,name)]=b'\0'
        if reset:
            dirty[3] &= ~(termios.ECHO|termios.ICANON)
            dirty[1] &= ~termios.ONLCR
        termios.tcsetattr(slave,termios.TCSANOW,dirty)
        before=modes(slave)
        p=subprocess.Popen(argv,stdin=slave,stdout=slave,stderr=slave,env=env,close_fds=True)
        status=p.wait(timeout=6)
        data=bytearray();os.set_blocking(master,False)
        while select.select([master],[],[],0)[0]:
            block=os.read(master,8192)
            if not block:break
            data.extend(block)
            if len(data)>65536:raise RuntimeError('terminal observation exceeded bound')
        return dict(status=status,wire_hex=data.hex(),before=before,after=modes(slave))
    finally:
        if p is not None and p.poll() is None:p.kill();p.wait(timeout=3)
        termios.tcsetattr(slave,termios.TCSANOW,original)
        os.close(master);os.close(slave)


def main():
    p=argparse.ArgumentParser();p.add_argument('shell');p.add_argument('reference_tput');p.add_argument('output');p.add_argument('--module')
    a=p.parse_args();guard()
    bash_version = require_bash_5320(a.shell)
    setup=('[[ $(type -t tput || :) != builtin ]] || exit 125\nenable -f "$1" tput || exit 125\n') if a.module else (
           '[[ $(type -t tput || :) == builtin ]] || exit 125\n')
    rows=[]
    with tempfile.TemporaryDirectory(prefix='qual-tput-') as td:
        root=Path(td);ti=root/'ti';ti.mkdir()
        (root/'init.bytes').write_bytes(b'INITFILE');(root/'reset.bytes').write_bytes(b'RESETFILE')
        source=("qual014|qualification terminal,\n"
                "\tcols#16, lines#6, it#4,\n"
                "\tis1=I1, is2=I2, is3=I3, rs1=R1, rs2=R2, rs3=R3,\n"
                "\tmgc=MARG, cr=\\r, tbc=TBC, hts=HTS,\n"
                f"\tif={root}/init.bytes, rf={root}/reset.bytes,\n")
        (root/'term.src').write_text(source)
        compiled=run(['/usr/bin/tic','-x','-o',ti,root/'term.src'])
        if compiled['status']!=0:raise RuntimeError('tic prerequisite failed: '+str(compiled))
        env=clean_env();env.update(TERM='qual014',TERMINFO=str(ti))
        table_hashes={str(x.relative_to(ti)):digest(x) for x in ti.rglob('*') if x.is_file()}
        for reset in (False,True):
            verb='reset' if reset else 'init'
            wire=(b'R1R2' if reset else b'I1I2')+b'MARG\rTBC'+(b'    HTS'*3)+b'\r'+(
                b'RESETFILER3' if reset else b'INITFILEI3')
            reference=observe([a.reference_tput,'-T','qual014',verb],env,reset)
            candidate=observe([a.shell,'--noprofile','--norc','-c',setup+'builtin tput -T qual014 '+verb,
                               'qualification',a.module or ''],env,reset)
            negative=observe(['/bin/true'],env,reset)
            controls=(reference['status']==0 and reference['wire_hex']==wire.hex() and
                      negative['wire_hex']=='' and negative['after']==negative['before'] and
                      reference['after']!=negative['after'])
            if reset:
                controls=controls and bool(reference['after'][3]&termios.ECHO) and bool(reference['after'][3]&termios.ICANON) and bool(reference['after'][1]&termios.ONLCR)
            rows.append(dict(case=verb,expected_hex=wire.hex(),reference=reference,candidate=candidate,negative=negative,
                             controls=bool(controls),matches=candidate['status']==0 and candidate['wire_hex']==wire.hex() and candidate['after']==reference['after']))
            no_tty_ref=run([a.reference_tput,'-T','qual014',verb],env=env,start_new_session=True)
            no_tty_new=run([a.shell,'--noprofile','--norc','-c',setup+'builtin tput -T qual014 '+verb,
                            'qualification',a.module or ''],env=env,start_new_session=True)
            no_tty_control=(no_tty_ref['status']==10 and no_tty_ref['stdout_hex']=='' and
                            bytes.fromhex(no_tty_ref['stderr_hex'])==b'tput: terminal attributes: No such device or address\n\n')
            rows.append(dict(case=verb+'-no-tty',reference=no_tty_ref,candidate=no_tty_new,controls=no_tty_control,
                             matches=all(no_tty_ref[k]==no_tty_new[k] for k in ('status','stdout_hex','stderr_hex'))))
        result='PASS' if all(r['matches'] for r in rows) else 'FAIL'
        if not all(r['controls'] for r in rows) or any(r['candidate']['status'] in (125,126,127) for r in rows):result='ERROR'
    save(a.output,dict(scope='0.1.4 compiled terminfo and private PTY; physical r4 still required',result=result,
                       bash_version=bash_version,
                       shell_sha256=digest(a.shell),reference_sha256=digest(a.reference_tput),
                       module_sha256=digest(a.module) if a.module else None,
                       terminfo_source=source,terminfo_sha256=table_hashes,tic=compiled,observations=rows))
    return {'PASS':0,'FAIL':1,'ERROR':125}[result]


if __name__=='__main__':entrypoint(main)
