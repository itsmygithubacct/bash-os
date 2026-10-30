#!/usr/bin/python3
"""Guest-only native reset-on-fork control on one owned disposable task."""
import ctypes,json,os,select,sys,uuid
from pathlib import Path
if os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=Path('/tmp/parity-case') or os.environ.get('HOME')!='/tmp/parity-home':raise SystemExit(125)
if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.uname().release!='7.2.11+deb13-amd64':raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
if len(sys.argv)!=4 or any(not x.isdigit() for x in sys.argv[1:]):raise SystemExit(125)
pid,expected_parent,expected_start=map(int,sys.argv[1:])
if pid<=1 or os.stat('/proc/%d'%pid).st_uid!=2000:raise SystemExit(125)
def identity():
    text=Path('/proc/%d/stat'%pid).read_text();pos=text.rfind(')')
    if pos<0:raise RuntimeError('invalid proc stat')
    fields=text[pos+1:].split()
    if len(fields)<20 or fields[0] in ('Z','X','x'):raise RuntimeError('task is dead or stat truncated')
    ident={'pid':pid,'ppid':int(fields[1]),'start_ticks':int(fields[19]),'uid':os.stat('/proc/%d'%pid).st_uid}
    if ident!={'pid':pid,'ppid':expected_parent,'start_ticks':expected_start,'uid':2000}:raise RuntimeError('owned task identity changed')
    return ident
class Attr(ctypes.Structure):
    _fields_=[('size',ctypes.c_uint32),('policy',ctypes.c_uint32),('flags',ctypes.c_uint64),('nice',ctypes.c_int32),('priority',ctypes.c_uint32),('runtime',ctypes.c_uint64),('deadline',ctypes.c_uint64),('period',ctypes.c_uint64),('util_min',ctypes.c_uint32),('util_max',ctypes.c_uint32)]
lib=ctypes.CDLL(None,use_errno=True);lib.syscall.restype=ctypes.c_long
def read():
    a=Attr();a.size=ctypes.sizeof(a)
    if lib.syscall(315,pid,ctypes.byref(a),ctypes.sizeof(a),0):raise OSError(ctypes.get_errno(),'sched_getattr')
    return a
try:
    before_id=identity();pidfd=os.pidfd_open(pid,0)
    poll=select.poll();poll.register(pidfd,select.POLLIN)
    if poll.poll(0) or identity()!=before_id:raise RuntimeError('owned task died during pidfd binding')
    a=read();before={n:getattr(a,n) for n,_ in Attr._fields_}
    if a.flags&1 or (a.util_min,a.util_max)!=(100,800):raise RuntimeError('initial native control state differs')
    a.size=ctypes.sizeof(a);a.flags=0x71;a.util_min=100;a.util_max=800
    if lib.syscall(314,pid,ctypes.byref(a),0):raise OSError(ctypes.get_errno(),'sched_setattr')
    b=read();after={n:getattr(b,n) for n,_ in Attr._fields_}
    after_id=identity()
    if poll.poll(0) or after_id!=before_id:raise RuntimeError('owned task died during native control')
    if not b.flags&1 or (b.util_min,b.util_max)!=(100,800):raise RuntimeError('native reset bit/readback differs')
    print(json.dumps({'pid':pid,'before':before,'after':after,'identity_before':before_id,'identity_after':after_id,'pidfd_alive':True,'request_flags':0x71},sort_keys=True))
except (OSError,RuntimeError,ValueError,IndexError,AttributeError) as e:
    print('native reset control incomplete: '+str(e),file=sys.stderr);raise SystemExit(125)
