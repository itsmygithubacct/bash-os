#!/usr/bin/python3
"""Guest-only owned task with self-read scheduler records and bounded lifetime."""
import ctypes,json,os,queue,sys,threading
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from clamp_r2_support import atomic, checkpoint, observed, finish, cleanup_task
from clamp_r2_guard import verify as verify_guard
verify_guard()
import importlib.util,signal
_guard_path=Path(__file__).with_name('clamp-profile-control-r2.py')
_guard_spec=importlib.util.spec_from_file_location('clamp_guard',_guard_path)
_guard=importlib.util.module_from_spec(_guard_spec);_guard_spec.loader.exec_module(_guard)
_guard.guard()
signal.alarm(50)
class Attr(ctypes.Structure):
    _fields_=[('size',ctypes.c_uint32),('policy',ctypes.c_uint32),('flags',ctypes.c_uint64),('nice',ctypes.c_int32),('priority',ctypes.c_uint32),('runtime',ctypes.c_uint64),('deadline',ctypes.c_uint64),('period',ctypes.c_uint64),('util_min',ctypes.c_uint32),('util_max',ctypes.c_uint32)]
lib=ctypes.CDLL(None,use_errno=True);lib.syscall.restype=ctypes.c_long
def get_self():
    a=Attr();a.size=ctypes.sizeof(a)
    if lib.syscall(315,0,ctypes.byref(a),ctypes.sizeof(a),0):raise OSError(ctypes.get_errno(),'sched_getattr')
    return {name:getattr(a,name) for name,_ in Attr._fields_}
def tid():return int(lib.syscall(186))
def set_self(low,high):
    a=Attr();a.size=ctypes.sizeof(a);a.flags=0x60;a.util_min=low;a.util_max=high
    if lib.syscall(314,0,ctypes.byref(a),0):raise OSError(ctypes.get_errno(),'sched_setattr owned thread')
mode=sys.argv[1];ready=queue.Queue();stop=threading.Event()
if mode=='empty':
    if lib.prctl(15,ctypes.c_char_p(b''),0,0,0):raise OSError(ctypes.get_errno(),'PR_SET_NAME')
if mode=='threads':
    set_self(0,1024)
    def run(low,high):
        set_self(low,high)
        ready.put({'tid':tid(),'attr':get_self()});stop.wait(50)
    threads=[threading.Thread(target=run,args=pair,daemon=True) for pair in ((100,900),(200,800))]
    for t in threads:t.start()
    peers=[ready.get(timeout=10) for _ in threads]
else:peers=[]
print(json.dumps({'pid':os.getpid(),'tid':tid(),'self_attr':get_self(),'peers':peers,'comm':open('/proc/self/comm').read().strip()},sort_keys=True),flush=True)
try:
    for raw in sys.stdin:
        if len(raw)>16:raise RuntimeError('owned command exceeds bound')
        command=raw.strip()
        if command=='exit':break
        if command=='read':
            print(json.dumps({'pid':os.getpid(),'attr':get_self()},sort_keys=True),flush=True)
        elif command=='fork':
            parent_before=get_self();rfd,wfd=os.pipe();pid=os.fork()
            if pid==0:
                os.close(rfd)
                try:os.write(wfd,json.dumps({'child_attr':get_self(),'pid':os.getpid(),'ppid':os.getppid()}).encode())
                finally:os._exit(0)
            os.close(wfd)
            with os.fdopen(rfd,'rb') as stream:result=json.loads(stream.read(8192))
            waited,status=os.waitpid(pid,0)
            result.update(wait_pid=waited,wait_status=status,parent_pid=os.getpid(),parent_before=parent_before,parent_after=get_self())
            print(json.dumps(result,sort_keys=True),flush=True)
        else:raise RuntimeError('unknown owned task command')
finally:stop.set()
