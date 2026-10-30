#!/usr/bin/python3
"""Guest-only owned task with self-read scheduler records and bounded lifetime."""
import ctypes,json,os,queue,sys,threading
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
    command=sys.stdin.readline().strip()
    if command=='fork':
        pid=os.fork()
        if pid==0:
            try:print(json.dumps({'child_attr':get_self(),'pid':os.getpid()},sort_keys=True),flush=True)
            finally:os._exit(0)
        os.waitpid(pid,0)
finally:stop.set()
