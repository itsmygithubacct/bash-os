#!/usr/bin/python3
"""Disposable guest owned child; self reads on bounded line protocol."""
import ctypes,json,os,sys
from pathlib import Path
import importlib.util,signal
_guard_path=Path(__file__).with_name('clamp-profile-control-r1.py')
_guard_spec=importlib.util.spec_from_file_location('clamp_guard',_guard_path)
_guard=importlib.util.module_from_spec(_guard_spec);_guard_spec.loader.exec_module(_guard)
_guard.guard()
signal.alarm(50)
class Attr(ctypes.Structure):
    _fields_=[('size',ctypes.c_uint32),('policy',ctypes.c_uint32),('flags',ctypes.c_uint64),('nice',ctypes.c_int32),('priority',ctypes.c_uint32),('runtime',ctypes.c_uint64),('deadline',ctypes.c_uint64),('period',ctypes.c_uint64),('util_min',ctypes.c_uint32),('util_max',ctypes.c_uint32)]
lib=ctypes.CDLL(None,use_errno=True);lib.syscall.restype=ctypes.c_long
def read_self():
    a=Attr();a.size=ctypes.sizeof(a)
    if lib.syscall(315,0,ctypes.byref(a),ctypes.sizeof(a),0):raise OSError(ctypes.get_errno(),'sched_getattr self')
    return {n:getattr(a,n) for n,_ in Attr._fields_}
def emit():print(json.dumps({'pid':os.getpid(),'ppid':os.getppid(),'uid':os.getuid(),'attr':read_self()},sort_keys=True),flush=True)
emit()
for line in sys.stdin:
    if len(line)>16:raise SystemExit(125)
    if line.strip()=='read':emit()
    elif line.strip()=='exit':break
    else:raise SystemExit(125)
