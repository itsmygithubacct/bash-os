#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only seccomp notification extension of the pinned system-sequence helper.

It observes sender FD flags at a paused sendto, injects one send return, or
mutates one private user xattr while its first data read is stopped. The pinned
helper owns filter setup/fork/exec; this file supplies only the bounded response
loop. No permissions are granted, and all non-injected syscalls continue in the
kernel. Config and traces must be beneath the per-side scratch directories.
"""
import base64
import ctypes
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import struct
import sys
import uuid

SEQ = Path('/opt/bashos-parity/harness/helpers/system-sequence.py')
CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU'
    assert Path.cwd().is_relative_to(CASE) and os.geteuid() == 2000


def under(path, root):
    return Path(path).resolve().is_relative_to(root)


def main():
    guard()
    config_path = Path(sys.argv[1]); assert under(config_path, CASE)
    config = json.loads(config_path.read_text())
    mode = config['mode']; trace = Path(config['trace']); assert under(trace, HOME)
    assert mode in ('logger-pass','logger-intr','logger-short','logger-fail','xgrow','xalways')
    if mode.startswith('x'):
        path = Path(config['path']); assert under(path, CASE)
        assert config['attribute'] == 'user.terra_fixture'
    spec = importlib.util.spec_from_file_location('terra_pinned_sequence', SEQ)
    seq = importlib.util.module_from_spec(spec); spec.loader.exec_module(seq)
    state = {'sends':0, 'grew':False, 'events':0}

    def supervise(lib, listener, child, replies, sequences, logargs, logstr, logmem, unused_log):
        status = None
        with trace.open('w') as log:
            try:
                while status is None:
                    done, wstatus = os.waitpid(child, os.WNOHANG)
                    if done:
                        status = wstatus; break
                    ready,_,_ = select.select([listener], [], [], .05)
                    if not ready: continue
                    request = bytearray(80)
                    try: fcntl.ioctl(listener, seq.NOTIF_RECV, request, True)
                    except OSError as exc:
                        if exc.errno in (errno.ENOENT, errno.EINTR): continue
                        raise
                    ident,pid,_flags,nr,_arch,_ip = struct.unpack_from('<QIIiIQ',request)
                    args = struct.unpack_from('<6Q',request,32)
                    raw = lib.seccomp_syscall_resolve_num_arch(0,nr)
                    name = ctypes.cast(raw,ctypes.c_char_p).value.decode() if raw else str(nr)
                    event = {'syscall':name, 'pid':pid, 'args':list(args), 'reply':'continue'}
                    kind='continue'; value=0
                    state['events'] += 1
                    if state['events'] > 64: raise RuntimeError('notification bound exceeded')
                    if mode.startswith('logger') and name == 'sendto':
                        state['sends'] += 1
                        fd = int(args[0]); link = Path('/proc/%d/fd/%d' % (pid,fd))
                        info = Path('/proc/%d/fdinfo/%d' % (pid,fd)).read_text()
                        flags = next(int(line.split()[1],8) for line in info.splitlines() if line.startswith('flags:'))
                        event.update(fd=fd, fd_target=os.readlink(link), fdinfo=info,
                                     cloexec=bool(flags & os.O_CLOEXEC), send_index=state['sends'])
                        if mode == 'logger-intr' and state['sends'] == 1: kind,value='errno',errno.EINTR
                        if mode == 'logger-short': kind,value='value',1
                        if mode == 'logger-fail': kind,value='errno',errno.EIO
                    if mode.startswith('x') and name in ('getxattr','lgetxattr','fgetxattr'):
                        size = int(args[3]); event['size'] = size
                        if mode == 'xalways' and size > 0: kind,value='errno',errno.ERANGE
                        if mode == 'xgrow' and size > 0 and not state['grew']:
                            old = os.getxattr(path, config['attribute'])
                            new = base64.b64decode(config['new_value'], validate=True)
                            if len(old) != size or len(new) <= size:
                                raise RuntimeError('growth barrier did not follow expected size probe')
                            os.setxattr(path,config['attribute'],new)
                            check = os.getxattr(path,config['attribute'])
                            if check != new: raise RuntimeError('growth write verification failed')
                            event.update(old_base64=base64.b64encode(old).decode(),
                                         new_base64=base64.b64encode(check).decode(), mutation='before-continued-read')
                            state['grew']=True
                    event['reply'] = kind if kind == 'continue' else '%s:%d' % (kind,value)
                    log.write(json.dumps(event,sort_keys=True)+'\n'); log.flush()
                    if kind == 'continue': response=struct.pack('<QqiI',ident,0,0,seq.FLAG_CONTINUE)
                    elif kind == 'value': response=struct.pack('<QqiI',ident,value,0,0)
                    else: response=struct.pack('<QqiI',ident,0,-value,0)
                    try: fcntl.ioctl(listener,seq.NOTIF_SEND,response)
                    except OSError as exc:
                        if exc.errno != errno.ENOENT: raise
            finally:
                if status is None:
                    os.kill(child,signal.SIGKILL)
                    status = os.waitpid(child,0)[1]
        return status
    seq.supervise=supervise
    rules = ['--notify','socket:0=1','--notify','sendto'] if mode.startswith('logger') else ['--notify',config['syscall']]
    assert config.get('syscall','getxattr') in ('getxattr','lgetxattr','fgetxattr')
    sys.argv = [str(SEQ)] + rules + ['--'] + sys.argv[2:]
    seq.main()


if __name__ == '__main__': main()
