#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only nonroot loadavg FIFO and independent four-read control."""
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import stat
import sys
import time
from terminal213_guard import require_guest

ROOT = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
FIFO = ROOT/'snap/loadavg'
STOP = HOME/'top-fifo-stop'
REPORT = HOME/'top-fifo-report.json'
CLOSE_NOWRITE = 0x00000010
CLOSE_WRITE = 0x00000008


def ensure_fifo():
    info = FIFO.lstat()
    if not stat.S_ISFIFO(info.st_mode) or info.st_uid != 2000 or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError('private load FIFO differs')


def write_report(records, state):
    temp = HOME/'top-fifo-report.tmp'
    data = (json.dumps({'schema':'top-fifo-frame-v1','state':state,'records':records},sort_keys=True)+'\n').encode()
    fd = os.open(temp, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
    try:
        if os.write(fd, data) != len(data): raise RuntimeError('short report write')
        os.fsync(fd)
    finally: os.close(fd)
    os.replace(temp, REPORT)


def writer():
    require_guest()
    ensure_fifo()
    if STOP.exists() or REPORT.exists(): raise RuntimeError('stale FIFO control state')
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
    if fd < 0: raise OSError(ctypes.get_errno(), 'inotify_init1')
    try:
        wd = libc.inotify_add_watch(fd, os.fsencode(FIFO), CLOSE_NOWRITE|CLOSE_WRITE)
        if wd < 0: raise OSError(ctypes.get_errno(), 'inotify_add_watch')
        records=[];deadline=time.monotonic()+30
        while time.monotonic() < deadline and len(records) < 16:
            if STOP.exists(): break
            try: out = os.open(FIFO, os.O_WRONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
            except OSError as e:
                if e.errno != errno.ENXIO: raise
                time.sleep(.002);continue
            value = ('0.%02d 0.50 1.00 1/30 130\n' % (len(records)+1)).encode('ascii')
            try:
                start=time.monotonic_ns();n=os.write(out,value)
                if n != len(value): raise RuntimeError('short FIFO write')
            finally: os.close(out)
            closed = False
            while time.monotonic() < deadline:
                if not select.select([fd],[],[],.05)[0]: continue
                data=os.read(fd,65536);pos=0
                while pos < len(data):
                    if len(data)-pos < 16: raise RuntimeError('truncated inotify event')
                    import struct
                    event_wd,mask,cookie,length=struct.unpack_from('iIII',data,pos);pos+=16
                    if len(data)-pos < length: raise RuntimeError('truncated inotify name')
                    pos+=length
                    if event_wd != wd or mask & 0x00004000: raise RuntimeError('inotify watch failed')
                    if mask & CLOSE_NOWRITE: closed=True
                if closed: break
            if not closed: raise RuntimeError('reader close was not observed')
            records.append({'index':len(records)+1,'value':value.decode().strip(),
                            'write_ns':start,'reader_close_ns':time.monotonic_ns()})
            write_report(records,'active')
        if len(records) >= 16:
            write_report(records,'limit')
            return
        if not STOP.exists(): raise RuntimeError('fixture did not signal completion')
        write_report(records,'completed')
    finally: os.close(fd)


def reader():
    require_guest();ensure_fifo()
    for i in range(1,5):
        with FIFO.open('rb', buffering=0) as stream: got=stream.read(64)
        if got != ('0.%02d 0.50 1.00 1/30 130\n' % i).encode(): raise RuntimeError('FIFO control mismatch')
    print('FIFO-CONTROL-4',flush=True)


def frames():
    """Control: two identical explicit frames followed by a changed frame."""
    require_guest()
    for value in (b'0.02', b'0.02', b'0.03'):
        frame = b'\x1b[H\x1b[2JCTRL-FRAME:' + value
        if os.write(1, frame) != len(frame): raise RuntimeError('short control frame')
        time.sleep(.2)
    if os.write(1, b'CONTROL-FRAMES-END') != len(b'CONTROL-FRAMES-END'):
        raise RuntimeError('short control trailer')


if __name__ == '__main__':
    if len(sys.argv)!=2 or sys.argv[1] not in ('writer','reader','frames'): raise SystemExit(2)
    {'writer':writer, 'reader':reader, 'frames':frames}[sys.argv[1]]()
