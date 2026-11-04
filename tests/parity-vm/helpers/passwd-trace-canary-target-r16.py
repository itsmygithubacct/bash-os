#!/usr/bin/python3
import errno, os, pathlib, sys
if os.geteuid() != 0 or pathlib.Path.cwd() != pathlib.Path('/tmp/parity-case'):
    raise SystemExit(125)
if sys.argv[1] == 'fork':
    try:
        pid = os.fork()
    except OSError as e:
        assert e.errno == errno.EPERM
        raise SystemExit(0)
    if pid == 0: os._exit(99)
    os.waitpid(pid, 0)
    raise SystemExit(99)
fd = os.open('tracer-canary.data', os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
assert os.write(fd, b'canary-data') == 11
os.fsync(fd)
os.lseek(fd, 0, os.SEEK_SET)
assert os.read(fd, 11) == b'canary-data'
os.close(fd)
os.link('tracer-canary.data', 'tracer-canary.link')
os.rename('tracer-canary.link', 'tracer-canary.renamed')
os.unlink('tracer-canary.renamed')
try:
    os.read(123456, 1)
except OSError as e:
    assert e.errno == errno.EBADF
else: raise AssertionError('invalid fd unexpectedly read')
raise SystemExit(7)
