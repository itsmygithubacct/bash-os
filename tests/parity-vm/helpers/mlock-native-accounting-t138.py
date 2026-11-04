#!/usr/bin/python3
"""Guest-only native accounting control; retain raw proc data for review."""
import ctypes
import json
import mmap
import os
from pathlib import Path
import resource
import uuid

case = Path('/tmp/parity-case')
home = Path('/tmp/parity-home')
if os.getuid() != 2000 or os.geteuid() != 2000 or Path.cwd() != case or os.environ.get('HOME') != str(home):
    raise SystemExit(125)
try:
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
        raise ValueError('not QEMU')
except (OSError, ValueError):
    raise SystemExit(125)
soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
if hard != resource.RLIM_INFINITY and hard < 64 * 1024 * 1024:
    raise SystemExit(125)
resource.setrlimit(resource.RLIMIT_MEMLOCK, (64 * 1024 * 1024, hard))
lib = ctypes.CDLL(None, use_errno=True)
record = {'limits': resource.getrlimit(resource.RLIMIT_MEMLOCK)}
def status():
    raw = Path('/proc/self/status').read_text()
    values = {line.split(':', 1)[0]: int(line.split()[1]) for line in raw.splitlines()
              if line.startswith(('VmLck:', 'VmRSS:', 'VmSize:'))}
    return {'raw': raw, 'values_kb': values}
try:
    record['before'] = status()
    record['all_rc'] = lib.mlockall(3)
    record['all_errno'] = ctypes.get_errno()
    if record['all_rc'] != 0:
        raise RuntimeError('native mlockall failed')
    record['locked'] = status()
    record['smaps'] = Path('/proc/self/smaps').read_text()
    mapping = mmap.mmap(-1, 1024 * 1024)
    record['future'] = status()
    mapping.close()
    record['unlock_rc'] = lib.munlockall()
    record['unlocked'] = status()
    a = record['locked']['values_kb']
    b = record['future']['values_kb']
    c = record['unlocked']['values_kb']
    record['literal_resident_comparison'] = a['VmLck'] >= a['VmRSS']
    if not (a['VmLck'] > 0 and b['VmLck'] > a['VmLck'] and record['unlock_rc'] == 0 and c['VmLck'] == 0):
        raise RuntimeError('native lock lifecycle failed')
finally:
    lib.munlockall()
    (home / 'mlock-native-accounting-t138.json').write_text(json.dumps(record, indent=2) + '\n')
print('native-accounting=recorded')
