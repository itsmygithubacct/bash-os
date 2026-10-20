#!/usr/bin/env python3
"""Run sed in a private root containing only a static Bash-OS binary."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve()
bwrap = shutil.which('bwrap')
if not bwrap:
    print('UNAVAILABLE: bubblewrap is not installed');raise SystemExit(77)
with tempfile.TemporaryDirectory(prefix='sol-sed-rootfs-') as tmp:
    d=Path(tmp)
    (d/'bin').mkdir();(d/'tmp').mkdir();(d/'dev').mkdir()
    shutil.copy2(binary,d/'bin/bash')
    script=r'''set -e
PATH=
printf 'a\0b\n' > /tmp/input
sed 's/./X/g' /tmp/input > /tmp/output
IFS= read -r value < /tmp/output
[[ $value == XXX ]]
sed 's/\x00/Q/' /tmp/input > /tmp/output
IFS= read -r value < /tmp/output
[[ $value == aQb ]]
printf a > /tmp/input
sed q /tmp/input > /tmp/output
IFS= read -r value < /tmp/output
[[ $value == a ]]
for ((i=0;i<32;i++)); do sed 's/a/A/' /tmp/input; done
printf '\nSED-ONLY-ROOTFS-OK\n'
'''
    p=subprocess.run([bwrap,'--unshare-all','--bind',str(d),'/','--dev','/dev',
                      '--setenv','PATH','','--setenv','LC_ALL','C','/bin/bash','-c',script],
                     capture_output=True,timeout=30)
    print(p.stdout.decode(errors='replace'),end='');print(p.stderr.decode(errors='replace'),end='')
    if p.returncode and (b'Operation not permitted' in p.stderr or b'No permissions' in p.stderr):
        print('UNAVAILABLE: host denies creation of the private namespace');raise SystemExit(77)
    assert p.returncode==0 and p.stdout==b'A'*32+b'\nSED-ONLY-ROOTFS-OK\n',p
print('sol-sed-rootfs: production static binary passed')
