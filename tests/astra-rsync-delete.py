#!/usr/bin/env python3
"""Multiple source roots must not delete one another's transferred entries."""
from pathlib import Path
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
binary=str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix='rsync-delete-') as tmp:
    outputs=[]
    for name in ['stock','builtin']:
        root=Path(tmp)/name;root.mkdir()
        for d in ['a','b','dest']:(root/d).mkdir()
        (root/'a/one').write_text('one\n');(root/'b/two').write_text('two\n');(root/'dest/stale').write_text('stale\n')
        cmd=[shutil.which('rsync'),'-a','--delete','a/','b/','dest/'] if name=='stock' else [binary,'--noprofile','--norc','-c','PATH=; rsync -a --delete a/ b/ dest/']
        p=subprocess.run(cmd,cwd=root,capture_output=True,timeout=10)
        files={p.name:p.read_bytes().decode() for p in (root/'dest').iterdir()}
        print(name,p.returncode,files,p.stderr,flush=True)
        outputs.append((p.returncode,files))
    assert outputs[0]==outputs[1],outputs
print('PASS merged multi-source deletion matches stock')
