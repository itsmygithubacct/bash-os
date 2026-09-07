#!/usr/bin/env python3
"""Prove that the executable contains exactly the selected collection commands."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'config'))
from loadables import parse_list
binary=Path(sys.argv[1]).resolve()
manifest=Path(sys.argv[2]) if len(sys.argv)>2 else binary.with_name(binary.name+'.manifest.json')
selection=json.loads(manifest.read_text())
assert binary.stat().st_size==selection['bytes'], 'binary size differs from manifest'
assert hashlib.sha256(binary.read_bytes()).hexdigest()==selection['binary_sha256'], 'binary checksum differs from manifest'
names=selection['names']
all_names=list(dict.fromkeys([*parse_list(root/'config/bash-loadables.list'),*names]))
script='PATH=\n'
for name in all_names:
    script+=f'if [[ $(type -t {shlex.quote(name)}) == builtin ]]; then printf "%s\\n" {shlex.quote(name)}; fi\n'
script+='printf "shell=%s\\n" "$((2+3))"\n'
command=[*shlex.split(os.environ.get('BASH_OS_RUNNER','')),str(binary),'-c',script]
p=subprocess.run(command,capture_output=True,text=True,timeout=90)
assert p.returncode==0,(p.returncode,p.stderr)
lines=p.stdout.splitlines()
assert lines[-1]=='shell=5',p.stdout
assert set(lines[:-1])==set(names),{'missing':set(names)-set(lines[:-1]),'unexpected':set(lines[:-1])-set(names)}
assert len(lines[:-1])==len(names)
print(f'profile-smoke: exactly {len(names)} injected builtins; shell arithmetic works')
