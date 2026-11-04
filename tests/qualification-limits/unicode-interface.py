#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the new descriptor API with the complete Unicode 17 byte corpus."""
import argparse
import importlib.util
from pathlib import Path
import tempfile
from guest import digest, entrypoint, guard, require_bash_5320, run, save


def main():
    p = argparse.ArgumentParser()
    p.add_argument("shell"); p.add_argument("corpus"); p.add_argument("output")
    p.add_argument("--module")
    a = p.parse_args(); guard()
    a.shell = str(Path(a.shell).resolve())
    if a.module: a.module = str(Path(a.module).resolve())
    bash_version = require_bash_5320(a.shell)
    spec = importlib.util.spec_from_file_location("corpus_data",Path(__file__).with_name("unicode-corpus.py"))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    rows = module.corpus(a.corpus)
    controls = [dict(line="empty",hex="",clusters=[]),
                dict(line="ascii",hex="6162",clusters=["61","62"]),
                dict(line="crlf",hex="0d0a",clusters=["0d0a"]),
                dict(line="nul",hex="610062",clusters=["61","00","62"])]
    checks = []
    with tempfile.TemporaryDirectory(prefix="qual-utf8-") as td:
        root = Path(td)
        script = ['set -u']
        if a.module:
            script += ['[[ $(type -t utf8 || :) != builtin ]] || exit 125',
                       'enable -f "$1" utf8 || exit 125']
        else:
            script += ['[[ $(type -t utf8 || :) == builtin ]] || exit 125']
        expected = []
        for i,row in enumerate(controls + rows):
            (root/f'{i}.in').write_bytes(bytes.fromhex(row['hex']))
            cases = [(f'{i}-length',f'utf8 length-fd 9 9<{i}.in',
                      (str(len(row['clusters']))+'\n').encode())]
            for j,cluster in enumerate(row['clusters']):
                cases.append((f'{i}-slice-{j}',f'utf8 slice-fd 9 {j} {j+1} 9<{i}.in',bytes.fromhex(cluster)))
            # Empty and out-of-range slices are raw empty output, not a newline.
            if i < len(controls):
                cases += [(f'{i}-empty',f'utf8 slice-fd 9 0 0 9<{i}.in',b''),
                          (f'{i}-beyond',f'utf8 slice-fd 9 100 101 9<{i}.in',b'')]
            for name,cmd,want in cases:
                script += [f'{cmd} >{name}.out 2>{name}.err',f'printf "%s\\n" "$?" >{name}.rc']
                expected.append((name,row['line'],want,0,False))
        (root/'oversize.in').write_bytes(b'A'*(16*1024*1024+1))
        for name,cmd,status in [
            ('bad-fd','utf8 length-fd 9 9<&-',1),
            ('fd-syntax','utf8 length-fd 1x',2),
            ('range','utf8 slice-fd 9 2 1 9<3.in',2),
            ('overflow','utf8 slice-fd 9 0 18446744073709551616 9<3.in',2),
            ('no-variable','utf8 slice-fd 9 0 3 -V value 9<3.in',2),
            ('bounded','utf8 length-fd 9 9<oversize.in',1)]:
            script += [f'{cmd} >{name}.out 2>{name}.err',f'printf "%s\\n" "$?" >{name}.rc']
            expected.append((name,'control',b'',status,True))
        script += ['exec 9<3.in', 'utf8 length-fd 9 >ownership-count.out',
                   "/usr/bin/python3 -c 'import os; print(os.lseek(9,0,os.SEEK_CUR))' >ownership.out",
                   'exec 9<&-']
        (root/'case.sh').write_text('\n'.join(script)+'\n')
        observed = run([a.shell,'--noprofile','--norc',str(root/'case.sh'),a.module or ''],
                       timeout=150,cwd=root)
        for name,line,want,status,diagnostic in expected:
            paths = [root/(name+suffix) for suffix in ('.out','.err','.rc')]
            present = all(x.exists() for x in paths)
            actual,err,rc = (x.read_bytes() for x in paths) if present else (b'',b'',b'')
            checks.append(dict(case=name,line=line,complete=present,status_text=rc.decode(errors='replace'),
                               stdout_hex=actual.hex(),stderr_hex=err.hex(),expected_hex=want.hex(),
                               matches=present and actual==want and rc==f'{status}\n'.encode() and bool(err)==diagnostic))
        ownership = ((root/'ownership.out').exists() and (root/'ownership.out').read_bytes()==b'3\n' and
                     (root/'ownership-count.out').read_bytes()==b'3\n')
        result = 'PASS' if all(x['matches'] for x in checks) and ownership and observed['status']==0 else 'FAIL'
        if observed['status'] in (125,126,127) or not all(x['complete'] for x in checks): result='ERROR'
    save(a.output,dict(scope='0.1.4 descriptor interface; not frozen TEXT evidence',result=result,
                       bash_version=bash_version,
                       shell_sha256=digest(a.shell),module_sha256=digest(a.module) if a.module else None,
                       corpus_sha256=module.PIN,total_rows=766,nul_rows=74,nul_cluster_slices=164,
                       descriptor_retained_at_eof=ownership,execution=observed,checks=checks))
    return {'PASS':0,'FAIL':1,'ERROR':125}[result]


if __name__ == '__main__': entrypoint(main)
