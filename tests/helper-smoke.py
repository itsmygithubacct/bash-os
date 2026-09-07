#!/usr/bin/env python3
"""Check helper-backed loadables against independent formats and private fixtures."""
import bz2
import gzip
import errno
import fcntl
import pty
import select
import termios
import time
import json
import lzma
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import tomllib
import zlib

binary=str(Path(sys.argv[1] if len(sys.argv)>1 else 'out/bash').resolve())
checks=0

def run(*args,data=None,rc=0,env=None,terminal=False):
    global checks
    child_env={**os.environ,'LC_ALL':'C','TZ':'UTC',**(env or {})}
    if os.environ.get('HELPER_LOAD_ENV'):
        child_env.update(BASH_ENV=os.environ['HELPER_LOAD_ENV'],LD_PRELOAD=os.environ['HELPER_ASAN_LIB'],
                         ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    command=[binary,'-e','-o','pipefail','-c','PATH=; "$@"','_',*map(str,args)]
    if terminal:
        master,slave=pty.openpty()
        def attach():
            os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
        proc=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,env=child_env,preexec_fn=attach)
        os.close(slave);output=bytearray();deadline=time.monotonic()+20
        try:
            while True:
                assert time.monotonic()<deadline,'terminal test timed out'
                if select.select([master],[],[],0.1)[0]:
                    try: chunk=os.read(master,65536)
                    except OSError as exc:
                        if exc.errno==errno.EIO: break
                        raise
                    if not chunk: break
                    output.extend(chunk)
            p=subprocess.CompletedProcess(command,proc.wait(timeout=2),bytes(output),bytes(output))
        finally:
            if proc.poll() is None: proc.kill();proc.wait()
            os.close(master)
    else:
        p=subprocess.run(command,input=data,capture_output=True,timeout=20,env=child_env,start_new_session=True)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr,(args,p.stderr)
    assert p.returncode==rc,(args,p.returncode,p.stdout[:200],p.stderr[:4000])
    checks+=1
    return p.stdout

with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp);env={'TEST_DIR':str(d)}
    names='pcre zlib zcat netids more less top slabtop ncdu tui vmstat toml sqlite vi vt utf8 dialog whiptail'
    for name in names.split(): assert run('type','-t',name)==b'builtin\n'
    run('eval', r'''pcre match '(?<=id:)([0-9]+)' 'id:123'
[[ ${BPCRE_MATCH[0]} == 123 && ${BPCRE_MATCH[1]} == 123 ]]
''')
    assert run('pcre','subst','([0-9]+)','<$1>','a12b34','-g')==b'a<12>b<34>\n'
    assert run('pcre','find-all','[0-9]+','a12b34')==b'12\n34\n'
    run('pcre','match','[','text',rc=1)
    payload=bytes(range(256))*1024
    codecs={'gzip':(gzip.compress,gzip.decompress),'zlib':(zlib.compress,zlib.decompress),
            'deflate':(lambda x:zlib.compress(x,wbits=-15),lambda x:zlib.decompress(x,wbits=-15)),
            'xz':(lzma.compress,lzma.decompress),'lzma':(lambda x:lzma.compress(x,format=lzma.FORMAT_ALONE),lzma.decompress),
            'bzip2':(bz2.compress,bz2.decompress)}
    for fmt,(compress,decompress) in codecs.items():
        assert run('zlib','-f',fmt,data=compress(payload))==payload
        assert decompress(run('zlib','-e','-f',fmt,data=payload))==payload
        run('zlib','-f',fmt,data=compress(payload)[:-5],rc=1)
    packed=run('zlib','-e','-f','zstd',data=payload)
    p=subprocess.run(['/usr/bin/zstd','-dc'],input=packed,capture_output=True,check=True)
    assert p.stdout==payload
    packed=subprocess.run(['/usr/bin/zstd','-c'],input=payload,capture_output=True,check=True).stdout
    assert run('zlib','-f','zstd',data=packed)==payload
    run('zlib','-f','zstd',data=packed[:-2],rc=1)
    assert run('zcat',data=gzip.compress(b'first')+gzip.compress(b'second'))==b'firstsecond'
    rules=d/'rules';rules.write_text('alert udp any any -> any any (msg:"fixture"; content:"hello"; sid:1001; rev:1;)\n')
    run('netids','compile','-S',rules)
    body=b'hello packet'
    udp=struct.pack('!HHHH',12345,8000,8+len(body),0)+body
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),1,0,64,17,0,bytes([192,0,2,1]),bytes([192,0,2,2]))+udp
    frame=b'\0'*12+b'\x08\x00'+ip
    capture=d/'traffic.pcap';capture.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+
        struct.pack('<IIII',1,0,len(frame),len(frame))+frame)
    run('netids','scan','-r',capture,'-S',rules,'-o',d/'eve')
    events=[json.loads(line) for line in (d/'eve').read_text().splitlines()]
    assert any(e.get('alert',{}).get('signature_id')==1001 for e in events),events
    content=b'one\ntwo\nthree\n'
    (d/'text').write_bytes(content)
    for name in ['more','less']: assert run(name,d/'text',data=b'')==content
    assert b'PID' in run('top','--once','-r','3')
    (d/'proc').mkdir()
    (d/'proc/slabinfo').write_text('slabinfo - version: 2.1\n# name <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>\nfixture 10 20 64 64 1 : tunables 0 0 0 : slabdata 1 1 0\n')
    assert b'fixture' in run('slabtop','-o',env={'BASHOS_PROC_ROOT':str(d/'proc')})
    assert b'procs' in run('vmstat')
    (d/'usage').mkdir();(d/'usage/data').write_bytes(b'x'*123)
    expected=subprocess.run(['/usr/bin/du','--apparent-size','--block-size=1','-s',str(d/'usage')],capture_output=True,check=True).stdout.split()[0]
    assert run('ncdu','-a','-t',d/'usage').strip()==expected
    run('eval','tui init; tui move 0 0; tui addstr fixture; tui refresh; tui end',terminal=True)
    config=d/'example.toml';config.write_text('title="example"\n[app]\nports=[80,443]\nenabled=true\n')
    run('toml','validate',config)
    assert run('toml','get',config,'app.ports[1]')==b'443\n'
    assert run('toml','count',config,'app.ports')==b'2\n'
    assert tomllib.loads(run('toml','emit',config).decode())==tomllib.loads(config.read_text())
    (d/'bad.toml').write_text('x=[');run('toml','validate',d/'bad.toml',rc=1)
    run('eval', '''sqlite open "$TEST_DIR/store.db" -h db
sqlite exec "$db" 'create table records (id integer, value text)'
sqlite prepare "$db" 'insert into records values (?,?)' -h st
sqlite bind "$st" 1 7 -t INTEGER
sqlite bind "$st" 2 'fixture value'
if sqlite step "$st"; then exit 1; else [[ $? == 1 ]]; fi
sqlite finalize "$st"
[[ $(sqlite changes "$db") == 1 ]]
sqlite transaction "$db" BEGIN
sqlite exec "$db" 'insert into records values (8,"rollback")'
sqlite transaction "$db" ROLLBACK
sqlite close "$db"
''',env=env)
    with sqlite3.connect(d/'store.db') as db: assert db.execute('select * from records').fetchall()==[(7,'fixture value')]
    run('eval', """sqlite open :memory: -h db
for value in zz 0g 1; do
  sqlite prepare "$db" 'select ?' -h st
  if sqlite bind "$st" 1 "$value" -t BLOB; then exit 1; else [[ $? == 2 ]]; fi
done
[[ $(sqlite stats) == $'active_stmts 0\n'* ]]
sqlite prepare "$db" 'select typeof(?1),length(?1)' -h st
sqlite bind "$st" 1 '' -t BLOB
sqlite step "$st" -V row
[[ $row == $'blob\t0' ]]
sqlite finalize "$st"; sqlite close "$db"
""")
    run('vi','selftest')
    (d/'edit').write_text('alpha\nbeta\n')
    (d/'keys').write_bytes(b'iadded \x1b:wq\n')
    run('vi','--keys',d/'keys',d/'edit',data=b'')
    assert (d/'edit').read_text()=='added alpha\nbeta\n'
    run('eval', '''vt new -h v -W 12 -H 3
vt feed "$v" $'hello\\e[2;1Hworld\\e]2;fixture\\a'
[[ $(vt title "$v") == fixture && $(vt cursor "$v") == '2 6' ]]
vt render "$v" > "$TEST_DIR/grid"
vt resize "$v" -W 14 -H 4
[[ $(vt size "$v") == '4 14' ]]
vt scrollback-enable "$v" -L 4
vt feed "$v" $'a\n\r b\n\r c\n\r d\n\r e\n\r'
handles=()
for ((i=0;i<31;i++)); do vt clone "$v" -h clone; handles+=("$clone"); done
if vt clone "$v" -h overflow; then exit 1; else [[ $? == 1 ]]; fi
for clone in "${handles[@]}"; do vt free "$clone"; done
vt free "$v"
''',env=env)
    assert (d/'grid').read_text().splitlines()[0].startswith('hello')
    assert run('utf8','upper','Straße')=='STRASSE\n'.encode()
    assert run('utf8','length','e\u0301👩\u200d💻','-T','grapheme')==b'2\n'
    assert run('utf8','normalize','NFC','e\u0301')=='é\n'.encode()
    assert run('utf8','casefold','Straße')==b'strasse\n'
    for name in ['dialog','whiptail']:
        assert run(name,'--stdout','--inputbox','label','8','30',data=b'answer\n')==b'answer\n'
        run(name,'--yesno','label','8','30',data=b'no\n',rc=1)
print(f'helper-smoke: {checks} checks passed')
