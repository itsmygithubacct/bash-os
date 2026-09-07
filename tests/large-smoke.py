#!/usr/bin/env python3
"""Per-module checks for the larger imports, using private files and loopback."""
import http.server
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import zlib

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
names = 'awk jq bc vec sv cron curl fw dhcpd fdisk strace coreutils bsdgames'.split()
selected = set(sys.argv[2:] or names)
checks = 0

def run(*args, data=None, rc=0, env=None):
    global checks
    child_env = {**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC', **(env or {})}
    if os.environ.get('LARGE_LOAD_ENV'):
        child_env.update(BASH_ENV=os.environ['LARGE_LOAD_ENV'],
                         LD_PRELOAD=os.environ['LARGE_ASAN_LIB'],
                         ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                         UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    p = subprocess.run([binary, '-e', '-o', 'pipefail', '-c', 'PATH=; "$@"', '_', *map(str, args)],
                       input=data, capture_output=True, timeout=25, env=child_env)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, (args, p.stderr)
    assert p.returncode == rc, (args, p.returncode, p.stdout, p.stderr)
    checks += 1
    return p.stdout

def parity(name, *args, data=None):
    external = shutil.which(name, path='/usr/bin:/bin')
    if not external:
        raise RuntimeError(f'missing comparison program: {name}')
    p = subprocess.run([external, *map(str, args)], input=data, capture_output=True,
                       timeout=15, env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'})
    actual = run(name, *args, data=data, rc=p.returncode)
    assert actual == p.stdout, (name, args, actual, p.stdout)

with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)
    env = {'TEST_DIR': str(d)}
    for name in names:
        if name not in selected: continue
        before = checks
        assert run('type', '-t', name) == b'builtin\n'
        if name == 'awk':
            rows = b'alpha 10\nbeta -2\nalpha 7\n'
            for program in ['{print $1, NF, NR}', '{s += $2} END {print s}',
                            '$2 > 0 {print $0}', 'BEGIN {for(i=1;i<=5;i++) print i*i}',
                            'function twice(x) {return x*2} {print twice($2)}',
                            'BEGIN {s="banana"; n=gsub(/a/,"X",s); print n,s}',
                            '{a[$1]+=$2} END {print a["alpha"], a["beta"]}',
                            'BEGIN {print substr("abcdef",2,3), index("abcdef","cd")}',
                            'BEGIN {print sprintf("%04d",12)}']:
                parity(name, program, data=rows)
            parity(name, '-F', ':', '-v', 'x=7', '{print $2+x}', data=b'a:5\nb:9\n')
            (d/'empty').write_text('')
            parity(name, '-f', d/'empty', data=rows)
            (d/'one').write_text('BEGIN {print 1}')
            (d/'two').write_text('BEGIN {print 2}')
            parity(name, '-f', d/'one', '-f', d/'two', data=b'')
            run(name, '{print}', d/'missing', rc=2)
            run(name, '--invalid', rc=2)
            run('eval', 'awk "{print}" < /dev/null; awk "{print}" <<< reused', data=b'')
        elif name == 'jq':
            for program, value in [('.a', {'a':[1,2]}), ('map(. * 2)',[1,2,3]),
                ('.[] | select(. > 1)',[1,2,3]), ('keys', {'b':1,'a':2}),
                ('length',[1,2,3]), ('reverse',[1,2,3]), ('sort | unique',[3,1,1,2]),
                ('to_entries | from_entries',{'x':3}), ('getpath(["a",0])',{'a':[4]}),
                ('if . > 0 then "yes" else "no" end',2), ('split(":")','a:b:c'),
                ('[range(1;5)]',None), ('..',{'a':[1,2]})]:
                parity(name, '-c', program, data=json.dumps(value).encode()+b'\n')
            parity(name, '-r', '.name', data=b'{"name":"hello"}\n')
            parity(name, '-s', '-c', 'add', data=b'1\n2\n3\n')
            run(name, '.', data=b'{broken', rc=1)
        elif name == 'bc':
            for expr in ['12345678901234567890+98765432109876543210', '2^100',
                         'scale=12; 22/7', 'scale=4; sqrt(2)', '17%5',
                         'a=12; a*3; a-5', 'length(123456); scale(1.250)']:
                parity(name, data=(expr+'\n').encode())
            parity(name, '-l', data=b'scale=8; s(1); c(0); a(1)\n')
        elif name == 'vec':
            run('eval', '''a=(1 2 3 4)
vec from-array -T f64 a -h v
[[ $(vec sum "$v") == 10 && $(vec dot "$v" "$v") == 30 ]]
vec scale "$v" 2
vec save "$v" "$TEST_DIR/vector"
vec load "$TEST_DIR/vector" -h w
vec to-array "$w" b
[[ ${b[*]} == '2 4 6 8' ]]
vec export-npy "$w" "$TEST_DIR/vector.npy"
vec import-npy "$TEST_DIR/vector.npy" -h n
[[ $(vec sum "$n") == 20 ]]
vec free "$v"; vec free "$w"; vec free "$n"
''', env=env)
            raw=(d/'vector.npy').read_bytes()
            assert raw[:6] == b'\x93NUMPY'
            assert struct.unpack('<4d',raw[-32:]) == (2,4,6,8)
            run(name, 'get', '99999', '0', rc=2)
        elif name == 'sv':
            for directory in ['services/fixture','run','logs']: (d/directory).mkdir(parents=True)
            service=d/'services/fixture/run'
            service.write_text('#!'+binary+'\nprintf supervised > "$TEST_DIR/service-result"\n')
            service.chmod(0o700)
            sv_env={**env,'BASHSV_DIR':str(d/'services'),'BASHSV_RUNDIR':str(d/'run'),
                    'BASHSV_LOGDIR':str(d/'logs')}
            run(name, 'once', 'fixture', env=sv_env)
            assert (d/'service-result').read_bytes() == b'supervised'
            run(name,'status','fixture',env=sv_env)
        elif name == 'cron':
            for schedule, epoch in [('@hourly',3600),('@daily',86400),('*/15 * * * *',900),
                                    ('0 0 2 JAN *',86400)]:
                assert run(name,'next','--from','1',*schedule.split()) == f'{epoch}\n'.encode()
            for directory in ['spool/atjobs','spool/tabs','etc','cron.d','out','mail']:
                (d/directory).mkdir(parents=True)
            run(name,'run','--once',env={'BASHCRON_SPOOL_DIR':str(d/'spool'),
                'BASHCRON_ETC_DIR':str(d/'etc'),'BASHCRON_CROND_DIR':str(d/'cron.d'),
                'BASHCRON_OUTPUT_DIR':str(d/'out'),'BASHCRON_MAIL_DIR':str(d/'mail'),
                'BASHCRON_NOW_EPOCH':'86400','BASHCRON_STATE_FILE':str(d/'state')})
            assert (d/'state').read_text().strip() == '1440'
        elif name == 'curl':
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self,*args): pass
                def do_GET(self):
                    if self.path == '/redirect':
                        self.send_response(302); self.send_header('Location','/binary')
                        self.send_header('Content-Length','0'); self.end_headers(); return
                    if self.path == '/chunked':
                        self.send_response(200); self.send_header('Transfer-Encoding','chunked')
                        self.end_headers(); self.wfile.write(b'3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n'); return
                    payload=b'a\x00b\xff\n'
                    self.send_response(404 if self.path == '/missing' else 200)
                    self.send_header('Content-Length',str(len(payload)));self.end_headers()
                    self.wfile.write(payload)
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            url=f'http://127.0.0.1:{server.server_port}'
            try:
                assert run(name,'-s',url+'/binary') == b'a\x00b\xff\n'
                assert run(name,'-sL',url+'/redirect') == b'a\x00b\xff\n'
                assert run(name,'-s',url+'/chunked') == b'abcde'
                run(name,'-sf',url+'/missing',rc=22)
                run(name,'-s','-o',d/'download',url+'/binary')
                assert (d/'download').read_bytes() == b'a\x00b\xff\n'
            finally: server.shutdown(); server.server_close()
        elif name == 'fw':
            text=run(name,'-B','nft','-n','allow','192.0.2.1','-p','tcp','-d','443')
            assert b'192.0.2.1' in text and b'443' in text
            text=run(name,'-B','iptables','-n','deny','192.0.2.2')
            assert b'192.0.2.2' in text and b'DROP' in text
        elif name == 'dhcpd':
            lease=d/'leases'
            run(name,'lease-add','02:00:00:00:00:01','192.0.2.100','-l',lease,'-t','600')
            assert b'192.0.2.100' in run(name,'lease-list','-l',lease)
            run(name,'lease-remove','02:00:00:00:00:01','-l',lease)
            assert b'192.0.2.100' not in run(name,'lease-list','-l',lease)
            config=d/'dhcp.conf';config.write_text('pool 192.0.2.100 192.0.2.110\nnetmask 255.255.255.0\nserver_id 192.0.2.1\n')
            request=bytearray(240);request[:4]=bytes([1,1,6,0]);request[4:8]=b'abcd'
            request[28:34]=bytes.fromhex('020000000001');request[236:]=bytes.fromhex('63825363')
            request+=bytes.fromhex('350101ff')
            reply=bytes.fromhex(run(name,'respond',request.hex(),'-c',config,'-l',lease).decode().strip())
            assert reply[0] == 2 and reply[4:8] == b'abcd' and reply[16:20] == bytes([192,0,2,100])
            run(name,'selftest-decline')
        elif name == 'fdisk':
            for label in ['mbr','gpt']:
                disk=d/(label+'.img')
                with disk.open('wb') as f: f.truncate(16*1024*1024)
                spec='2048,4096,83' if label=='mbr' else '2048,4096,,fixture'
                run(name,'--create-'+label,disk,spec)
                run(name,'--verify',disk)
                raw=disk.read_bytes()
                assert raw[510:512] == b'\x55\xaa'
                if label=='mbr': assert struct.unpack_from('<II',raw,454)==(2048,4096)
                else:
                    for offset in [512,len(raw)-512]:
                        hdr=bytearray(raw[offset:offset+92]);assert hdr[:8]==b'EFI PART'
                        crc=struct.unpack_from('<I',hdr,16)[0];hdr[16:20]=b'\0'*4
                        assert zlib.crc32(hdr)==crc
                        lba,count,size,crc=struct.unpack_from('<QIII',hdr,72)
                        assert zlib.crc32(raw[lba*512:lba*512+count*size])==crc
                    assert struct.unpack_from('<QQ',raw,1024+32)==(2048,6143)
        elif name == 'strace':
            run(name,'-o',d/'trace','--','/bin/true')
            assert b'execve(' in (d/'trace').read_bytes()
            run(name,'-o',d/'trace','--','/bin/sh','-c','exit 7',rc=7)
        elif name == 'coreutils':
            for verb,args,data in [('factor',['1234567890','97'],None),
                ('tac',[],b'a\nb\nlast'),('numfmt',['--to=iec','1024','4096'],None),
                ('fmt',['-w','20'],b'one two three four five six seven eight nine\n')]:
                p=subprocess.run(['/usr/bin/'+verb,*args],input=data,capture_output=True)
                assert run(name,verb,*args,data=data,rc=p.returncode)==p.stdout
            order=run(name,'tsort',data=b'a b\na c\nb d\nc d\n').splitlines()
            assert order.index(b'a')<order.index(b'b')<order.index(b'd') and order.index(b'a')<order.index(b'c')<order.index(b'd')
            assert sorted(run(name,'shuf','-i','1-10').splitlines()) == sorted(str(i).encode() for i in range(1,11))
            assert int(run(name,'nproc')) > 0
            (d/'source').write_bytes(b'fixture')
            run(name,'install','-m','600',d/'source',d/'installed')
            assert (d/'installed').read_bytes()==b'fixture' and stat.S_IMODE((d/'installed').stat().st_mode)==0o600
            run(name,'mknod',d/'fifo','p'); assert stat.S_ISFIFO((d/'fifo').stat().st_mode)
            run(name,'shred','-n','0','-z',d/'installed');assert (d/'installed').read_bytes()==b'\0'*7
            for verb,flag in [('fmt','-w'),('shred','-n'),('install','-m'),('mknod','-m')]:
                run(name,verb,d/'source',flag,'invalid',rc=2)
        elif name == 'bsdgames':
            run(name,'selftest')
            for game in ['trek','snake','tetris','worm','worms','wump','sail']:
                run(name,game,'--selftest',env={'BASH_BSDGAMES_STATE_ROOT':str(d/'games')})
            assert run(name,'rot13',data=b'Hello World\n') == b'Uryyb Jbeyq\n'
            assert run(name,'primes','2','20').split()==[b'2',b'3',b'5',b'7',b'11',b'13',b'17',b'19']
            run(name,'trek','--seed','1',data=b'move\nimpulse\nphasers\ntorpedo\nquit\n')
        print(f'{name}: {checks-before} checks passed',flush=True)
print(f'large-smoke: {checks} checks passed')
