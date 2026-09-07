#!/usr/bin/env python3
"""Exercise crypto, protocol, account, Git and parser imports in private fixtures."""
import base64
import concurrent.futures
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
selected = set(sys.argv[2:])
checks = 0

def run(*args, data=None, rc=0, env=None):
    global checks
    child_env = {**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC', **(env or {})}
    if os.environ.get('FINAL_LOAD_ENV'):
        child_env.update(BASH_ENV=os.environ['FINAL_LOAD_ENV'], LD_PRELOAD=os.environ['FINAL_ASAN_LIB'],
                         ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                         UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    p = subprocess.run([binary, '-e', '-o', 'pipefail', '-c', 'PATH=; "$@"', '_', *map(str, args)],
                       input=data, capture_output=True, timeout=30, env=child_env, start_new_session=True)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, (args, p.stderr)
    assert p.returncode == rc, (args, p.returncode, p.stdout[:300], p.stderr[:4000])
    checks += 1
    return p.stdout

def host(*args, data=None, env=None):
    p = subprocess.run(list(map(str, args)), input=data, capture_output=True,
                       timeout=30, env={**os.environ, **(env or {})})
    assert p.returncode == 0, (args,p.returncode,p.stdout[:300],p.stderr[:4000])
    return p.stdout

def raw_public(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def crypto(d):
    msg = bytes(range(256)) * 31
    for name in ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'blake2b']:
        assert run('crypto', name, '-x', data=msg).strip().decode() == hashlib.new(name, msg).hexdigest()
        assert run('crypto', name, '-x', data=b'').strip().decode() == hashlib.new(name, b'').hexdigest()
    for name in ['md5', 'sha1', 'sha256', 'sha512']:
        assert run('crypto', 'hmac-'+name, '-k', '0b'*20, '-x', data=msg).strip().decode() == hmac.new(b'\x0b'*20, msg, name).hexdigest()
    expected = HKDF(algorithm=hashes.SHA256(), length=42, salt=b'salt', info=b'info').derive(b'input')
    assert run('crypto', 'hkdf-sha256', '-s', b'salt'.hex(), '-k', b'input'.hex(), '-i', b'info'.hex(), '-L', 42, '-x').strip() == expected.hex().encode()
    assert run('crypto', 'pbkdf2', '-a', 'sha256', '-s', b'salt'.hex(), '-p', 'fixture', '-i', 1000, '-L', 32, '-x').strip() == hashlib.pbkdf2_hmac('sha256', b'fixture', b'salt', 1000).hex().encode()
    for name, impl in [('aes-gcm', AESGCM), ('chacha20-poly1305', ChaCha20Poly1305)]:
        key, nonce, aad = bytes(range(32)), bytes(range(12)), b'header'
        cipher = impl(key).encrypt(nonce, msg, aad)
        args = ['crypto', name, '-k', key.hex(), '-n', nonce.hex(), '-A', aad.hex()]
        assert run(*args, '-e', data=msg) == cipher
        assert run(*args, '-d', data=cipher) == msg
        run(*args, '-d', data=cipher[:-1]+bytes([cipher[-1]^1]), rc=1)
        assert run(*args, '-e', data=b'') == impl(key).encrypt(nonce, b'', aad)
    seed = bytes(range(32)); ed = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pub = raw_public(ed.public_key())
    assert run('crypto', 'ed25519-pub', '-k', seed.hex(), '-x').strip() == pub.hex().encode()
    sig = run('crypto', 'ed25519-sign', '-k', seed.hex(), data=msg)
    assert sig == ed.sign(msg)
    run('crypto', 'ed25519-verify', '-k', pub.hex(), '-s', sig.hex(), data=msg)
    run('crypto', 'ed25519-verify', '-k', pub.hex(), '-s', sig.hex(), data=msg+b'!', rc=1)
    x = x25519.X25519PrivateKey.from_private_bytes(seed)
    peer = x25519.X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    assert run('crypto', 'x25519-pub', '-k', seed.hex(), '-x').strip() == raw_public(x.public_key()).hex().encode()
    assert run('crypto', 'x25519-shared', '-k', seed.hex(), '-p', raw_public(peer.public_key()).hex(), '-x').strip() == x.exchange(peer.public_key()).hex().encode()
    sk = '00'*31+'01'; ec_key = ec.derive_private_key(1, ec.SECP256R1())
    pub = ec_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert run('crypto', 'ecdsa-p256-pub', '-k', sk, '-x').strip() == pub.hex().encode()
    sig = run('crypto', 'ecdsa-p256-sign', '-k', sk, data=msg)
    assert len(sig) == 64
    der = utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big'))
    ec_key.public_key().verify(der, msg, ec.ECDSA(hashes.SHA256()))
    run('crypto', 'ecdsa-p256-verify', '-k', pub.hex(), '-s', sig.hex(), data=msg)
    for payload in [b'', b'a', b'abc', bytes(range(256))]:
        encoded = run('crypto', 'base64url', '-e', '--no-pad', data=payload).strip()
        assert encoded.decode() == b64url(payload)
        assert run('crypto', 'base64url', '-d', data=encoded) == payload
    jwk = json.loads(run('acme', 'jwk-public', '-k', sk))
    assert jwk == {'crv':'P-256', 'kty':'EC', 'x':b64url(pub[1:33]), 'y':b64url(pub[33:])}
    thumb = b64url(hashlib.sha256(json.dumps(jwk, sort_keys=True, separators=(',', ':')).encode()).digest())
    assert run('acme', 'jwk-thumbprint', '-k', sk).strip().decode() == thumb
    assert run('acme', 'key-authorization', 'fixture', '-k', sk).strip().decode() == 'fixture.'+thumb
    jws = json.loads(run('acme', 'jws-sign', '-k', sk, '--url', 'https://example.invalid/acme', '--nonce', 'fixture', '--jwk', '-d', '{"ok":true}'))
    signature = base64.urlsafe_b64decode(jws['signature']+'==')
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big'))
    ec_key.public_key().verify(der, (jws['protected']+'.'+jws['payload']).encode(), ec.ECDSA(hashes.SHA256()))
    for flag, version in [('-r',4), ('-t',1), ('-6',6), ('-7',7)]:
        values = [uuid.UUID(line) for line in run('uuidgen', flag, '-C', 8).decode().splitlines()]
        assert len(set(values)) == 8 and all(v.version == version and v.variant == uuid.RFC_4122 for v in values)
    for flag, fn in [('-m',uuid.uuid3), ('-s',uuid.uuid5)]:
        assert run('uuidgen', flag, '-n', '@dns', '-N', 'example.invalid').strip().decode() == str(fn(uuid.NAMESPACE_DNS, 'example.invalid'))
    assert run('wg', 'pubkey', data=base64.b64encode(seed)+b'\n').strip() == base64.b64encode(raw_public(x.public_key()))
    generated = base64.b64decode(run('wg', 'genkey').strip(), validate=True)
    assert len(generated) == 32 and generated[0]&7 == 0 and generated[31]&0xc0 == 0x40
    assert run('totp', 'generate', '-t', 59, '-d', 8, '-k', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ').strip() == b'94287082'

def formats(d):
    repo = d/'repo'; host('git', 'init', '-q', repo)
    data = b'blob fixture\n'; file = d/'blob'; file.write_bytes(data)
    sha = host('git', '-C', repo, 'hash-object', '--stdin', data=data).strip().decode()
    assert run('obj', 'blob', file, '-r', repo).strip().decode() == sha
    assert run('obj', 'type', sha, '-r', repo) == b'blob\n'
    assert run('obj', 'cat', sha, '-r', repo) == data
    assert host('git', '-C', repo, 'cat-file', 'blob', sha) == data
    idx = repo/'.git/index'
    entries = f'100644 {sha} 0 zeta\n100755 {sha} 0 alpha\n'.encode()
    run('index', 'write', idx, data=entries)
    assert host('git', '-C', repo, 'ls-files', '--stage') == f'100755 {sha} 0\talpha\n100644 {sha} 0\tzeta\n'.encode()
    assert run('index', 'read', idx) == b'\n'.join(sorted(entries.splitlines(), key=lambda x:x.split()[-1]))+b'\n'
    host('git', '-C', repo, 'update-index', '--index-info', data=f'100644 {sha}\tfrom-git\n'.encode())
    assert b'from-git' in run('index', 'read', idx)
    raw = idx.read_bytes(); idx.write_bytes(raw[:-1]+bytes([raw[-1]^1])); run('index', 'read', idx, rc=1)
    run('index', 'write', idx, data=b''); assert run('index', 'read', idx) == b''
    assert host('git', '-C', repo, 'ls-files') == b''
    long_path = 'x'*5000
    run('index', 'write', idx, data=f'100644 {sha} 0 {long_path}\n'.encode())
    assert run('index', 'read', idx).endswith(long_path.encode()+b'\n')
    assert host('git', '-C', repo, 'ls-files').strip() == long_path.encode()
    run('index', 'write', idx, data=f'garbage {sha} 0 x\n'.encode(), rc=2)
    # A valid checksum must not make a missing terminator/padding acceptable.
    raw = idx.read_bytes(); body = bytearray(raw[:-20]); body[74:] = b'x'*(len(body)-74)
    idx.write_bytes(body+hashlib.sha1(body).digest()); run('index', 'read', idx, rc=1)
    packed, paired = d/'objects.pack', d/'objects.idx'
    run('pack', 'create', packed, '--idx', paired, '-r', repo, sha)
    assert sha.encode() in host('git', 'verify-pack', '-v', paired)
    run('pack', 'verify-idx', paired, packed)
    assert run('pack', 'cat', packed, paired, sha) == data
    run('pack', 'list-objects', paired)
    (d/'checks').write_bytes(bytes(range(256))*23)
    assert run('cksum', d/'checks') == host('/usr/bin/cksum', d/'checks')
    for size in [0, 1, 65536]:
        old, new, patch, out = [d/x for x in ['old','new','delta','result']]
        old.write_bytes(b'a'*size); new.write_bytes(b'a'*(size//2)+b'changed'+b'b'*(size//2))
        run('pkg', 'delta-make', old, new, patch)
        run('pkg', 'delta-apply', old, patch, out)
        assert out.read_bytes() == new.read_bytes()
    source = d/'source'; dest = d/'destination'; source.mkdir()
    (source/'data').write_bytes(bytes(range(256))*512)
    run('rsync', '-a', '--delta', '-e', binary+' -c', str(source)+'/', dest)
    assert (dest/'data').read_bytes() == (source/'data').read_bytes()
    (source/'data').write_bytes(b'changed')
    run('rsync', '-an', '-e', binary+' -c', str(source)+'/', dest)
    assert (dest/'data').stat().st_size == 256*512
    run('rsync', '-a', '--delta', '-e', binary+' -c', str(source)+'/', dest)
    assert (dest/'data').read_bytes() == b'changed'
    root = d/'integrity'; root.mkdir(); (root/'data').write_text('fixture\n')
    manifest = d/'manifest'; manifest.write_bytes(run('integrity', 'emit-manifest', '--root', root, '/'))
    run('integrity', 'verify', manifest, '--root', root, '/')
    (root/'data').write_text('changed\n'); run('integrity', 'verify', manifest, '--root', root, '/', rc=1)

def accounts(d):
    env = {'PHCLIB_PASSWD':str(d/'passwd'), 'PHCLIB_SHADOW':str(d/'shadow'), 'PHCLIB_GROUP':str(d/'group'),
           'BPW_LOCK_DIR':str(d/'locks'), 'BASHPASSWD_KERNEL_SECRETS':'0', 'PHCLIB_M':'1024', 'PHCLIB_T':'1'}
    (d/'passwd').write_text('fixture:x:12345:12345:Fixture:/nonexistent:/bin/bash\n')
    (d/'shadow').write_text('fixture:!:20000:0:99999:7:::\n')
    (d/'group').write_text('fixture:x:12345:\n')
    assert run('login', 'lookup', 'fixture', env=env) == b'12345:12345:/nonexistent:/bin/bash:Fixture\n'
    run('login', 'lookup', 'absent-fixture', env=env, rc=1)
    run('login', 'aging-check', 'fixture', 20001, env=env, rc=1)
    assert b'fixture' in run('passwd', 'info', 'fixture', env=env)
    run('passwd', 'set-fd', 'fixture', 0, data=b'fixture-password\n', env=env)
    run('login', 'aging-check', 'fixture', int(time.time()/86400), env=env)
    run('passwd', 'verify-fd', 'fixture', 0, data=b'fixture-password\n', env=env)
    run('passwd', 'verify-fd', 'fixture', 0, data=b'wrong\n', env=env, rc=1)
    run('passwd', 'lock', 'fixture', env=env)
    assert (d/'shadow').read_text().split(':')[1].startswith('!')
    run('passwd', 'unlock', 'fixture', env=env)
    run('passwd', 'verify-fd', 'fixture', 0, data=b'fixture-password\n', env=env)
    original = (d/'passwd').read_text()
    for bad_id in ['oops', '-1', '', '4294967296', '1junk']:
        (d/'passwd').write_text(original.replace(':12345:', ':'+bad_id+':', 1))
        run('login', 'lookup', 'fixture', env=env, rc=1)
    (d/'passwd').write_text(original)
    run('auth', 'policy-fnmatch', '/usr/bin/*', '/usr/bin/true')
    run('auth', 'policy-fnmatch', '/usr/bin/*', '/tmp/true', rc=1)
    policy = d/'policy'; policy.write_text('fixture ALL = (root) NOPASSWD: /usr/bin/true\n')
    assert b'digest_sha256=' in run('auth', 'policy-parse', policy)
    policy.write_text('invalid policy\n'); run('auth', 'policy-parse', policy, rc=1)
    run('eval', '''auth peruser reset fixture
auth peruser bump fixture
auth peruser check fixture
auth peruser bump fixture
if auth peruser check fixture; then exit 1; fi
auth peruser reset fixture
auth peruser check fixture
''', env={'BASHAUTH_PERUSER_MAX':'2'})
    # Parser rejection happens before any authentication or credential transition.
    for name in ['su','doas','sudo']: run(name, '--invalid-fixture-option', rc=2)

def network(d):
    assert run('ldap', 'encode-test', 'bind', '', '').strip() == b'300c020101600702010304008000'
    assert run('ldap', 'filter-test', '(uid=fixture)').strip() == b'a30e0403756964040766697874757265'
    run('ldap', 'filter-test', '(&(uid=fixture)(objectClass=*))')
    run('ldap', 'filter-test', '(uid=fixture', rc=1)
    run('ldap', 'decode-test', '300c02010161070a010004000400')
    run('ldap', 'decode-test', '3080', rc=1)
    body = b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"fixture\\ntext"}}\n\n'
    head = b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n'
    assert run('claude', 'parse-response', data=head+b'\r\n'+body) == b'fixture\ntext\n'
    chunked = b''.join(f'{len(part):x}\r\n'.encode()+part+b'\r\n' for part in [body[:17],body[17:]])+b'0\r\n\r\n'
    assert run('claude', 'parse-response', data=head+b'Transfer-Encoding: chunked\r\n\r\n'+chunked) == b'fixture\ntext\n'
    assert run('claude', 'parse-response', '--raw', data=head+b'\r\n') == b''
    run('claude', 'parse-response', data=b'HTTP/1.1 400 Bad Request\r\n\r\n{"error":{"message":"fixture"}}', rc=1)
    request = json.loads(run('claude', 'prompt', '--dump-request', 'quoted "text"\nnext'))
    assert request['messages'][0]['content'] == 'quoted "text"\nnext'
    run('claude', 'prompt', '--dump-request', data=b'\n', rc=2)
    zone = d/'zone'; zone.write_text('$ORIGIN example.invalid.\n$TTL 60\n@ IN SOA ns.example.invalid. hostmaster.example.invalid. 1 60 60 3600 60\n@ IN NS ns.example.invalid.\nns IN A 192.0.2.1\n')
    run('dns', 'checkzone', zone)
    with zone.open('a') as f: f.write('    IN A 192.0.2.2\n')
    run('dns', 'checkzone', zone)
    zone.write_text('bad IN A 999.0.0.1\n'); run('dns', 'checkzone', zone, rc=1)
    run('dns','update','--server','127.0.0.1','--zone','example.invalid',
        '--prereq','name-exists','example.invalid','--timeout',rc=2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, concurrent.futures.ThreadPoolExecutor() as pool:
        sock.bind(('127.0.0.1',0)); sock.settimeout(10)
        def dns_reply():
            query, peer = sock.recvfrom(65536)
            response = query[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+query[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+bytes([192,0,2,42])
            sock.sendto(response,peer)
        future = pool.submit(dns_reply)
        answer = run('dns', 'query', 'example.invalid', 'A', '-s', '127.0.0.1', '-t', 1000, env={'BASHDNS_SERVER_PORT':str(sock.getsockname()[1])})
        future.result(); assert b'192.0.2.42' in answer
    # Malformed query names must be rejected before any packet is sent.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1',0)); sock.setblocking(False)
        for name in ['x'*64+'.invalid', 'a..invalid']:
            run('dns','query',name,'A','-s','127.0.0.1','-t',10,
                env={'BASHDNS_SERVER_PORT':str(sock.getsockname()[1])},rc=1)
        assert not select.select([sock],[],[],0)[0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, concurrent.futures.ThreadPoolExecutor() as pool:
        sock.bind(('127.0.0.1',0)); sock.settimeout(10)
        def ntp_reply():
            query, peer = sock.recvfrom(2048)
            stamp = struct.pack('!II',int(time.time())+2208988800,0)
            response = bytes([0x24,2,6,0xec])+b'\0'*8+b'TEST'+stamp+query[40:48]+stamp+stamp
            sock.sendto(response,peer)
        future = pool.submit(ntp_reply)
        answer = run('ntp', 'query', '127.0.0.1', '-p', sock.getsockname()[1], '-t', 1000)
        future.result(); assert b'stratum=2' in answer
    aliases, database = d/'aliases', d/'aliases.db'
    aliases.write_text('team: fixturea, fixtureb\n')
    run('mail', 'newaliases', '--aliases', aliases, '--db', database)
    assert run('mail', 'expand', '--aliases-db', database, '--aliases', aliases, '--forward-root', d/'forward', 'team').splitlines() == [b'fixturea',b'fixtureb']
    aliases.write_text(''); run('mail', 'newaliases', '--aliases', aliases, '--db', database)
    aliases.write_text('invalid alias\n'); run('mail', 'newaliases', '--aliases', aliases, '--db', database, rc=78)
    env = {'BASHSSH_KNOWN_HOSTS':str(d/'known_hosts')}
    key = 'ssh-ed25519 '+base64.b64encode(b'public-key-fixture').decode()
    run('ssh', 'known-hosts', 'add', 'example.invalid', key, env=env)
    run('ssh', 'known-hosts', 'verify', 'example.invalid', key, env=env)
    run('ssh', 'known-hosts', 'verify', 'example.invalid', key+'x', env=env, rc=1)
    assert b'example.invalid' in run('ssh', 'known-hosts', 'list', env=env)
    run('ssh', 'known-hosts', 'remove', 'example.invalid', env=env)
    run('ssh', 'known-hosts', 'verify', 'example.invalid', key, env=env, rc=2)
    run('sshd', 'run', '-a', '127.0.0.1', '-p', 0, '-k', d/'missing-key', '--once', env={'BASHSSHD_RUN_DIR':str(d/'sshd')}, rc=1)

def tls(d):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
            .sign(key,hashes.SHA256()))
    certfile, keyfile = d/'cert.pem', d/'key.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(certfile,keyfile)
    for sni, expected in [('localhost',0), ('wrong.invalid',1)]:
        with socket.socket() as sock, concurrent.futures.ThreadPoolExecutor() as pool:
            sock.bind(('127.0.0.1',0)); sock.listen(); sock.settimeout(10)
            def reply():
                conn,_ = sock.accept(); conn.settimeout(10)
                try:
                    with context.wrap_socket(conn,server_side=True) as stream:
                        request = stream.recv(4096); assert b'GET /' in request
                        stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nfixture')
                except ssl.SSLError:
                    assert expected == 1
                finally: conn.close()
            future = pool.submit(reply)
            result = run('crypto','tls','connect',f'127.0.0.1:{sock.getsockname()[1]}','-c',certfile,'-s',sni,
                         '--connect-timeout',2000,'--read-timeout',2000,data=b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',rc=expected)
            future.result()
            if expected == 0: assert result.endswith(b'fixture')

def ssh_interop(d):
    global checks
    key, hostkey = d/'client', d/'host'
    for path in [key,hostkey]: host('ssh-keygen','-q','-t','ed25519','-N','','-f',path)
    user = pwd.getpwuid(os.getuid()).pw_name
    for client in ['openssh','builtin']:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1',0)); port = reserve.getsockname()[1]
        env = {**os.environ, 'BASHSSHD_RUN_DIR':str(d/('run-'+client)),
               'BASHSSHD_AUTHORIZED_KEYS':str(key)+'.pub', 'LC_ALL':'C'}
        if os.environ.get('FINAL_LOAD_ENV'):
            env.update(BASH_ENV=os.environ['FINAL_LOAD_ENV'], LD_PRELOAD=os.environ['FINAL_ASAN_LIB'],
                       ASAN_OPTIONS='detect_leaks=0:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        proc = subprocess.Popen([binary,'-c','sshd run --encrypted --once -a 127.0.0.1 -p "$1" -k "$2"',
                                 '_',str(port),str(hostkey)],env=env,stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        captured = bytearray()
        try:
            deadline = time.monotonic()+10
            while b'listening' not in captured:
                assert time.monotonic() < deadline and proc.poll() is None, captured
                if select.select([proc.stderr],[],[],0.1)[0]:
                    captured.extend(os.read(proc.stderr.fileno(),4096))
            known = d/('known-'+client)
            if client == 'openssh':
                result = host('ssh','-F','/dev/null','-p',port,'-i',key,'-o','IdentitiesOnly=yes',
                              '-o','BatchMode=yes','-o','ConnectTimeout=5','-o','LogLevel=ERROR',
                              '-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(known),
                              '-o','GlobalKnownHostsFile=/dev/null',user+'@127.0.0.1','printf fixture')
                assert result == b'fixture'; checks += 1
            else:
                result = run('eval', '''ssh connect 127.0.0.1 -p "$TEST_PORT" -l "$TEST_USER" -i "$TEST_KEY" --encrypted -h connection
ssh exec "$connection" 'printf fixture'
ssh close "$connection"
''',env={'TEST_PORT':str(port),'TEST_USER':user,'TEST_KEY':str(key),'BASHSSH_KNOWN_HOSTS':str(known)})
                assert result == b'fixture',result
            output, errors = proc.communicate(timeout=10); captured.extend(errors)
            assert proc.returncode == 0 and b'AddressSanitizer' not in captured and b'runtime error:' not in captured,(output,captured)
            checks += 1
        finally:
            if proc.poll() is None:
                # The private listener and its children share this new process group.
                os.killpg(proc.pid,15)
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired: os.killpg(proc.pid,9); proc.wait()
            _, remaining = proc.communicate(timeout=3); captured.extend(remaining)
            assert b'AddressSanitizer' not in captured and b'runtime error:' not in captured,captured

def graphics(d):
    pixels = bytes([255,0,0,0,255,0,0,0,255,255,255,255])
    def chunk(kind, body): return struct.pack('!I',len(body))+kind+body+struct.pack('!I',zlib.crc32(kind+body))
    png = (b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',2,2,8,2,0,0,0))+
           chunk(b'IDAT',zlib.compress(b'\0'+pixels[:6]+b'\0'+pixels[6:]))+chunk(b'IEND',b''))
    file = d/'image.png'; file.write_bytes(png)
    assert run('tiv','-m','ascii','-w',2,'-H',2,file).strip()
    apc = run('kitty','--raw-apc','--no-tmux',file)
    match = re.fullmatch(rb'\x1b_G([^;]+);([^\x1b]+)\x1b\\',apc)
    assert match and b's=2,v=2' in match[1] and base64.b64decode(match[2]) == pixels, apc
    sixel = run('sixel','-w',2,'-H',2,file)
    assert sixel.startswith(b'\x1bPq"1;1;2;2') and b'\x1b\\' in sixel
    for name in ['tiv','kitty','sixel']:
        run(name,'--base64',data=base64.b64encode(png))
        run(name,'-',data=b'invalid image',rc=1)

def parsing(d):
    languages = {'json':b'{"a":1}', 'toml':b'a=1\n', 'bash':b'printf hello\n',
                 'markdown':b'# Heading\n', 'markdown_inline':b'**bold**'}
    available = run('ts','language-list').decode()
    for language, source in languages.items():
        assert language in available
        parsed = run('ts','parse','-L',language,data=source)
        assert parsed.startswith(b'(') and b'ERROR' not in parsed, (language,parsed)
        rendered = run('hl','-L',language,data=source)
        assert re.sub(rb'\x1b\[[0-9;]*m',b'',rendered) == source
    assert b'number' in run('ts','query','-L','json','-q','(number) @number',data=b'[1,2]')
    run('ts','query','-L','json','-q','(',data=b'{}',rc=1)
    run('ts','parse','-L','missing',data=b'{}',rc=2)
    assert b'ERROR' in run('ts','parse','-L','json',data=b'{bad')

def terminal(d):
    for suffix in ['', '-piecetable', '-keybindings', '-saveprompt', '-replace', '-search',
                   '-resize', '-statusbar', '-yank-ring', '-atomic-save', '-undo-redo']:
        output = run('nano','selftest'+suffix)
        assert b'not ok ' not in output
    env = {'BASHSCREEN_STATE_DIR':str(d/'screen')}
    run('screen','run','-n','fixture','-d',env=env)
    assert b'fixture' in run('screen','list',env=env)
    run('screen','win-create','fixture','second',env=env)
    assert b'second' in run('screen','win-list','fixture',env=env)
    run('screen','pane-split','fixture','0','h',env=env)
    assert len(run('screen','pane-list','fixture','0',env=env).splitlines()) == 2
    run('screen','win-rename','fixture','1','renamed',env=env)
    assert b'renamed' in run('screen','win-list','fixture',env=env)
    run('screen','kill','fixture',env=env)

groups = [crypto, formats, accounts, network, tls, ssh_interop, graphics, parsing, terminal]
assert not selected-set(f.__name__ for f in groups), selected
with tempfile.TemporaryDirectory() as temporary:
    for group in groups:
        if selected and group.__name__ not in selected: continue
        d = Path(temporary)/group.__name__; d.mkdir()
        before = checks
        group(d)
        print(f'final-smoke/{group.__name__}: {checks-before} checks passed',flush=True)
print(f'final-smoke: {checks} checks passed')
