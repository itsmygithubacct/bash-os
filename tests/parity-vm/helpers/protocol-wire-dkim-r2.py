#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only DKIM fixture with RFC 8463 Appendix A vectors and OpenSSL oracle."""
import base64
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
import uuid

DIAG = Path(os.environ.get('HOME', '.')) / 'dkim-trace.json'
LIMIT = 32768
ED_PUBLIC = '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='
RSA_PUBLIC = ('MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR'
              'iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC'
              'DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3'
              'Ip3G+2kryOTIKT+l/K4w3QIDAQAB')
ED_SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
ED_SIGNATURE = (b'DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n'
                b' d=football.example.com; i=@football.example.com;\r\n'
                b' q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n'
                b' subject : date : message-id : from : subject : date;\r\n'
                b' bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n'
                b' b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r\n'
                b' Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r\n')
RSA_SIGNATURE = (b'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n'
                 b' d=football.example.com; i=@football.example.com;\r\n'
                 b' q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r\n'
                 b' date : message-id : from : subject : date;\r\n'
                 b' bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n'
                 b' b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r\n'
                 b' DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r\n'
                 b' dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=\r\n')
RFC_MESSAGE = (b'From: Joe SixPack <joe@football.example.com>\r\n'
               b'To: Suzie Q <suzie@shopping.example.net>\r\n'
               b'Subject: Is dinner ready?\r\n'
               b'Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n'
               b'Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n'
               b'\r\nHi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n\r\n')


def check(ok, why):
    if not ok: raise AssertionError(why)


def relaxed_body(body):
    lines = body.split(b'\r\n')
    lines = [re.sub(rb'[ \t]+', b' ', line).rstrip(b' ') for line in lines]
    while lines and not lines[-1]: lines.pop()
    return b'\r\n'.join(lines) + b'\r\n'


def relaxed_header(header):
    name, value = header.split(b':', 1)
    value = re.sub(rb'\r\n[ \t]+', b' ', value)
    value = re.sub(rb'[ \t]+', b' ', value).strip(b' ')
    return name.strip().lower() + b':' + value


def verify(message, key_type, trace):
    head, body = message.split(b'\r\n\r\n', 1)
    headers = re.split(rb'\r\n(?=[^ \t])', head)
    sigs = [h for h in headers if h.split(b':', 1)[0].lower() == b'dkim-signature']
    check(len(sigs) == 1, 'expected one DKIM-Signature')
    sig_header = sigs[0]; val = relaxed_header(sig_header).split(b':', 1)[1]
    tags = {}
    for part in val.split(b';'):
        if b'=' in part:
            key, value = part.split(b'=', 1); tags[key.strip().lower()] = value.strip()
    check(tags.get(b'c') == b'relaxed/relaxed' and tags.get(b'a') == (b'ed25519-sha256' if key_type == 'ed25519' else b'rsa-sha256'), 'DKIM algorithm/canonicalization mismatch')
    bh = base64.b64encode(hashlib.sha256(relaxed_body(body)).digest())
    if bh != tags.get(b'bh'):
        trace['verification'] = 'body hash mismatch'; return False
    signed = bytearray(); used = set()
    for field in tags[b'h'].split(b':'):
        name = field.strip().lower()
        for index in range(len(headers)-1, -1, -1):
            if index not in used and headers[index].split(b':', 1)[0].strip().lower() == name:
                used.add(index); signed += relaxed_header(headers[index]) + b'\r\n'; break
    # The b= tag value, including any continuation whitespace, is empty during hashing.
    unsigned = re.sub(rb'(?i)(\bb[ \t]*=)[^;]*', rb'\1', sig_header, count=1)
    signed += relaxed_header(unsigned)
    signature = base64.b64decode(re.sub(rb'\s+', b'', tags[b'b']), validate=True)
    if key_type == 'ed25519':
        key_der = bytes.fromhex('302a300506032b6570032100') + base64.b64decode(ED_PUBLIC)
    else: key_der = base64.b64decode(RSA_PUBLIC)
    pem = b'-----BEGIN PUBLIC KEY-----\n' + base64.encodebytes(key_der) + b'-----END PUBLIC KEY-----\n'
    with tempfile.TemporaryDirectory(prefix='dkim-oracle-', dir=os.environ['HOME']) as tmp:
        root=Path(tmp); (root/'key.pem').write_bytes(pem); (root/'sig').write_bytes(signature); (root/'signed').write_bytes(signed)
        if key_type == 'ed25519':
            (root/'digest').write_bytes(hashlib.sha256(signed).digest())
            cmd=['/usr/bin/openssl','pkeyutl','-verify','-pubin','-inkey',str(root/'key.pem'),'-rawin','-in',str(root/'digest'),'-sigfile',str(root/'sig')]
        else:
            cmd=['/usr/bin/openssl','dgst','-sha256','-verify',str(root/'key.pem'),'-signature',str(root/'sig'),str(root/'signed')]
        result=subprocess.run(cmd, capture_output=True, timeout=4)
        trace['verification'] = {'status':result.returncode, 'stdout':result.stdout[:2048].decode('utf8','replace'), 'stderr':result.stderr[:2048].decode('utf8','replace'), 'signed_hex':bytes(signed).hex()[:LIMIT], 'body_hash':bh.decode()}
        return result.returncode == 0


def candidate(shell, message, option):
    command='mail dkim-verify ' + option
    result=subprocess.run([shell,'--noprofile','--norc','-c',command],input=message,capture_output=True,timeout=5)
    return {'status':result.returncode,'stdout_hex':result.stdout[:LIMIT].hex(),'stderr':result.stderr[:LIMIT].decode('utf8','replace')}


def published_controls(trace):
    checks=[]; trace['controls']=checks
    for alg, sig in (('ed25519',ED_SIGNATURE),('rsa',RSA_SIGNATURE)):
        t={}; message=sig+RFC_MESSAGE
        checks.append({'algorithm':alg,'positive':t})
        check(verify(message,alg,t),'independent '+alg+' RFC vector verification failed: '+repr(t))
        bad={}; check(not verify(message.replace(b'We lost the game.',b'We won the game.'),alg,bad),'body tamper negative control passed'); checks[-1]['tampered']=bad
    trace['controls']=checks


def signing(shell, trace):
    queue=Path('queue/active/ABCDEF123456789'); queue.mkdir(parents=True)
    (queue/'headers').write_bytes(b'From: Alice <alice@example.test>\nTo: bob@example.test\nSubject: fixture\n')
    (queue/'body').write_bytes(b'.hello  \nline\t \n\n'); (queue/'meta').write_text('separator=1\n')
    Path('seed.hex').write_text(ED_SEED_HEX+'\n')
    client, peer=socket.socketpair(); peer.settimeout(4); observed={}
    def smtp():
        try:
            with peer:
                f=peer.makefile('rb'); peer.sendall(b'220 fixture\r\n')
                for expected,reply in ((b'EHLO dkim.fixture\r\n',b'250 fixture\r\n'),(b'MAIL FROM:<alice@example.test>\r\n',b'250 ok\r\n'),(b'RCPT TO:<bob@example.test>\r\n',b'250 ok\r\n'),(b'DATA\r\n',b'354 go\r\n')):
                    got=f.readline(4096); check(got==expected,'SMTP command mismatch '+repr(got)); peer.sendall(reply)
                data=bytearray()
                while True:
                    line=f.readline(4096); check(line and line.endswith(b'\r\n'),'bad SMTP DATA framing')
                    if line==b'.\r\n': break
                    if line.startswith(b'.'): check(line.startswith(b'..'),'unstuffed leading dot'); line=line[1:]
                    data += line; check(len(data)<LIMIT,'signed message too large')
                observed['message_hex']=bytes(data).hex(); peer.sendall(b'250 accepted\r\n')
                check(f.readline(4096)==b'QUIT\r\n','missing QUIT'); peer.sendall(b'221 bye\r\n'); f.close()
        except Exception as exc: observed['error']=type(exc).__name__+': '+str(exc)
    thread=threading.Thread(target=smtp,daemon=True); thread.start(); proc=None
    cmd=('mail deliver-fd --queue queue --qid ABCDEF123456789 --fd %d --from alice@example.test '
         '--ehlo dkim.fixture --tls off --timeout 1000 --dkim-key seed.hex --dkim-selector s1 '
         '--dkim-domain example.test --dkim-alg ed25519 --dkim-ts 1528637909 -- bob@example.test') % client.fileno()
    try:
        proc=subprocess.Popen([shell,'--noprofile','--norc','-c',cmd],pass_fds=(client.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        client.close(); out,err=proc.communicate(timeout=5)
    finally:
        if proc is not None and proc.poll() is None: proc.kill(); proc.communicate(timeout=2)
        client.close(); thread.join(5); trace['peer']=observed
    trace['candidate']={'status':proc.returncode,'stdout_hex':out[:LIMIT].hex(),'stderr':err[:LIMIT].decode('utf8','replace')}
    check(not thread.is_alive() and 'error' not in observed,'SMTP signing peer failed')
    check(proc.returncode==0 and out==b'delivered bob@example.test\n','signed delivery failed')
    message=bytes.fromhex(observed['message_hex']); verification={}
    trace['signed_verification']=verification
    check(verify(message,'ed25519',verification),'independent verifier rejected generated signature')
    check(b'c=relaxed/relaxed;' in message and b'd=example.test;' in message and b's=s1;' in message,'signed selector/domain or canonicalization missing')
    bad={}; check(not verify(message.replace(b'.hello',b'.changed'),'ed25519',bad),'tampered signed output accepted'); trace['tampered_verification']=bad
    return message


def main(shell, scenario):
    trace={'scenario':scenario}
    try:
        published_controls(trace)
        if scenario=='control': pass
        elif scenario=='sign': signing(shell,trace)
        elif scenario in ('sign-tamper-body', 'sign-tamper-header'):
            message = signing(shell, trace)
            option = '--pubkey-b64 ' + ED_PUBLIC + ' --alg ed25519'
            original = candidate(shell, message, option); trace['candidate_generated_original'] = original
            changed = (message.replace(b'.hello', b'.changed') if scenario == 'sign-tamper-body'
                       else message.replace(b'Subject: fixture', b'Subject: changed'))
            check(changed != message, 'tamper did not alter the signed input')
            altered_verification = {}; trace['generated_altered_verification'] = altered_verification
            check(not verify(changed, 'ed25519', altered_verification), 'independent verifier accepted generated-message tamper')
            altered = candidate(shell, changed, option); trace['candidate_generated_altered'] = altered
            check(original['status'] == 0, 'candidate rejected independently verified generated message')
            check(altered['status'] == 1, 'candidate accepted tampered generated message')
        elif scenario=='usage':
            runs=[candidate(shell,b'', ''),candidate(shell,b'', '--unknown')]; trace['candidate']=runs
            check(all(r['status']==2 and r['stderr'] for r in runs),'missing key or unknown option did not return usage')
        else:
            rsa=scenario=='rsa-valid'; msg=(RSA_SIGNATURE if rsa else ED_SIGNATURE)+RFC_MESSAGE
            opt='--pubkey-b64 '+(RSA_PUBLIC if rsa else ED_PUBLIC)+' --alg '+('rsa' if rsa else 'ed25519')
            original=candidate(shell,msg,opt); trace['candidate_original']=original
            if scenario=='tamper-body': msg=msg.replace(b'We lost the game.',b'We won the game.')
            elif scenario=='tamper-header': msg=msg.replace(b'Subject: Is dinner ready?',b'Subject: Is breakfast ready?')
            elif scenario not in ('ed-valid','rsa-valid'): raise ValueError('unknown scenario')
            if scenario.startswith('tamper-'):
                altered_verification = {}; trace['independent_altered'] = altered_verification
                check(not verify(msg,'ed25519',altered_verification),'independent verifier accepted tamper')
                altered=candidate(shell,msg,opt); trace['candidate_altered']=altered
                check(altered['status']==1,'tampered DKIM message was not rejected')
            check(original['status']==0,'published valid DKIM vector rejected')
        print('dkim-'+scenario+'=ok')
    except Exception as exc:
        trace['error']=type(exc).__name__+': '+str(exc)
        print('dkim fixture failed: '+trace['error'],file=sys.stderr)
        raise SystemExit(1)
    finally: DIAG.write_text(json.dumps(trace,indent=2)+'\n')


def require_guest():
    """Fail closed before helper behavior; the guest evaluator checks UUID equality."""
    try:
        marker = Path('/etc/bashos-parity-vm').read_text().strip()
        parsed = uuid.UUID(marker)
        if str(parsed) != marker.lower():
            raise ValueError('non-canonical VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
            raise ValueError('not a QEMU guest')
        if os.getuid() != 2000 or os.geteuid() != 2000:
            raise ValueError('unexpected guest uid')
        if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home':
            raise ValueError('unexpected guest scratch directory')
    except (OSError, ValueError) as exc:
        raise SystemExit('disposable-VM guard refused helper: ' + str(exc))


if __name__=='__main__':
    require_guest()
    if len(sys.argv)==3: main(sys.argv[1],sys.argv[2])
    else: raise SystemExit('usage: helper SHELL SCENARIO')
