#!/usr/bin/python3
"""Protected controller identity and per-side namespace proof for clamp r2."""
import json
import os
from pathlib import Path
import stat
import uuid

PROOF = Path('/run/bashos-clamp-side-r2.json')


def protected(path, limit=32768):
    path = Path(path)
    for parent in [path.parent, *path.parent.parents]:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise RuntimeError('unprotected guard directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1 or info.st_size > limit):
            raise RuntimeError('unprotected guard record')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise RuntimeError('oversized guard record')
        return data
    finally:
        os.close(fd)


def identities():
    marker = protected('/etc/bashos-parity-vm').decode().strip()
    if str(uuid.UUID(marker)) != marker or protected('/run/bashos-parity-vm-identity').decode().strip() != marker:
        raise RuntimeError('protected identity mismatch')
    return marker


def namespaces():
    return {name: os.readlink('/proc/self/ns/' + name) for name in ('pid', 'net', 'mnt')}


def verify():
    token = identities()
    parent = json.loads(protected('/run/bashos-syslog-namespace-208.json'))
    proof = json.loads(protected(PROOF))
    if (parent.get('schema') != 'bashos-syslog-namespace-attestation-v1'
            or parent.get('token') != token or proof.get('schema') != 'clamp-side-r2'
            or proof.get('token') != token or proof.get('namespaces') != namespaces()
            or proof.get('evaluator_namespaces') != parent.get('namespaces')):
        raise RuntimeError('namespace proof mismatch')
    inner, outer = parent['namespaces'], parent.get('outer_namespaces', {})
    if set(inner) != {'pid', 'net', 'mnt'} or set(outer) != set(inner) or any(inner[k] == outer[k] for k in inner):
        raise RuntimeError('evaluator namespace not isolated')
    if namespaces()['pid'] != inner['pid']:
        raise RuntimeError('fixture left evaluator PID namespace')
    # Root sides have their own mount/net boundary, explicitly attested by root.
    if proof.get('root_side') is True:
        if any(namespaces()[k] == inner[k] for k in ('mnt', 'net')):
            raise RuntimeError('root side namespace not isolated')
    elif namespaces() != inner:
        raise RuntimeError('unexpected fixture namespace')
    return proof


def attest_side(root_side=False):
    if os.geteuid() != 0:
        raise RuntimeError('side attestation requires root controller')
    token = identities()
    parent = json.loads(protected('/run/bashos-syslog-namespace-208.json'))
    if parent.get('token') != token or namespaces()['pid'] != parent['namespaces']['pid']:
        raise RuntimeError('controller identity/namespace mismatch')
    data = {'schema': 'clamp-side-r2', 'token': token, 'namespaces': namespaces(),
            'evaluator_namespaces': parent['namespaces'], 'root_side': root_side}
    temporary = PROOF.with_name(PROOF.name + '.tmp-' + str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(data, out, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fchmod(out.fileno(), 0o444)
            os.fsync(out.fileno())
        os.replace(temporary, PROOF)
    finally:
        if temporary.exists():
            temporary.unlink()
    return verify()
