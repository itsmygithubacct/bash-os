#!/usr/bin/python3
"""VM-only SCP/rsync adapter, with a bounded full-duplex stock-rsync proxy."""
import json
import os
from pathlib import Path
import select
import shlex
import signal
import stat
import struct
import subprocess
import sys
import time
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        cwd = Path.cwd().resolve()
        if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.geteuid() != 2000 or os.environ.get('HOME') != str(HOME)
                or not (cwd == CASE or CASE in cwd.parents)
                or CASE.stat().st_uid != 2000 or HOME.stat().st_uid != 2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def record(event, **details):
    with (HOME / 'copy-invocations.jsonl').open('a', encoding='utf-8') as out:
        out.write(json.dumps({'event': event, **details}, sort_keys=True) + '\n')


def config():
    path = HOME / 'copy-config.json'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 2000 or info.st_size > 1024:
        raise ValueError('invalid configuration file')
    result = json.loads(path.read_text(encoding='utf-8'))
    if (set(result) != {'phase', 'mode', 'fail'}
            or result['phase'] not in ('control', 'case')
            or result['mode'] not in ('scp', 'rsync')
            or type(result['fail']) is not bool):
        raise ValueError('invalid configuration fields')
    return result


def tree_stream(path):
    path = Path(path).resolve()
    allowed = ((CASE / 'remote/source').resolve(), (HOME / 'control-source').resolve())
    if path not in allowed or not path.is_dir():
        raise ValueError('unexpected tree-stream source')
    data = bytearray(b'bRT1')
    for item in sorted(path.rglob('*')):
        info = item.lstat()
        name = item.relative_to(path).as_posix().encode()
        if stat.S_ISDIR(info.st_mode):
            tag, contents = b'D', None
        elif stat.S_ISREG(info.st_mode):
            tag, contents = b'F', item.read_bytes()
        else:
            raise ValueError('fixture permits only files and directories')
        data += tag + struct.pack('<H', len(name)) + name
        data += struct.pack('<IQII', stat.S_IMODE(info.st_mode), int(info.st_mtime), info.st_uid, info.st_gid)
        if contents is not None:
            data += struct.pack('<Q', len(contents)) + contents
    data += b'E'
    sys.stdout.buffer.write(data)


class Interrupted(Exception):
    pass


def interrupted(signum, _frame):
    raise Interrupted('signal %s' % signum)


def stock_proxy(words, conf):
    """Concurrently forward both directions; the stock server owns its handshake."""
    phase = conf['phase']
    report = {'command': words, 'client_bytes': 0, 'server_bytes': 0,
              'child_status': None, 'error': None, 'cleanup': []}
    result_path = HOME / ('control-proxy.json' if phase == 'control' else 'proxy.json')
    protocol_path = HOME / ('control-protocol.bin' if phase == 'control' else 'protocol.bin')
    proc = None
    captured = bytearray()
    client_to_server = bytearray()
    server_to_client = bytearray()
    max_buffer = 262144
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        proc = subprocess.Popen(['/usr/bin/rsync', *words[1:]], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=None, close_fds=True,
                                env=dict(os.environ, PATH='/usr/bin:/bin'))
        report['child_pid'] = proc.pid
        child_in, child_out = proc.stdin.fileno(), proc.stdout.fileno()
        os.set_blocking(child_in, False)
        os.set_blocking(child_out, False)
        client_open = child_in_open = child_out_open = True
        deadline = time.monotonic() + 16
        while True:
            if not child_out_open and not server_to_client and proc.poll() is not None:
                break
            if not client_open and not client_to_server and child_in_open:
                proc.stdin.close()
                child_in_open = False
            if time.monotonic() >= deadline:
                raise TimeoutError('stock rsync proxy deadline')
            readers = []
            if client_open and child_in_open and len(client_to_server) < max_buffer:
                readers.append(0)
            if child_out_open and len(server_to_client) < max_buffer:
                readers.append(child_out)
            writers = []
            if child_in_open and client_to_server:
                writers.append(child_in)
            if server_to_client:
                writers.append(1)
            if not readers and not writers:
                proc.wait(timeout=max(0.01, deadline-time.monotonic()))
                break
            ready_r, ready_w, _ = select.select(readers, writers, [], min(.2, deadline-time.monotonic()))
            if 0 in ready_r:
                data = os.read(0, min(65536, max_buffer-len(client_to_server)))
                if not data:
                    client_open = False
                else:
                    client_to_server.extend(data)
                    report['client_bytes'] += len(data)
                    if len(captured) < 4:
                        captured.extend(data[:4-len(captured)])
                        protocol_path.write_bytes(captured)
            if child_out in ready_r:
                data = os.read(child_out, min(65536, max_buffer-len(server_to_client)))
                if not data:
                    child_out_open = False
                    proc.stdout.close()
                else:
                    server_to_client.extend(data)
                    report['server_bytes'] += len(data)
            if child_in in ready_w:
                try:
                    n = os.write(child_in, client_to_server[:65536])
                    del client_to_server[:n]
                except BrokenPipeError:
                    proc.stdin.close()
                    child_in_open = client_open = False
                    client_to_server.clear()
            if 1 in ready_w:
                n = os.write(1, server_to_client[:4096])
                del server_to_client[:n]
        report['child_status'] = proc.wait(timeout=max(0.01, deadline-time.monotonic()))
    except (OSError, ValueError, TimeoutError, Interrupted, subprocess.TimeoutExpired) as exc:
        report['error'] = repr(exc)
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        # Only the Popen handle created above is signalled; no process search.
        if proc is not None:
            for stream in (proc.stdin, proc.stdout):
                if stream is not None and not stream.closed:
                    stream.close()
            if proc.poll() is None:
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    report['cleanup'].append('terminate')
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        report['cleanup'].append('kill')
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                        proc.wait(timeout=2)
            report['child_status'] = proc.wait()
        result_path.write_text(json.dumps(report, sort_keys=True) + '\n')
        record('proxy-finished', phase=phase, status=report['child_status'], error=report['error'])
    return 90 if report['error'] or report['child_status'] is None else report['child_status']


def main():
    args = sys.argv[1:]
    record('invoked', argv=args)
    conf = config()
    record('configured', **conf)
    with (HOME / ('control-peer.jsonl' if conf['phase']=='control' else 'peer.jsonl')).open('a', encoding='utf-8') as out:
        out.write(json.dumps(args, ensure_ascii=True) + '\n')
    if conf['fail']:
        record('refused', argv=args)
        print('fixture transport refused', file=sys.stderr)
        return 86
    env = dict(os.environ, PATH='/usr/bin:/bin')
    if conf['mode'] == 'scp':
        root = HOME / 'control-remote' if conf['phase']=='control' else CASE / 'remote'
        if not root.is_dir() or root.is_symlink():
            raise ValueError('unexpected scp root')
        os.chdir(root)
        if len(args) >= 2 and args[-1] == 'sftp' and '-s' in args:
            if args[-2] != 'fixture':
                raise ValueError('unexpected sftp target')
            record('sftp-server', argv=args)
            os.execve('/usr/lib/openssh/sftp-server', ['sftp-server', '-d', str(root)], env)
        if len(args) < 2 or args[-2] not in ('fixture', 'alice@fixture'):
            raise ValueError('unexpected scp target')
        record('command', argv=args)
        os.execve('/bin/sh', ['sh', '-c', args[-1]], env)
    if len(args) < 2 or args[0] != 'fixture':
        raise ValueError('unexpected rsync target')
    os.chdir(CASE)
    command = ' '.join(args[1:])
    words = shlex.split(command)
    if len(words) == 4 and words[:2] == ['rsync', '--server-send'] and words[3] == 'contents':
        record('tree-stream', argv=args)
        tree_stream(words[2])
        return 0
    if len(words) >= 2 and Path(words[0]).name == 'rsync' and words[1] == '--server':
        record('stock-proxy', argv=args)
        return stock_proxy(words, conf)
    record('command', argv=args)
    os.execve('/bin/sh', ['sh', '-c', command], env)


if __name__ == '__main__':
    require_guest()
    try:
        sys.exit(main())
    except (KeyError, TypeError, OSError, ValueError) as exc:
        try:
            record('error', error=repr(exc))
        except OSError:
            pass
        print('fixture transport: ' + str(exc), file=sys.stderr)
        sys.exit(90)
