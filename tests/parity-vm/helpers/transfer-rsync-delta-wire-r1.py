#!/usr/bin/python3
"""VM-only stock-receiver observer and bounded rsync transport for delta evidence.

This source has not been run.  A failed observer is an evidence gap, not a
candidate diagnosis.  The companion suite and handoff describe qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import re
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
ADAPTER = CASE / 'rsync-delta-wire-adapter'
SOURCE_SHA = '6b85e0037d32124fd1dd033988d3d2b2c40d2dd4d8ecf581021d2485d9f3009f'
BASIS_SHA = 'ae29abfb7c12d1b01c39e8a7b97b88ca6c92af3f4877d1eb7be2a664965f0cad'
MAX_CAPTURE = 131072  # each wire direction, or the stock server's stderr
MAX_QUEUE = 65536
PROXY_TIMEOUT = 16
CLIENT_TIMEOUT = 21
PHASES = ('positive', 'literal', 'case')


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


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def phase_file():
    path = HOME / 'delta-phase.txt'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 2000 or info.st_size > 32:
        raise ValueError('invalid phase file')
    phase = path.read_text(encoding='ascii').strip()
    if phase not in PHASES:
        raise ValueError('invalid phase')
    return phase


def set_phase(phase):
    if phase not in PHASES:
        raise ValueError('invalid phase')
    (HOME / 'delta-phase.txt').write_text(phase + '\n', encoding='ascii')


class Interrupted(Exception):
    pass


def interrupted(signum, _frame):
    raise Interrupted('signal %s' % signum)


def proxy(args):
    """Proxy only the one-file stock receiver, preserving all bounded bytes."""
    phase = phase_file()
    report = {'phase': phase, 'argv': args, 'child_status': None,
              'client_read': 0, 'client_written': 0, 'server_read': 0,
              'server_written': 0, 'stderr_read': 0, 'error': None,
              'cleanup': [], 'complete': False}
    child = None
    capture = {}
    try:
        if len(args) < 2 or args[0] != 'fixture':
            raise ValueError('unexpected transport host')
        words = shlex.split(' '.join(args[1:]))
        dest = CASE / 'remote/dest' if phase == 'case' else HOME / ('delta-' + phase) / 'dest'
        if (len(words) < 4 or Path(words[0]).name != 'rsync' or words[1] != '--server'
                or words[-2] != '.' or Path(words[-1]).resolve() != dest.resolve()
                or not dest.is_dir() or dest.is_symlink()):
            raise ValueError('unexpected rsync receiver or destination')
        for option in words[2:-2]:
            if not re.fullmatch(r'-[logDtprWv]+', option):
                raise ValueError('unexpected or compressed server option')
        for label in ('c2s', 's2c', 'server'):
            capture[label] = (HOME / ('delta-' + phase + '-' + label + '.bin')).open('xb')
        report['command'] = ['/usr/bin/rsync', '--server', '--debug=DELTASUM3',
                             '--msgs2stderr', *words[2:]]
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, interrupted)
        child = subprocess.Popen(report['command'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True, cwd=CASE,
                                 env=dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C'))
        report['child_pid'] = child.pid
        cin, cout, cerr = child.stdin.fileno(), child.stdout.fileno(), child.stderr.fileno()
        for fd in (cin, cout, cerr):
            os.set_blocking(fd, False)
        cqueue, squeue = bytearray(), bytearray()
        client_open = child_in_open = child_out_open = child_err_open = True
        deadline = time.monotonic() + PROXY_TIMEOUT
        while True:
            if not child_out_open and not child_err_open and not squeue and child.poll() is not None:
                break
            if not client_open and not cqueue and child_in_open:
                child.stdin.close()
                child_in_open = False
            if time.monotonic() >= deadline:
                raise TimeoutError('stock proxy deadline')
            readers = []
            if client_open and child_in_open and len(cqueue) < MAX_QUEUE:
                readers.append(0)
            if child_out_open and len(squeue) < MAX_QUEUE:
                readers.append(cout)
            if child_err_open:
                readers.append(cerr)
            writers = ([cin] if child_in_open and cqueue else []) + ([1] if squeue else [])
            if not readers and not writers:
                raise ValueError('proxy stalled')
            ready_r, ready_w, _ = select.select(readers, writers, [], min(.2, deadline - time.monotonic()))
            for fd, label, counter in ((0, 'c2s', 'client_read'),
                                       (cout, 's2c', 'server_read'),
                                       (cerr, 'server', 'stderr_read')):
                if fd not in ready_r:
                    continue
                limit = MAX_QUEUE - len(cqueue) if fd == 0 else MAX_QUEUE - len(squeue) if fd == cout else 65536
                data = os.read(fd, min(65536, limit))
                if not data:
                    if fd == 0:
                        client_open = False
                    elif fd == cout:
                        child_out_open = False
                        child.stdout.close()
                    else:
                        child_err_open = False
                        child.stderr.close()
                    continue
                report[counter] += len(data)
                if report[counter] > MAX_CAPTURE:
                    raise ValueError(label + ' capture limit exceeded')
                capture[label].write(data)
                if fd == 0:
                    cqueue.extend(data)
                elif fd == cout:
                    squeue.extend(data)
            if cin in ready_w:
                n = os.write(cin, cqueue[:65536])
                del cqueue[:n]
                report['client_written'] += n
            if 1 in ready_w:
                n = os.write(1, squeue[:4096])
                del squeue[:n]
                report['server_written'] += n
        report['child_status'] = child.wait(timeout=max(.01, deadline - time.monotonic()))
        report['complete'] = (not cqueue and not squeue and not child_out_open and not child_err_open
                              and report['client_read'] == report['client_written']
                              and report['server_read'] == report['server_written'])
    except (OSError, ValueError, TimeoutError, Interrupted, subprocess.TimeoutExpired) as exc:
        report['error'] = repr(exc)
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        if child is not None:
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            if child.poll() is None:
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    report['cleanup'].append('terminate')
                    try:
                        child.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        report['cleanup'].append('kill')
                        try:
                            child.kill()
                        except ProcessLookupError:
                            pass
                        child.wait(timeout=2)
            report['child_status'] = child.wait()
        for f in capture.values():
            f.close()
        write_json(HOME / ('delta-' + phase + '-proxy.json'), report)
    return 90 if report['error'] or not report['complete'] else report['child_status']


def number(s):
    return int(s.replace(',', ''))


def decode_events(server_log, source, basis):
    """Decode stock receiver's own DELTASUM3 events, not sender diagnostics."""
    events, offset, sums, mapped = [], 0, 0, False
    chunk = re.compile(r'^chunk\[(\d+)\] of size (\d+) at ([\d,]+) offset=([\d,]+)(?: \(seek\))?$')
    literal = re.compile(r'^data recv (\d+) at ([\d,]+)$')
    for line in server_log.decode('utf-8', 'strict').splitlines():
        if line.startswith('recv mapped '):
            mapped = True
        if line == 'got file_sum':
            sums += 1
        m = literal.fullmatch(line)
        if m:
            size, pos = int(m[1]), number(m[2])
            if not size or pos != offset or pos + size > len(source):
                raise ValueError('invalid stock literal event')
            if events and events[-1]['kind'] == 'literal':
                events[-1]['length'] += size
            else:
                events.append({'kind': 'literal', 'offset': pos, 'length': size})
            offset += size
            continue
        m = chunk.fullmatch(line)
        if m:
            index, size, basis_offset, pos = int(m[1]), int(m[2]), number(m[3]), number(m[4])
            if (not size or pos != offset or pos + size > len(source)
                    or basis_offset + size > len(basis)
                    or basis[basis_offset:basis_offset + size] != source[pos:pos + size]):
                raise ValueError('invalid stock basis-reference event')
            events.append({'kind': 'block', 'index': index, 'basis_offset': basis_offset,
                           'offset': pos, 'length': size})
            offset += size
    if sums != 1 or offset != len(source) or not events:
        raise ValueError('incomplete or ambiguous stock receiver trace')
    if any(e['kind'] == 'block' for e in events) and not mapped:
        raise ValueError('block references without a mapped basis')
    return events


def locate_tokens(wire, events, source):
    """Find a unique uncompressed token sequence agreeing with every stock event.

    This is constrained matching, not a complete rsync frame parser.  A unique
    match plus the stock receiver trace is required; ambiguity is a hold.
    """
    matches = []
    for start in range(4, max(4, len(wire) - 19)):
        p = start
        refs = []
        good = True
        for event in events:
            if event['kind'] == 'block':
                if p + 4 > len(wire) or struct.unpack_from('<i', wire, p)[0] != -1 - event['index']:
                    good = False
                    break
                refs.append({'wire_offset': p, **event})
                p += 4
                continue
            consumed = 0
            while consumed < event['length']:
                if p + 4 > len(wire):
                    good = False
                    break
                count = struct.unpack_from('<i', wire, p)[0]
                p += 4
                start_source = event['offset'] + consumed
                if (count <= 0 or count > event['length'] - consumed or p + count > len(wire)
                        or wire[p:p + count] != source[start_source:start_source + count]):
                    good = False
                    break
                p += count
                consumed += count
            if not good:
                break
        # Token terminator and the protocol-27 16-byte transfer checksum must exist.
        if good and p + 20 <= len(wire) and wire[p:p + 4] == b'\0\0\0\0':
            matches.append({'start': start, 'end': p + 4, 'references': refs})
            if len(matches) > 1:
                break
    if len(matches) != 1:
        raise ValueError('token stream missing or non-unique in complete wire capture')
    return matches[0]


def observe(phase, source, basis):
    report = json.loads((HOME / ('delta-' + phase + '-proxy.json')).read_text())
    c2s = (HOME / ('delta-' + phase + '-c2s.bin')).read_bytes()
    s2c = (HOME / ('delta-' + phase + '-s2c.bin')).read_bytes()
    log = (HOME / ('delta-' + phase + '-server.bin')).read_bytes()
    if (report['error'] is not None or report['child_status'] != 0 or report['cleanup']
            or not report['complete'] or report['client_read'] != len(c2s)
            or report['server_read'] != len(s2c) or report['stderr_read'] != len(log)
            or any(len(x) > MAX_CAPTURE for x in (c2s, s2c, log))
            or len(c2s) < 4 or c2s[:4] != b'\x1b\0\0\0'
            or len(s2c) < 4 or int.from_bytes(s2c[:4], 'little') < 27):
        raise ValueError('incomplete proxy, child failure, capture, or protocol greeting')
    events = decode_events(log, source, basis)
    located = locate_tokens(c2s, events, source)
    return {'phase': phase, 'protocol': 27, 'source_sha256': hashlib.sha256(source).hexdigest(),
            'basis_sha256': hashlib.sha256(basis).hexdigest(), 'events': events,
            'token_stream': located, 'references': len(located['references'])}


def setup():
    source, basis = CASE / 'source/delta.bin', CASE / 'remote/dest/delta.bin'
    if sha(source) != SOURCE_SHA or sha(basis) != BASIS_SHA or source.read_bytes() == basis.read_bytes():
        raise ValueError('original source or existing basis does not match the pinned fixture')
    adapter_source = Path(__file__).resolve()
    if adapter_source == ADAPTER or ADAPTER.exists():
        raise ValueError('unexpected adapter source or existing target')
    ADAPTER.write_bytes(adapter_source.read_bytes())
    ADAPTER.chmod(0o755)
    if sha(ADAPTER) != sha(adapter_source) or not os.access(ADAPTER, os.X_OK):
        raise ValueError('adapter copy differs')
    (HOME / 'delta-original-basis.bin').write_bytes(basis.read_bytes())
    os.utime(source, (1609459200, 1609459200))
    os.utime(basis, (1577836800, 1577836800))
    version = subprocess.run(['/usr/bin/rsync', '--version'], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3,
                             env=dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C'), check=True)
    if len(version.stdout) > 16384 or len(version.stderr) > 16384:
        raise ValueError('unexpected stock version output size')
    controls = {'stock_rsync_sha256': sha(Path('/usr/bin/rsync')),
                'stock_rsync_version': version.stdout.decode('utf-8', 'strict').splitlines()[0],
                'adapter_sha256': sha(ADAPTER), 'original_source_sha256': sha(source),
                'original_basis_sha256': sha(basis), 'controls': {}}
    for phase in ('positive', 'literal'):
        root = HOME / ('delta-' + phase)
        (root / 'source').mkdir(parents=True)
        (root / 'dest').mkdir()
        control_source, control_dest = root / 'source/delta.bin', root / 'dest/delta.bin'
        control_source.write_bytes(source.read_bytes())
        control_dest.write_bytes(basis.read_bytes())
        os.utime(control_source, (1609459200, 1609459200))
        os.utime(control_dest, (1577836800, 1577836800))
        set_phase(phase)
        args = ['/usr/bin/rsync', '--protocol=27', '-a']
        if phase == 'literal':
            args.append('--whole-file')
        args += ['-e', str(ADAPTER), str(root / 'source') + '/', 'fixture:' + str(root / 'dest') + '/']
        run = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=CLIENT_TIMEOUT,
                             env=dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C'))
        if run.returncode != 0 or control_dest.read_bytes() != source.read_bytes():
            raise ValueError('stock ' + phase + ' transfer failed')
        obs = observe(phase, source.read_bytes(), basis.read_bytes())
        if (phase == 'positive' and obs['references'] < 1) or (phase == 'literal' and obs['references'] != 0):
            raise ValueError('stock ' + phase + ' token control failed')
        if phase == 'positive':
            wire = (HOME / 'delta-positive-c2s.bin').read_bytes()
            token = obs['token_stream']
            # VM-only negative checks built from the actually captured stock stream.
            altered = {'truncated': wire[:token['end']],
                       'ambiguous': wire + wire[token['start']:token['end']] + bytes(16)}
            controls['token_negative_controls'] = {}
            for name, altered_wire in altered.items():
                try:
                    locate_tokens(altered_wire, obs['events'], source.read_bytes())
                except ValueError:
                    controls['token_negative_controls'][name] = 'rejected'
                else:
                    raise ValueError('token ' + name + ' control accepted')
        obs.update(client_status=run.returncode, result_identical=True)
        controls['controls'][phase] = obs
    if sha(source) != SOURCE_SHA or sha(basis) != BASIS_SHA:
        raise ValueError('controls modified the original case inputs')
    set_phase('case')
    refusal = subprocess.run([str(ADAPTER), 'not-fixture', 'true'], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             timeout=3, env=dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C'))
    refusal_report = json.loads((HOME / 'delta-case-proxy.json').read_text())
    if refusal.returncode != 90 or refusal_report['error'] is None or 'child_pid' in refusal_report:
        raise ValueError('invalid-host transport refusal control failed')
    controls['invalid_host_refusal'] = {'client_status': refusal.returncode, 'proxy': refusal_report}
    write_json(HOME / 'delta-controls.json', controls)


def case_result(client_status):
    result_path = HOME / 'delta-observation.json'
    try:
        if phase_file() != 'case' or not (HOME / 'delta-controls.json').is_file():
            raise ValueError('control or phase missing')
        source = (CASE / 'source/delta.bin').read_bytes()
        basis = (HOME / 'delta-original-basis.bin').read_bytes()
        if hashlib.sha256(source).hexdigest() != SOURCE_SHA or hashlib.sha256(basis).hexdigest() != BASIS_SHA:
            raise ValueError('pinned source or saved basis changed')
        obs = observe('case', source, basis)
        identical = (CASE / 'remote/dest/delta.bin').read_bytes() == source
        obs.update(client_status=client_status, result_identical=identical, observer='complete')
        write_json(result_path, obs)
        print('status=%d\nprotocol-27=1\nbasis=1\ndelta-copy=%d\nbytes-identical=%d\npeer-stage=observed'
              % (client_status, bool(obs['references']), identical))
        return 0
    except (OSError, KeyError, ValueError, UnicodeError, struct.error) as exc:
        write_json(result_path, {'observer': 'incomplete', 'client_status': client_status, 'error': repr(exc)})
        print('observer-incomplete')
        return 88


def main():
    require_guest()
    if sys.argv[1:] == ['setup']:
        setup()
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'observe':
        return case_result(int(sys.argv[2]))
    return proxy(sys.argv[1:])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, KeyError, ValueError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        print('delta fixture: ' + repr(exc), file=sys.stderr)
        sys.exit(98)
