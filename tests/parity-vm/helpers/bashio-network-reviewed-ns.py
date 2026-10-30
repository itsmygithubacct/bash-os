#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only isolated ioctl controls, candidate capture, and assertions."""
import base64
import copy
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

HOME = Path('/tmp/parity-home')
HELPERS = Path('/opt/bashos-parity/harness/helpers')
HERE = str(HELPERS / 'bashio-network-reviewed-ns.py')
CANDIDATE = '/opt/bashos-parity/candidate'
IP = '/usr/sbin/ip'
TRACER = str(HOME / 'network-tracer')
NATIVE = str(HOME / 'network-native')
ADDR, MASK, GETFLAGS, SETFLAGS, ROUTE = 0x8916, 0x891c, 0x8913, 0x8914, 0x890b
MAX_OUTPUT = 65536
CASES = {
    'addr-success': ('set-addr bn0 192.0.2.20 255.255.255.0', 0, '', 'addr'),
    'addr-missing': ('set-addr', 2, 'set-addr needs IFACE IP MASK', 'none'),
    'addr-missing-ip': ('set-addr bn0', 2, 'set-addr needs IFACE IP MASK', 'none'),
    'addr-missing-mask': ('set-addr bn0 192.0.2.20', 2, 'set-addr needs IFACE IP MASK', 'none'),
    'addr-bad-ip': ('set-addr bn0 invalid 255.255.255.0', 2, 'bad IP:', 'none'),
    'addr-bad-mask': ('set-addr bn0 192.0.2.20 invalid', 2, 'bad MASK:', 'none'),
    'addr-nodev': ('set-addr no_such_if 192.0.2.20 255.255.255.0', 1, 'SIOCSIFADDR', 'nodev'),
    'addr-perm': ('set-addr bn0 192.0.2.20 255.255.255.0', 1, 'SIOCSIFADDR', 'addrperm'),
    'route-missing': ('set-route', 2, 'set-route needs GATEWAY', 'none'),
    'route-missing-iface': ('set-route 192.0.2.1 -i', 2, '-i needs IFACE', 'none'),
    'route-extra': ('set-route 192.0.2.1 extra', 2, 'set-route: extra arg', 'none'),
    'route-bad-gateway': ('set-route invalid', 2, 'bad GATEWAY:', 'none'),
    'route-long-iface': ('set-route 192.0.2.1 -i abcdefghijklmnop', 2, 'interface name too long:', 'none'),
    'route-auto': ('set-route 192.0.2.1', 0, '', 'auto'),
    'route-iface': ('set-route 192.0.2.1 -i bn1', 0, '', 'iface'),
    'route-repeat': ('set-route 192.0.2.1 -i bn0', 0, '', 'duplicate'),
    'route-unreachable': ('set-route 203.0.113.1 -i bn0', 1, 'SIOCADDRT via', 'unreachable'),
    'route-perm': ('set-route 192.0.2.1 -i bn0', 1, 'SIOCADDRT via', 'routeperm'),
}


def write(name, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    if len(data) > 900000:
        raise RuntimeError('diagnostic exceeds safe retention limit: ' + name)
    (HOME / name).write_bytes(data)


def guest():
    token = str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    actual = str(uuid.UUID(Path('/sys/class/dmi/id/product_uuid').read_text().strip()))
    if (token != actual or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
            or Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(HOME)
            or os.uname().machine != 'x86_64'):
        raise RuntimeError('guest identity mismatch')


def run(argv, events, label):
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        event = {'label': label, 'argv': argv, 'status': p.returncode,
                 'stdout_b64': base64.b64encode(p.stdout[:MAX_OUTPUT]).decode(),
                 'stderr_b64': base64.b64encode(p.stderr[:MAX_OUTPUT]).decode(),
                 'stdout_bytes': len(p.stdout), 'stderr_bytes': len(p.stderr)}
        events.append(event); write('network-controls.json', events)
        if p.returncode or len(p.stdout) > MAX_OUTPUT or len(p.stderr) > MAX_OUTPUT:
            raise RuntimeError('control failed: ' + label)
        return p.stdout
    except subprocess.TimeoutExpired as exc:
        events.append({'label': label, 'argv': argv, 'timeout': True,
                       'stdout_b64': base64.b64encode(exc.stdout or b'').decode(),
                       'stderr_b64': base64.b64encode(exc.stderr or b'').decode()})
        write('network-controls.json', events)
        raise RuntimeError('control timed out: ' + label) from exc


def parse_trace(raw, complete=True):
    if not raw or len(raw) > 500000 or not raw.endswith(b'\n'):
        raise ValueError('empty, oversized or incomplete trace')
    events = [json.loads(line) for line in raw.splitlines()]
    if not events or events[0].get('type') != 'exec':
        raise ValueError('missing exec record')
    if not re.fullmatch(r'[0-9a-fA-F]{1,16}', events[0].get('cap_eff', '')):
        raise ValueError('bad capability record')
    if any(e.get('type') == 'observer_error' for e in events):
        raise ValueError('observer failed')
    if any(e.get('type') == 'spawn' for e in events):
        raise ValueError('tracee attempted process creation; descendant tracing unavailable')
    if sum(e.get('type') == 'exec' for e in events) != 1:
        raise ValueError('duplicate exec record')
    if complete and (events[-1].get('type') != 'exit' or sum(e.get('type') == 'exit' for e in events) != 1):
        raise ValueError('missing exit record')
    for e in events:
        if e.get('type') not in ('exec', 'marker', 'ioctl', 'exit'):
            raise ValueError('unknown trace event')
        if e.get('type') == 'ioctl' and (type(e.get('request')) is not int or type(e.get('errno')) is not int or
                                          type(e.get('return')) is not int or type(e.get('valid')) is not bool):
            raise ValueError('malformed ioctl record')
        if e.get('type') == 'exit' and (type(e.get('status')) is not int or type(e.get('signal')) is not int):
            raise ValueError('malformed exit record')
    markers = [e.get('phase') for e in events if e['type'] == 'marker']
    if markers not in ([], ['begin'], ['begin', 'end']):
        raise ValueError('malformed operation markers')
    phase = 'before'
    for event in events:
        if event['type'] == 'marker':
            phase = 'inside' if event['phase'] == 'begin' else 'after'
        if event['type'] == 'ioctl' and event.get('window') != phase:
            raise ValueError('ioctl window disagrees with markers')
    return events


def observe(argv, mode, label, controls, product=False):
    trace = HOME / ('trace-' + label + '.jsonl')
    command = [TRACER, str(trace), mode, 'mark'] + argv
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    totals = {'stdout': 0, 'stderr': 0}
    reason = 'exited'; deadline = time.monotonic() + 8
    with selectors.DefaultSelector() as sel:
        for name in chunks:
            stream = getattr(proc, name); os.set_blocking(stream.fileno(), False); sel.register(stream, selectors.EVENT_READ, name)
        while sel.get_map():
            if time.monotonic() >= deadline:
                reason = 'timeout'; break
            if trace.exists() and trace.stat().st_size > 100000:
                reason = 'trace-limit'; break
            for key, _ in sel.select(.05):
                data = os.read(key.fd, 16384)
                if not data:
                    sel.unregister(key.fileobj); continue
                name = key.data; totals[name] += len(data)
                chunks[name].extend(data[:max(0, MAX_OUTPUT - len(chunks[name]))])
                if totals[name] > MAX_OUTPUT: reason = 'output-limit'; break
            if reason != 'exited': break
        if reason == 'exited':
            try: proc.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired: reason = 'timeout'
    if reason != 'exited':
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
    proc.wait(timeout=5)
    if reason == 'exited' and trace.exists() and trace.stat().st_size > 100000:
        reason = 'trace-limit'
    with trace.open('rb') if trace.exists() else open(os.devnull, 'rb') as stream:
        raw = stream.read(110001)
    record = {'label': label, 'argv': argv, 'mode': mode, 'capture_mode': 'mark', 'termination': reason,
              'tracer_status': proc.returncode, 'stdout_b64': base64.b64encode(chunks['stdout']).decode(),
              'stderr_b64': base64.b64encode(chunks['stderr']).decode(), 'bytes_observed': totals,
              'trace_bytes_at_stop': trace.stat().st_size if trace.exists() else 0,
              'trace_prefix_only': trace.exists() and trace.stat().st_size > len(raw),
              'trace_b64': base64.b64encode(raw).decode()}
    controls.append(record); write('network-controls.json', controls)
    if reason != 'exited':
        if not product: raise RuntimeError('native observer did not complete: ' + label)
        # Retain the raw partial line; only complete lines are parsed.
        complete_lines = raw[:raw.rfind(b'\n') + 1]
        partial = parse_trace(complete_lines, complete=False)
        if bool(int(partial[0]['cap_eff'], 16) & (1 << 12)) != (mode == 'keep'):
            raise RuntimeError('tracee capability control failed: ' + label)
        record['events'] = partial
        record['outcome'] = observation_outcome(record)
        write('network-controls.json', controls)
        return record
    if proc.returncode != 0:
        raise RuntimeError('observer infrastructure failed: ' + label)
    record['events'] = parse_trace(raw)
    cap = int(record['events'][0]['cap_eff'], 16)
    if bool(cap & (1 << 12)) != (mode == 'keep'):
        raise RuntimeError('tracee capability control failed: ' + label)
    if product:
        record['outcome'] = observation_outcome(record)
    write('network-controls.json', controls)
    return record


def ip(events, *args):
    return run([IP, *args], events, 'ip-' + '-'.join(args))


def route_records(raw):
    data = json.loads(raw)
    if not isinstance(data, list) or any(not isinstance(x, dict) for x in data):
        raise ValueError('invalid route data')
    defaults = [x for x in data if x.get('dst') == 'default']
    if len(defaults) > 1:
        raise ValueError('ambiguous defaults')
    for r in defaults:
        if not isinstance(r.get('gateway'), str) or not isinstance(r.get('dev'), str):
            raise ValueError('default route fields missing')
    return data


def kernel_defaults(text):
    lines = text.splitlines()
    if not lines or lines[0].split()[:4] != ['Iface', 'Destination', 'Gateway', 'Flags']:
        raise ValueError('invalid proc route header')
    defaults = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != 11 or any(not re.fullmatch(r'[0-9A-Fa-f]{8}', fields[i]) for i in (1, 2, 7)):
            raise ValueError('invalid proc route row')
        if fields[1] == '00000000' and fields[7] == '00000000':
            defaults.append({'dev': fields[0], 'gateway': socket.inet_ntoa(struct.pack('<I', int(fields[2], 16))),
                             'flags': int(fields[3], 16)})
    if len(defaults) > 1:
        raise ValueError('ambiguous proc default routes')
    return defaults


def snapshot(events):
    interfaces = {}
    for name in ('bn0', 'bn1'):
        data = json.loads(ip(events, '-j', '-4', 'addr', 'show', 'dev', name))
        if not isinstance(data, list) or len(data) != 1 or data[0].get('ifname') != name or not isinstance(data[0].get('addr_info'), list):
            raise RuntimeError('bad interface data')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            raw = fcntl.ioctl(sock.fileno(), 0x8913, struct.pack('16s24x', name.encode()))
        interfaces[name] = {'json': data[0], 'flags': struct.unpack_from('H', raw, 16)[0]}
    routes_raw = ip(events, '-j', '-4', 'route', 'show', 'table', 'main')
    routes = route_records(routes_raw)
    proc = Path('/proc/net/route').read_text()
    if not proc.startswith('Iface\t') or len(proc) > 65536:
        raise RuntimeError('route table unavailable')
    return {'interfaces': interfaces, 'routes': routes, 'proc_route': proc, 'kernel_defaults': kernel_defaults(proc)}


def ios(record):
    return [e for e in record['events'] if e['type'] == 'ioctl' and e.get('window') == 'inside']


def ioctl_check(event, req, err, name=None, addr=None):
    return (event.get('request') == req and event.get('valid') is True and event.get('errno') == err and
            event.get('return') == (-err if err else 0) and
            (name is None or event.get('ifname_hex') == name.encode().hex()) and
            (addr is None or (event.get('address_family') == socket.AF_INET and event.get('address') == addr)))


def route_check(event, gateway, dev, err):
    return (ioctl_check(event, ROUTE, err) and event.get('dst') == '0.0.0.0' and event.get('mask') == '0.0.0.0' and
            all(event.get(x + '_family') == socket.AF_INET for x in ('dst', 'mask', 'gateway')) and
            event.get('gateway') == gateway and event.get('flags') == 3 and
            event.get('dev_present') == (dev is not None) and
            (dev is None or (event.get('dev_valid') is True and event.get('dev_hex') == dev.encode().hex())))


def native_marked(events, label, args, mode, guard):
    rec = observe([NATIVE, '--marked', guard, *args], mode, label, events)
    phases = [e.get('phase') for e in rec['events'] if e['type'] == 'marker']
    outside = [e for e in rec['events'] if e['type'] == 'ioctl' and
               e.get('window') in ('before', 'after') and e.get('request') == GETFLAGS and
               e.get('ifname_hex') == guard.encode().hex()]
    if (phases != ['begin', 'end'] or len(outside) != 2 or
            [e['window'] for e in outside] != ['before', 'after'] or
            any(not ioctl_check(e, GETFLAGS, 0, guard) for e in outside) or
            base64.b64decode(rec['stdout_b64']) or base64.b64decode(rec['stderr_b64'])):
        raise RuntimeError('marked native observer control failed: ' + label)
    return rec


def defaults(state):
    return [r for r in state['routes'] if r.get('dst') == 'default']


def observation_outcome(obs):
    markers = [e.get('phase') for e in obs['events'] if e['type'] == 'marker']
    if obs['termination'] != 'exited':
        if markers == ['begin', 'end']: return 'post-operation-limit'
        return 'operation-limit' if markers == ['begin'] else 'startup-unresolved'
    if not markers:
        return 'early-exit'
    if markers == ['begin']:
        return 'operation-interrupted'
    if markers == ['begin', 'end']:
        return 'operation-exited'
    raise ValueError('invalid candidate markers')


def assess_observation(name, obs):
    command, expected, fragment, kind = CASES[name]
    del command
    fail = []
    def check(x, msg):
        if not x: fail.append(msg)
    outcome = observation_outcome(obs)
    if outcome == 'startup-unresolved':
        raise RuntimeError('candidate interrupted before operation marker')
    if outcome in ('operation-limit', 'post-operation-limit'): return ['candidate ' + outcome + ': ' + obs['termination']]
    if outcome in ('early-exit', 'operation-interrupted'):
        return ['candidate ' + outcome]
    events = obs['events']; seq = ios(obs)
    check([e.get('phase') for e in events if e['type'] == 'marker'] == ['begin', 'end'], 'missing or duplicate operation marker')
    check(events[-1]['status'] == expected and events[-1]['signal'] == 0, 'status')
    check(base64.b64decode(obs['stdout_b64'], validate=True) == b'', 'stdout')
    stderr = base64.b64decode(obs['stderr_b64'], validate=True)
    check(fragment.encode() in stderr if fragment else stderr == b'', 'stderr')
    before, after = obs['before'], obs['after']
    if kind == 'none':
        check(not seq, 'validation issued an ioctl')
        check(before == after, 'validation changed network state')
    elif kind in ('addr', 'nodev', 'addrperm'):
        e = {'addr': 0, 'nodev': errno.ENODEV, 'addrperm': errno.EPERM}[kind]
        iface = 'no_such_if' if kind == 'nodev' else 'bn0'
        expected_len = 4 if kind == 'addr' else 1
        check(len(seq) == expected_len, 'address ioctl count')
        if seq:
            check(ioctl_check(seq[0], ADDR, e, iface, '192.0.2.20'), 'address request/return')
        if kind == 'addr' and len(seq) == 4:
            check(ioctl_check(seq[1], MASK, 0, 'bn0', '255.255.255.0'), 'netmask request/return')
            check(ioctl_check(seq[2], GETFLAGS, 0, 'bn0'), 'get-flags request/return')
            check(ioctl_check(seq[3], SETFLAGS, 0, 'bn0') and (seq[3].get('flags', 0) & 0x41) == 0x41, 'set-flags request/return')
        if kind == 'addr':
            iface_state = after['interfaces']['bn0']
            check((iface_state['flags'] & 0x41) == 0x41, 'kernel UP/RUNNING flags')
            check(any(a.get('local') == '192.0.2.20' and a.get('prefixlen') == 24 for a in iface_state['json']['addr_info']), 'kernel address/netmask')
        else:
            check(before == after, 'failed address changed network state')
            check((b'No such device' if kind == 'nodev' else b'Operation not permitted') in stderr, 'address errno diagnostic')
    else:
        e = {'auto': 0, 'iface': 0, 'duplicate': errno.EEXIST, 'unreachable': errno.ENETUNREACH, 'routeperm': errno.EPERM}[kind]
        dev = None if kind == 'auto' else 'bn1' if kind == 'iface' else 'bn0'
        gateway = '203.0.113.1' if kind == 'unreachable' else '192.0.2.1'
        check(len(seq) == 1 and route_check(seq[0], gateway, dev, e), 'route request/return')
        ds = defaults(after)
        if kind in ('auto', 'iface', 'duplicate'):
            want_dev = 'bn1' if kind == 'iface' else 'bn0'
            check(len(ds) == 1 and ds[0].get('gateway') == gateway and ds[0].get('dev') == want_dev, 'kernel default route')
            kd = after['kernel_defaults']
            check(len(kd) == 1 and kd[0]['gateway'] == gateway and kd[0]['dev'] == want_dev and
                  (kd[0]['flags'] & 3) == 3, 'kernel route mask/gateway flags')
        else:
            check(before == after, 'failed route changed network state')
            check((b'Network is unreachable' if kind == 'unreachable' else b'Operation not permitted') in stderr, 'route errno diagnostic')
    return fail


def parser_controls():
    valid = b'{"type":"exec","cap_eff":"00001000"}\n{"type":"marker","phase":"begin"}\n{"type":"marker","phase":"end"}\n{"type":"exit","status":0,"signal":0}\n'
    if len(parse_trace(valid)) != 4 or route_records('[{"dst":"default","gateway":"192.0.2.1","dev":"bn0"}]')[0]['dev'] != 'bn0':
        raise RuntimeError('positive parser control failed')
    windowed = (b'{"type":"exec","cap_eff":"1000"}\n'
                b'{"type":"ioctl","window":"before","request":1,"return":0,"errno":0,"valid":true}\n'
                b'{"type":"marker","phase":"begin"}\n'
                b'{"type":"ioctl","window":"inside","request":2,"return":0,"errno":0,"valid":true}\n'
                b'{"type":"marker","phase":"end"}\n'
                b'{"type":"ioctl","window":"after","request":3,"return":0,"errno":0,"valid":true}\n'
                b'{"type":"exit","status":0,"signal":0}\n')
    if [e['request'] for e in ios({'events': parse_trace(windowed)})] != [2]:
        raise RuntimeError('operation window selection control failed')
    for bad in (b'', valid[:-1], b'{"type":"exit"}\n', valid + b'{"type":"exit"}\n',
                b'{"type":"exec","cap_eff":"1000"}\n{"type":"spawn","syscall":56,"return":123}\n{"type":"exit","status":0,"signal":0}\n',
                b'{"type":"exec","cap_eff":"1000"}\n{"type":"marker","phase":"begin"}\n{"type":"marker","phase":"end"}\n{"type":"ioctl","request":1,"return":0,"errno":0,"valid":true}\n{"type":"exit","status":0,"signal":0}\n',
                b'{"type":"exec","cap_eff":"1000"}\n{"type":"ioctl","request":"x"}\n{"type":"exit"}\n'):
        try: parse_trace(bad)
        except (ValueError, KeyError, TypeError): continue
        raise RuntimeError('trace parser accepted negative control')
    for bad in ('{}', '[{"dst":"default"}]', '[{"dst":"default","gateway":"a","dev":"b"},{"dst":"default","gateway":"c","dev":"d"}]'):
        try: route_records(bad)
        except (ValueError, KeyError, TypeError): continue
        raise RuntimeError('route parser accepted negative control')
    proc_sample = 'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nbn0 00000000 010200C0 0003 0 0 0 00000000 0 0 0\n'
    if kernel_defaults(proc_sample) != [{'dev': 'bn0', 'gateway': '192.0.2.1', 'flags': 3}]:
        raise RuntimeError('proc route parser positive control')
    for bad in ('', 'Iface Destination Gateway Flags\nbroken\n', proc_sample + proc_sample.splitlines()[1] + '\n'):
        try: kernel_defaults(bad)
        except (ValueError, KeyError, TypeError): continue
        raise RuntimeError('proc route parser accepted negative control')
    state = {'interfaces': {'bn0': {'flags': 0, 'json': {'addr_info': []}},
                            'bn1': {'flags': 0, 'json': {'addr_info': []}}}, 'routes': [], 'proc_route': 'sample',
             'kernel_defaults': []}
    obs = {'termination': 'exited', 'events': [{'type': 'exec', 'cap_eff': '1000'}, {'type': 'marker', 'phase': 'begin'}, {'type': 'marker', 'phase': 'end'},
                                               {'type': 'exit', 'status': 2, 'signal': 0}],
           'stdout_b64': '', 'stderr_b64': base64.b64encode(b'bad IP: invalid').decode(),
           'before': state, 'after': copy.deepcopy(state)}
    if assess_observation('addr-bad-ip', obs): raise RuntimeError('positive assertion control failed')
    bad = copy.deepcopy(obs); bad['events'].insert(2, {'type': 'ioctl', 'window': 'inside', 'request': ADDR, 'valid': True, 'return': 0, 'errno': 0})
    if not assess_observation('addr-bad-ip', bad): raise RuntimeError('assertion ignored unexpected ioctl')
    bad = copy.deepcopy(obs); bad['after']['interfaces']['bn0']['flags'] = 1
    if not assess_observation('addr-bad-ip', bad): raise RuntimeError('assertion ignored partial state')
    for reason in ('timeout', 'output-limit', 'trace-limit'):
        bad = copy.deepcopy(obs); bad['termination'] = reason
        if observation_outcome(bad) != 'post-operation-limit': raise RuntimeError('post-operation limit misclassified')
        if not assess_observation('addr-bad-ip', bad): raise RuntimeError('assertion ignored ' + reason)
        bad['events'] = [{'type': 'exec', 'cap_eff': '1000'}, {'type': 'marker', 'phase': 'begin'}]
        if observation_outcome(bad) != 'operation-limit': raise RuntimeError('operation limit misclassified')
        if not assess_observation('addr-bad-ip', bad): raise RuntimeError('operation limit was not a candidate failure')
        bad['events'] = [{'type': 'exec', 'cap_eff': '1000'}]
        if observation_outcome(bad) != 'startup-unresolved': raise RuntimeError('pre-marker interruption classified as product failure')
        try: assess_observation('addr-bad-ip', bad)
        except RuntimeError: continue
        raise RuntimeError('pre-marker interruption was assessed as product failure')
    for phases, want in [([], 'early-exit'), (['begin'], 'operation-interrupted')]:
        bad = copy.deepcopy(obs)
        bad['events'] = [{'type': 'exec', 'cap_eff': '1000'}, *[{'type': 'marker', 'phase': p} for p in phases],
                         {'type': 'exit', 'status': 1, 'signal': 0}]
        if observation_outcome(bad) != want or assess_observation('addr-bad-ip', bad) != ['candidate ' + want]:
            raise RuntimeError('early candidate exit misclassified')
    sample = {'request': ROUTE, 'valid': True, 'return': 0, 'errno': 0, 'dst': '0.0.0.0', 'mask': '0.0.0.0',
              'gateway': '192.0.2.1', 'dst_family': 2, 'mask_family': 2, 'gateway_family': 2,
              'flags': 3, 'dev_present': True, 'dev_valid': True, 'dev_hex': 'bn1'.encode().hex()}
    if not route_check(sample, '192.0.2.1', 'bn1', 0): raise RuntimeError('route request positive control')
    for key, value in [('dev_hex', 'bn0'.encode().hex()), ('flags', 1), ('mask', '255.255.255.0'), ('errno', 17)]:
        bad = dict(sample); bad[key] = value
        if route_check(bad, '192.0.2.1', 'bn1', 0): raise RuntimeError('route request negative control: ' + key)
    # Exercise the complete candidate assertion for every scenario, with a
    # correct synthetic record and two independently incorrect records.
    for name, (_, expected, fragment, kind) in CASES.items():
        before = copy.deepcopy(state); after = copy.deepcopy(state); seq = []
        suffix = {'nodev': ' No such device', 'addrperm': ' Operation not permitted',
                  'unreachable': ' Network is unreachable', 'routeperm': ' Operation not permitted'}.get(kind, '')
        def event(req, err=0, **fields):
            return {'type': 'ioctl', 'window': 'inside', 'request': req, 'valid': True, 'return': -err if err else 0, 'errno': err, **fields}
        if kind in ('addr', 'nodev', 'addrperm'):
            err = {'addr': 0, 'nodev': errno.ENODEV, 'addrperm': errno.EPERM}[kind]
            dev = 'no_such_if' if kind == 'nodev' else 'bn0'
            seq.append(event(ADDR, err, ifname_hex=dev.encode().hex(), address_family=2, address='192.0.2.20'))
            if kind == 'addr':
                seq.extend([event(MASK, ifname_hex='bn0'.encode().hex(), address_family=2, address='255.255.255.0'),
                            event(GETFLAGS, ifname_hex='bn0'.encode().hex()),
                            event(SETFLAGS, ifname_hex='bn0'.encode().hex(), flags=0x41)])
                after['interfaces']['bn0'] = {'flags': 0x41, 'json': {'addr_info': [{'local': '192.0.2.20', 'prefixlen': 24}]}}
        elif kind != 'none':
            err = {'auto': 0, 'iface': 0, 'duplicate': errno.EEXIST,
                   'unreachable': errno.ENETUNREACH, 'routeperm': errno.EPERM}[kind]
            dev = None if kind == 'auto' else 'bn1' if kind == 'iface' else 'bn0'
            gateway = '203.0.113.1' if kind == 'unreachable' else '192.0.2.1'
            seq.append(event(ROUTE, err, dst='0.0.0.0', mask='0.0.0.0', gateway=gateway,
                             dst_family=2, mask_family=2, gateway_family=2, flags=3,
                             dev_present=dev is not None, dev_valid=dev is not None,
                             dev_hex=dev.encode().hex() if dev else ''))
            if kind in ('auto', 'iface', 'duplicate'):
                after['routes'] = [{'dst': 'default', 'gateway': gateway, 'dev': 'bn1' if kind == 'iface' else 'bn0'}]
                after['kernel_defaults'] = [{'gateway': gateway, 'dev': 'bn1' if kind == 'iface' else 'bn0', 'flags': 3}]
                if kind == 'duplicate':
                    before['routes'] = copy.deepcopy(after['routes'])
                    before['kernel_defaults'] = copy.deepcopy(after['kernel_defaults'])
        candidate = {'termination': 'exited', 'events': [{'type': 'exec'}, {'type': 'marker', 'phase': 'begin'},
                     *seq, {'type': 'marker', 'phase': 'end'}, {'type': 'exit', 'status': expected, 'signal': 0}],
                     'stdout_b64': '', 'stderr_b64': base64.b64encode((fragment + suffix).encode()).decode(),
                     'before': before, 'after': after}
        if assess_observation(name, candidate): raise RuntimeError('scenario assertion positive: ' + name)
        wrong_status = copy.deepcopy(candidate); wrong_status['events'][-1]['status'] += 1
        if not assess_observation(name, wrong_status): raise RuntimeError('scenario assertion status negative: ' + name)
        wrong_request = copy.deepcopy(candidate)
        if seq: wrong_request['events'][2]['request'] ^= 1
        else: wrong_request['events'].insert(2, event(ADDR))
        if not assess_observation(name, wrong_request): raise RuntimeError('scenario assertion ioctl negative: ' + name)
    write('network-parser-controls.json', {'trace_positive': 1, 'trace_negative': 7, 'route_positive': 1,
                                            'route_negative': 3, 'assertion_positive': 1,
                                            'assertion_negative': 5, 'request_positive': 1, 'request_negative': 4,
                                            'window_controls': 1, 'startup_limit_controls': 3,
                                            'operation_limit_controls': 3, 'post_operation_limit_controls': 3,
                                            'early_exit_controls': 2,
                                            'proc_route_positive': 1, 'proc_route_negative': 3,
                                            'scenario_positive': len(CASES), 'scenario_negative': 2 * len(CASES)})


def native_control(events):
    ip(events, 'link', 'add', 'bnc', 'type', 'dummy')
    def trace(label, args, mode='keep'):
        return native_marked(events, label, args, mode, 'bnc')
    empty = trace('native-mark-empty', ['empty', '-', '-', '-'])
    if empty['events'][-1]['status'] != 0 or ios(empty):
        raise RuntimeError('marked no-ioctl observer control failed')
    rec = trace('native-addr', ['addr', 'bnc', '198.51.100.10', '255.255.255.0'])
    seq = ios(rec)
    if (rec['events'][-1]['status'] != 0 or len(seq) != 4 or
            not ioctl_check(seq[0], ADDR, 0, 'bnc', '198.51.100.10') or
            not ioctl_check(seq[1], MASK, 0, 'bnc', '255.255.255.0') or
            not ioctl_check(seq[2], GETFLAGS, 0, 'bnc') or
            not ioctl_check(seq[3], SETFLAGS, 0, 'bnc') or (seq[3].get('flags', 0) & 0x41) != 0x41):
        raise RuntimeError('native address observer positive control failed')
    addr = json.loads(ip(events, '-j', '-4', 'addr', 'show', 'dev', 'bnc'))
    if (len(addr) != 1 or 'UP' not in addr[0].get('flags', []) or
            not any(a.get('local') == '198.51.100.10' and a.get('prefixlen') == 24 for a in addr[0].get('addr_info', []))):
        raise RuntimeError('native address readback failed')
    for label, args, mode, want, request in [
        ('native-unreachable', ['route', 'bnc', '203.0.113.1', '-'], 'keep', errno.ENETUNREACH, (ROUTE, '203.0.113.1', 'bnc', errno.ENETUNREACH)),
        ('native-route', ['route', 'bnc', '198.51.100.1', '-'], 'keep', 0, (ROUTE, '198.51.100.1', 'bnc', 0)),
        ('native-duplicate', ['route', 'bnc', '198.51.100.1', '-'], 'keep', errno.EEXIST, (ROUTE, '198.51.100.1', 'bnc', errno.EEXIST)),
        ('native-addr-perm', ['addr', 'bnc', '198.51.100.11', '255.255.255.0'], 'drop', errno.EPERM, (ADDR, 'bnc', '198.51.100.11', errno.EPERM)),
        ('native-route-perm', ['route', 'bnc', '198.51.100.1', '-'], 'drop', errno.EPERM, (ROUTE, '198.51.100.1', 'bnc', errno.EPERM)),
        ('native-nodev', ['addr', 'no_such_if', '198.51.100.11', '255.255.255.0'], 'keep', errno.ENODEV, (ADDR, 'no_such_if', '198.51.100.11', errno.ENODEV)),
    ]:
        rec = trace(label, args, mode); seq = ios(rec)
        valid = (len(seq) == 1 and (route_check(seq[0], request[1], request[2], request[3]) if request[0] == ROUTE
                                     else ioctl_check(seq[0], ADDR, request[3], request[1], request[2])))
        if rec['events'][-1]['status'] != want or not valid:
            raise RuntimeError('native observer/error control failed: ' + label)
        if label == 'native-route':
            routes = route_records(ip(events, '-j', '-4', 'route', 'show', 'default'))
            if len(routes) != 1 or routes[0].get('gateway') != '198.51.100.1' or routes[0].get('dev') != 'bnc':
                raise RuntimeError('native route readback failed')
            proc_raw = Path('/proc/net/route').read_text()
            events.append({'label': 'native-proc-route', 'text': proc_raw})
            write('network-controls.json', events)
            kernel = kernel_defaults(proc_raw)
            if len(kernel) != 1 or kernel[0]['dev'] != 'bnc' or kernel[0]['gateway'] != '198.51.100.1' or (kernel[0]['flags'] & 3) != 3:
                raise RuntimeError('native proc route readback failed')
    ip(events, 'route', 'del', 'default', 'via', '198.51.100.1', 'dev', 'bnc')
    ip(events, 'link', 'del', 'bnc')


def inner(name, outer_net, outer_user):
    events = []
    stage = {'scenario': name, 'state': 'preparing', 'stage': 'identity'}
    write('network-stage.json', stage)
    try:
        if (os.getuid() != 0 or os.geteuid() != 0 or Path('/proc/self/uid_map').read_text().split() != ['0', '2000', '1'] or
                os.readlink('/proc/self/ns/net') == outer_net or os.readlink('/proc/self/ns/user') == outer_user):
            raise RuntimeError('namespace isolation or uid mapping failed')
        cap = int(re.search(r'^CapEff:\s*([0-9a-f]+)$', Path('/proc/self/status').read_text(), re.M).group(1), 16)
        if not cap & (1 << 12): raise RuntimeError('namespace lacks CAP_NET_ADMIN')
        stage.update({'user_ns': os.readlink('/proc/self/ns/user'), 'net_ns': os.readlink('/proc/self/ns/net'),
                      'outer_user_ns': outer_user, 'outer_net_ns': outer_net, 'cap_eff': hex(cap),
                      'uid': os.getuid(), 'euid': os.geteuid(),
                      'uid_map': Path('/proc/self/uid_map').read_text(), 'stage': 'native-controls'})
        write('network-stage.json', stage)
        native_control(events)
        stage['stage'] = 'fixture'; write('network-stage.json', stage)
        ip(events, 'link', 'add', 'bn0', 'type', 'dummy')
        ip(events, 'link', 'add', 'bn1', 'type', 'dummy')
        if name.startswith('route-'):
            ip(events, 'addr', 'add', '192.0.2.20/24', 'dev', 'bn0')
            ip(events, 'addr', 'add', '192.0.2.30/24', 'dev', 'bn1')
            ip(events, 'link', 'set', 'bn0', 'up')
            ip(events, 'link', 'set', 'bn1', 'up')
            # Independently prove the unbound route chooses bn0 with both interfaces eligible.
            ctrl = native_marked(events, 'native-auto', ['route', '-', '192.0.2.1', '-'], 'keep', 'bn0')
            seq = ios(ctrl)
            if ctrl['events'][-1]['status'] != 0 or len(seq) != 1 or not route_check(seq[0], '192.0.2.1', None, 0):
                raise RuntimeError('native unbound route control failed')
            routes = route_records(ip(events, '-j', '-4', 'route', 'show', 'default'))
            if len(routes) != 1 or routes[0].get('dev') != 'bn0' or routes[0].get('gateway') != '192.0.2.1':
                raise RuntimeError('interface discrimination precondition failed')
            raw_proc = Path('/proc/net/route').read_text()
            events.append({'label': 'native-auto-proc-route', 'text': raw_proc}); write('network-controls.json', events)
            kd = kernel_defaults(raw_proc)
            if len(kd) != 1 or kd[0]['dev'] != 'bn0' or kd[0]['gateway'] != '192.0.2.1' or (kd[0]['flags'] & 3) != 3:
                raise RuntimeError('native auto proc-route control failed')
            ip(events, 'route', 'del', 'default', 'via', '192.0.2.1', 'dev', 'bn0')
            if name == 'route-repeat':
                ip(events, 'route', 'add', 'default', 'via', '192.0.2.1', 'dev', 'bn0')
        before = snapshot(events)
        ds = defaults(before)
        if name == 'route-repeat':
            if len(ds) != 1 or ds[0].get('gateway') != '192.0.2.1' or ds[0].get('dev') != 'bn0':
                raise RuntimeError('duplicate route precondition failed')
            kd = before['kernel_defaults']
            if len(kd) != 1 or kd[0]['gateway'] != '192.0.2.1' or kd[0]['dev'] != 'bn0' or (kd[0]['flags'] & 3) != 3:
                raise RuntimeError('duplicate proc route precondition failed')
        elif ds or before['kernel_defaults']:
            raise RuntimeError('unexpected initial default route')
        for dev in ('bn0', 'bn1'):
            addrs = before['interfaces'][dev]['json']['addr_info']
            if name.startswith('addr-') and addrs: raise RuntimeError('address fixture not empty')
            if name.startswith('route-'):
                expected_ip = '192.0.2.20' if dev == 'bn0' else '192.0.2.30'
                if not any(a.get('local') == expected_ip and a.get('prefixlen') == 24 for a in addrs):
                    raise RuntimeError('on-link route fixture incomplete')
        targeted = {
            'addr-nodev': (['addr', 'no_such_if', '192.0.2.20', '255.255.255.0'], 'keep', ADDR, errno.ENODEV),
            'addr-perm': (['addr', 'bn0', '192.0.2.20', '255.255.255.0'], 'drop', ADDR, errno.EPERM),
            'route-repeat': (['route', 'bn0', '192.0.2.1', '-'], 'keep', ROUTE, errno.EEXIST),
            'route-unreachable': (['route', 'bn0', '203.0.113.1', '-'], 'keep', ROUTE, errno.ENETUNREACH),
            'route-perm': (['route', 'bn0', '192.0.2.1', '-'], 'drop', ROUTE, errno.EPERM),
        }
        if name in targeted:
            args, mode, req, expected_errno = targeted[name]
            ctrl = native_marked(events, 'native-target', args, mode, 'bn0')
            seq = ios(ctrl)
            ok = (len(seq) == 1 and
                  (route_check(seq[0], args[2], args[1], expected_errno) if req == ROUTE else
                   ioctl_check(seq[0], ADDR, expected_errno, args[1], args[2])))
            if ctrl['events'][-1]['status'] != expected_errno or not ok or snapshot(events) != before:
                raise RuntimeError('scenario-specific native error control failed')
        stage['stage'] = 'candidate'; write('network-stage.json', stage)
        cmd = CASES[name][0]
        mode = 'drop' if name.endswith('-perm') else 'keep'
        argv = [CANDIDATE, '--noprofile', '--norc', '-c',
                'builtin kill -s STOP "$$"; builtin bashio ' + cmd +
                '; rc=$?; builtin kill -s STOP "$$"; exit "$rc"']
        obs = observe(argv, mode, 'candidate', events, product=True)
        obs['scenario'] = name
        obs['before'] = before
        write('network-observation.json', obs)
        if obs['outcome'] == 'startup-unresolved':
            raise RuntimeError('candidate interrupted before operation-begin; startup outcome unresolved')
        if obs['outcome'] != 'operation-exited':
            obs['after'] = None
            write('network-observation.json', obs)
            failures = assess_observation(name, obs)
            write('network-assessment.json', {'scenario': name, 'complete': True, 'outcome': obs['outcome'],
                                              'failures': failures, 'bad_mask_state': None})
            stage.update({'stage': 'complete', 'state': 'complete', 'termination': obs['termination']})
            write('network-stage.json', stage)
            return
        obs['after'] = snapshot(events)
        write('network-observation.json', obs)
        failures = assess_observation(name, obs)
        partial = {'before_bn0': before['interfaces']['bn0'], 'after_bn0': obs['after']['interfaces']['bn0']}
        write('network-assessment.json', {'scenario': name, 'complete': True, 'outcome': obs['outcome'], 'failures': failures,
                                          'bad_mask_state': partial if name == 'addr-bad-mask' else None})
        stage.update({'stage': 'complete', 'state': 'complete', 'termination': obs['termination']})
        write('network-stage.json', stage)
    except Exception as exc:
        stage.update({'state': 'setup-error', 'error': repr(exc)})
        write('network-stage.json', stage)
        raise


def setup(name):
    if os.getuid() != 2000 or os.geteuid() != 2000 or name not in CASES:
        raise RuntimeError('outer identity or scenario invalid')
    parser_controls()
    events = []
    for source, target in [('bashio-network-reviewed-tracer.c', TRACER), ('bashio-network-reviewed-native.c', NATIVE)]:
        run(['/usr/bin/gcc', '-O2', '-Wall', '-Wextra', '-o', target, str(HELPERS / source)], events, 'compile-' + source)
    write('network-compile.json', events)
    outer = {'user': os.readlink('/proc/self/ns/user'), 'net': os.readlink('/proc/self/ns/net')}
    identity = {'uid': os.getuid(), 'euid': os.geteuid(),
                'vendor': Path('/sys/class/dmi/id/sys_vendor').read_text().strip(),
                'uuid': str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())),
                'product_uuid': str(uuid.UUID(Path('/sys/class/dmi/id/product_uuid').read_text().strip()))}
    write('network-outer.json', {'state': 'launching', 'namespaces': outer, 'identity': identity})
    try:
        result = subprocess.run(['/usr/bin/unshare', '--user', '--map-root-user', '--net', '/usr/bin/python3', HERE,
                                 'inner', name, outer['net'], outer['user']], capture_output=True, timeout=52)
        write('network-outer.json', {'state': 'finished', 'namespaces': outer, 'identity': identity, 'status': result.returncode,
                                     'stdout_b64': base64.b64encode(result.stdout[:MAX_OUTPUT]).decode(),
                                     'stderr_b64': base64.b64encode(result.stderr[:MAX_OUTPUT]).decode(),
                                     'stdout_bytes': len(result.stdout), 'stderr_bytes': len(result.stderr)})
        if result.returncode or len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
            raise RuntimeError('namespace or fixture setup failed; inspect stage and controls')
    except subprocess.TimeoutExpired as exc:
        write('network-outer.json', {'state': 'timeout', 'namespaces': outer, 'identity': identity,
                                     'stdout_b64': base64.b64encode(exc.stdout or b'').decode(),
                                     'stderr_b64': base64.b64encode(exc.stderr or b'').decode()})
        raise RuntimeError('namespace setup timed out') from exc


def assess(name):
    data = json.loads((HOME / 'network-assessment.json').read_text())
    if data.get('scenario') != name or data.get('complete') is not True or not isinstance(data.get('failures'), list):
        raise RuntimeError('incomplete assessment')
    if data['failures']:
        print('candidate mismatch: ' + ', '.join(data['failures']), file=sys.stderr)
        return 1
    print('observed ' + name)
    return 0


def main():
    guest()
    if len(sys.argv) == 3 and sys.argv[1] == 'setup': setup(sys.argv[2]); return 0
    if len(sys.argv) == 5 and sys.argv[1] == 'inner': inner(sys.argv[2], sys.argv[3], sys.argv[4]); return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'assess': return assess(sys.argv[2])
    raise ValueError('invalid invocation')


if __name__ == '__main__':
    raise SystemExit(main())
