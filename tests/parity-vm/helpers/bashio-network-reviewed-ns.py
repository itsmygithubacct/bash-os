#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only namespace observations; ioctl request fields are not traced here."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

HOME = Path('/tmp/parity-home')
HERE = '/opt/bashos-parity/harness/helpers/bashio-network-reviewed-ns.py'
CANDIDATE = '/opt/bashos-parity/candidate'
IP = '/usr/sbin/ip'
SCENARIOS = {
    'addr-success': ['set-addr bn0 192.0.2.20 255.255.255.0'],
    'addr-bad-mask': ['set-addr bn0 192.0.2.20 invalid'],
    'addr-nodev': ['set-addr no_such_if 192.0.2.20 255.255.255.0'],
    'route-auto': ['set-route 192.0.2.1'],
    'route-iface-repeat': ['set-route 192.0.2.1 -i bn0', 'set-route 192.0.2.1 -i bn0'],
    'route-unreachable': ['set-route 203.0.113.1 -i bn0'],
}


def guest():
    marker = str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    product = str(uuid.UUID(Path('/sys/class/dmi/id/product_uuid').read_text().strip()))
    if (marker != product or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
            or Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(HOME)):
        raise RuntimeError('guest identity mismatch')


def run(argv, events, label, required=True):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise RuntimeError('observation exceeds diagnostic limit: ' + label)
    events.append({'label': label, 'argv': argv, 'status': result.returncode,
                   'stdout_b64': base64.b64encode(result.stdout).decode(),
                   'stderr_b64': base64.b64encode(result.stderr).decode()})
    if required and result.returncode != 0:
        raise RuntimeError('control failed: ' + label)
    return result


def interface_record(data, name):
    records = json.loads(data)
    if not isinstance(records, list) or len(records) != 1 or records[0].get('ifname') != name:
        raise ValueError('interface observation incomplete')
    if not isinstance(records[0].get('flags'), list) or not isinstance(records[0].get('addr_info'), list):
        raise ValueError('interface fields missing')
    return records[0]


def snapshot(events, label):
    addr = run([IP, '-j', '-4', 'addr', 'show', 'dev', 'bn0'], events, label + '-addr')
    route = run([IP, '-j', '-4', 'route', 'show', 'table', 'main'], events, label + '-route')
    interface = interface_record(addr.stdout, 'bn0')
    routes = json.loads(route.stdout)
    if not isinstance(routes, list):
        raise RuntimeError('route observation incomplete')
    proc = Path('/proc/net/route').read_text()
    events.append({'label': label + '-proc-route', 'text': proc})
    if not proc.startswith('Iface\t') or len(proc) > 65536:
        raise RuntimeError('route table unavailable')
    return {'interface': interface, 'routes': routes, 'proc_route': proc}


def inner(scenario, outer_net, outer_user):
    events = []
    try:
        if (os.getuid() != 0 or os.geteuid() != 0 or
                Path('/proc/self/uid_map').read_text().split() != ['0', '2000', '1'] or
                os.readlink('/proc/self/ns/net') == outer_net or
                os.readlink('/proc/self/ns/user') == outer_user):
            raise RuntimeError('fresh user and network namespace precondition failed')
        cap = int(re.search(r'^CapEff:\s*([0-9a-f]+)$', Path('/proc/self/status').read_text(), re.M).group(1), 16)
        if not cap & (1 << 12):
            raise RuntimeError('namespace lacks CAP_NET_ADMIN')
        events.append({'label': 'namespace', 'user': os.readlink('/proc/self/ns/user'),
                       'net': os.readlink('/proc/self/ns/net'), 'outer_user': outer_user,
                       'outer_net': outer_net, 'uid_map': Path('/proc/self/uid_map').read_text(),
                       'cap_eff': hex(cap)})
        run([IP, 'link', 'add', 'bnc', 'type', 'dummy'], events, 'native-create')
        run([IP, 'addr', 'add', '198.51.100.10/24', 'dev', 'bnc'], events, 'native-address')
        run([IP, 'link', 'set', 'bnc', 'up'], events, 'native-up')
        native_addr = json.loads(run([IP, '-j', '-4', 'addr', 'show', 'dev', 'bnc'], events, 'native-address-read').stdout)
        if (len(native_addr) != 1 or 'UP' not in native_addr[0].get('flags', []) or
                not any(a.get('local') == '198.51.100.10' and a.get('prefixlen') == 24
                        for a in native_addr[0].get('addr_info', []))):
            raise RuntimeError('native address or flag readback mismatch')
        run([IP, 'route', 'add', 'default', 'via', '198.51.100.1', 'dev', 'bnc'], events, 'native-route')
        native = run([IP, '-j', 'route', 'show', 'default'], events, 'native-route-read')
        observed = json.loads(native.stdout)
        if len(observed) != 1 or observed[0].get('gateway') != '198.51.100.1' or observed[0].get('dev') != 'bnc':
            raise RuntimeError('native route readback mismatch')
        run([IP, 'route', 'del', 'default', 'via', '198.51.100.1', 'dev', 'bnc'], events, 'native-route-delete')
        run([IP, 'link', 'del', 'bnc'], events, 'native-delete')
        run([IP, 'link', 'add', 'bn0', 'type', 'dummy'], events, 'fixture-create')
        if scenario.startswith('route-'):
            run([IP, 'addr', 'add', '192.0.2.20/24', 'dev', 'bn0'], events, 'fixture-address')
            run([IP, 'link', 'set', 'bn0', 'up'], events, 'fixture-up')
        before = snapshot(events, 'before')
        infos = before['interface'].get('addr_info', [])
        if any(r.get('dst') == 'default' for r in before['routes']):
            raise RuntimeError('fixture has a default route before candidate')
        if scenario.startswith('addr-') and infos:
            raise RuntimeError('address fixture unexpectedly populated')
        if scenario.startswith('route-') and not any(a.get('local') == '192.0.2.20' and a.get('prefixlen') == 24 for a in infos):
            raise RuntimeError('route fixture has no on-link address')
        observations = []
        for index, command in enumerate(SCENARIOS[scenario]):
            result = run([CANDIDATE, '--noprofile', '--norc', '-c', 'builtin bashio ' + command],
                         events, 'candidate-' + str(index), required=False)
            after = snapshot(events, 'after-' + str(index))
            observations.append({'status': result.returncode,
                                 'stdout_b64': base64.b64encode(result.stdout).decode(),
                                 'stderr_b64': base64.b64encode(result.stderr).decode(), 'state': after})
        (HOME / 'namespace-observation.json').write_text(json.dumps({'scenario': scenario, 'before': before,
                                                                      'observations': observations}, indent=2) + '\n')
    finally:
        (HOME / 'namespace-events.json').write_text(json.dumps(events, indent=2) + '\n')


def setup(scenario):
    if os.getuid() != 2000 or os.geteuid() != 2000:
        raise RuntimeError('outer user is not uid 2000')
    if scenario not in SCENARIOS:
        raise RuntimeError('unknown scenario')
    assert interface_record('[{"ifname":"bn0","flags":[],"addr_info":[]}]', 'bn0')['ifname'] == 'bn0'
    for invalid in ('[]', '[{"ifname":"bn0"}]', '[{"ifname":"other","flags":[],"addr_info":[]}]'):
        try:
            interface_record(invalid, 'bn0')
        except ValueError:
            continue
        raise RuntimeError('interface parser accepted an invalid control')
    (HOME / 'namespace-parser-controls.json').write_text('{"positive":1,"negative":3}\n')
    events = []
    result = run(['/usr/bin/unshare', '--user', '--map-root-user', '--net', '/usr/bin/python3', HERE,
                  'inner', scenario, os.readlink('/proc/self/ns/net'), os.readlink('/proc/self/ns/user')],
                 events, 'unshare', required=False)
    (HOME / 'namespace-setup.json').write_text(json.dumps(events, indent=2) + '\n')
    if result.returncode != 0:
        raise RuntimeError('namespace setup or control failed; see namespace-setup and namespace-events')


def assess(scenario):
    data = json.loads((HOME / 'namespace-observation.json').read_text())
    if data['scenario'] != scenario or len(data['observations']) != len(SCENARIOS[scenario]):
        raise RuntimeError('observation incomplete')
    failures = []
    obs = data['observations']
    def check(value, message):
        if not value: failures.append(message)
    def outputs(item, status, fragment=''):
        check(item['status'] == status, 'status')
        check(base64.b64decode(item['stdout_b64'], validate=True) == b'', 'stdout')
        stderr = base64.b64decode(item['stderr_b64'], validate=True)
        check((fragment.encode() in stderr) if fragment else not stderr, 'stderr')
    if scenario == 'addr-success':
        outputs(obs[0], 0)
        iface = obs[0]['state']['interface']
        check('UP' in iface.get('flags', []), 'interface not up')
        check(any(a.get('local') == '192.0.2.20' and a.get('prefixlen') == 24 for a in iface.get('addr_info', [])), 'address or mask')
    elif scenario == 'addr-bad-mask':
        outputs(obs[0], 2, 'bad MASK')
    elif scenario == 'addr-nodev':
        outputs(obs[0], 1, 'SIOCSIFADDR')
        check(b'No such device' in base64.b64decode(obs[0]['stderr_b64']), 'missing ENODEV')
    elif scenario in ('route-auto', 'route-iface-repeat'):
        for item in obs:
            outputs(item, 0)
            defaults = [r for r in item['state']['routes'] if r.get('dst') == 'default']
            check(len(defaults) == 1 and defaults[0].get('gateway') == '192.0.2.1' and defaults[0].get('dev') == 'bn0', 'default route')
    else:
        outputs(obs[0], 1, 'SIOCADDRT via')
        check(b'Network is unreachable' in base64.b64decode(obs[0]['stderr_b64']), 'missing ENETUNREACH')
        check(not any(r.get('dst') == 'default' for r in obs[0]['state']['routes']), 'unexpected default route')
    (HOME / 'namespace-assertion.json').write_text(json.dumps({'scenario': scenario, 'failures': failures}, indent=2) + '\n')
    if failures:
        print('candidate mismatch: ' + ', '.join(failures), file=sys.stderr)
        return 1
    print('observed ' + scenario)
    return 0


def main():
    guest()
    if len(sys.argv) == 3 and sys.argv[1] == 'setup':
        setup(sys.argv[2]); return 0
    if len(sys.argv) == 5 and sys.argv[1] == 'inner':
        inner(sys.argv[2], sys.argv[3], sys.argv[4]); return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'assess':
        return assess(sys.argv[2])
    raise ValueError('bad invocation')


if __name__ == '__main__':
    raise SystemExit(main())
