#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Assemble the reference directory for the authority qualification cases.

    stage-qualification.py --build DIR --output REFDIR \\
        --libargon2 FILE --libseccomp FILE [--route default|explicit] \\
        [--suite FILE] [--registry FILE --dynamic BASH --static BASH]

DIR is the output of

    kernel/bashos-auth/tools/build-authority.sh --kdir KDIR --out DIR --qualification

for the guest kernel. Nothing here compiles, loads or runs anything: the
script copies the built modules and native programs, the guest drivers from
this directory and the two pinned distribution libraries into REFDIR, and
writes one receipt per driver family. Each receipt lists every file of its
directory with SHA-256 and length, names the endpoint its drivers must use,
and binds the build tool's own receipt by SHA-256.

REFDIR is what `vm.py run --references REFDIR` uploads:

    privcmd/                 production /dev/bashos-privcmd-v2 family
    executor/                executor fault observer for privcmd/
    privcmd-test/            the same drivers on bashos_privcmd_v2_test.ko
    authority-consumers/     production /dev/bashos-auth-v2 family
    authority-consumers-test/  the same drivers on bashos_auth_v2_test.ko

A production directory never contains a test module. A test directory exists
only for the controls that need a fault knob or a test-only ioctl; the matrix
file names them.

--suite rewrites the receipt and driver pins (and the control inventory pin
from qualification-matrix.json) inside the named suite file and prints them.
The committed pins are those of the reference build; a different build has
different module bytes and therefore needs this refresh in the tree that runs
the cases. A candidate hash is never written to a suite.

--registry writes the source-pin registry the executor observer placement
needs (it names both candidate hashes, so it is generated, not committed).
It belongs at tests/parity-vm/executor-observer-pins-r2.json of the tree
that runs vm.py.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
HARNESS = REPO / 'tests/parity-vm'
PINS = HERE / 'qualification-guest-pins.json'
MATRIX = HERE / 'qualification-matrix.json'
TRANSPORT = 'helpers/qualification-authority-v2-r1.py'
GUEST_ROOT = '/opt/bashos-parity'
FAULT_VERIFIERS = ['fault-verifier-%d' % n for n in range(1, 16)]
PRIVCMD_NATIVE = ['executor-v2', 'verifier-v2', 'privcmd-target', 'safeedit-editor', 'policy-model-controls']
PRIVCMD_DRIVERS = {'guest-privcmd-controls.py': 'privcmd-v2/guest-controls.py',
                   'guest-safeedit-controls.py': 'privcmd-v2/guest-safeedit-controls.py',
                   'guest-command-timestamp-controls.py': 'privcmd-v2/guest-command-timestamp-controls.py',
                   'guest-denial-no-helper.py': 'privcmd-v2/guest-denial-no-helper.py'}
EXECUTOR_NATIVE = ['executor-observed', 'executor-bad-continue', 'executor-bad-saved']
EXECUTOR_DRIVERS = {'executor-observer.py': 'privcmd-v2/executor-observer.py',
                    'guest-executor-controls-ancestor-r2.py': 'privcmd-v2/guest-executor-controls-ancestor-r2.py'}
IDENTITY_NATIVE = ['verifier-v2', 'consumer-target', 'login-state-negative'] + FAULT_VERIFIERS
IDENTITY_DRIVERS = {'guest-controls.py': 'protocol-v2/guest-controls.py',
                    'guest-consumers.py': 'protocol-v2/guest-consumers.py',
                    'guest-login-state.py': 'protocol-v2/guest-login-state.py',
                    'guest-ssh-restrictions.py': 'protocol-v2/guest-ssh-restrictions.py',
                    'guest-ssh-completion.py': 'protocol-v2/guest-ssh-completion.py',
                    'consumer-observer.py': 'protocol-v2/consumer-observer.py',
                    'auth-client-listener.py': '../parity-vm/helpers/auth-client-listener.py'}
PROTOCOL_MEMBERS = ['verifier-v2', 'guest-controls.py', 'libargon2.so.1'] + FAULT_VERIFIERS
ENDPOINTS = {'production': '', 'qualification': '_test'}
BUILD_RECEIPT, SOURCE_MANIFEST = 'authority-build-receipt.json', 'authority-source-manifest.txt'


def require(value, reason):
    if not value:
        raise SystemExit('stage-qualification.py: ' + reason)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def regular(path):
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode), 'not a regular file: ' + str(path))
    return Path(path)


def pin(path):
    return {'sha256': sha(path), 'bytes': Path(path).stat().st_size}


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


class Stage:
    def __init__(self, args):
        self.args = args
        self.build = args.build.resolve()
        self.tool_receipt = regular(self.build / 'receipt.json')
        self.tool = json.loads(self.tool_receipt.read_text())
        require(self.tool.get('schema') == 1 and self.tool.get('kind') == 'bashos-authority-build' and
                self.tool.get('qualification') is True and self.tool.get('behavior_executed') is False,
                '--build is not a build-authority.sh --qualification output')
        for name, entry in self.tool['files'].items():
            path = regular(self.build / name)
            require(Path(name).name == name and pin(path) == entry, 'build output differs from its receipt: ' + name)
        manifest = regular(self.build / 'source-manifest.txt')
        require(sha(manifest) == self.tool['source_manifest_sha256'], 'source manifest differs from the build receipt')
        self.manifest = {}
        for line in manifest.read_text().splitlines():
            digest, name = line.split('  ', 1)
            self.manifest[name.removeprefix('./')] = digest
        self.pins = json.loads(PINS.read_text())
        self.libraries = {'libargon2.so.1': regular(args.libargon2), 'libseccomp.so.2': regular(args.libseccomp)}
        for name, path in self.libraries.items():
            require(sha(path) == self.pins['libraries'][name]['sha256'], name + ' is not the pinned distribution library')
        self.written = {}

    def source(self, relative):
        """A driver from this tree; the build must have seen the same bytes."""
        path = regular((HERE / relative).resolve())
        name = str(path.relative_to(REPO))
        if name in self.manifest:
            require(self.manifest[name] == sha(path), 'driver differs from the built source tree: ' + name)
        return path

    def directory(self, name, modules, native, drivers, libraries):
        target = self.args.output / name
        target.mkdir()
        for item in modules + native:
            require(item in self.tool['files'], 'build output lacks ' + item)
            shutil.copyfile(self.build / item, target / item)
            (target / item).chmod(0o644 if item.endswith('.ko') else 0o755)
        staged = []
        for item, relative in drivers.items():
            shutil.copyfile(self.source(relative), target / item)
            (target / item).chmod(0o644)
            staged.append(item)
        for item in libraries:
            shutil.copyfile(self.libraries[item], target / item)
            (target / item).chmod(0o644)
            staged.append(item)
        shutil.copyfile(self.tool_receipt, target / BUILD_RECEIPT)
        shutil.copyfile(self.build / 'source-manifest.txt', target / SOURCE_MANIFEST)
        for item in (BUILD_RECEIPT, SOURCE_MANIFEST):
            (target / item).chmod(0o644)
        return target, staged

    def receipt(self, target, filename, kind, endpoint, members, staged, extra):
        files = {name: pin(target / name) for name in sorted(members)}
        value = {'schema': 1, 'kind': kind, 'kernel_release': self.tool['kernel_release'],
                 'endpoint': endpoint, 'behavior_executed': False, 'files': files,
                 'source_manifest_sha256': self.tool['source_manifest_sha256'],
                 'build': {'receipt': BUILD_RECEIPT, 'sha256': sha(self.tool_receipt),
                           'source_manifest': SOURCE_MANIFEST,
                           'source_manifest_sha256': self.tool['source_manifest_sha256'],
                           'staged': sorted(name for name in members if name in staged)}}
        if endpoint == 'production':
            value['consumer_route'] = self.args.route
        value.update(extra)
        # Read every member back before the receipt claims it.
        for name, entry in files.items():
            require(pin(target / name) == entry, 'staged member changed: ' + name)
        value['input_readback_unchanged'] = True
        path = target / filename
        write(path, value)
        path.chmod(0o644)
        self.written[str(path.relative_to(self.args.output))] = sha(path)
        return sha(path)

    def privcmd(self, name, endpoint):
        module = 'bashos_privcmd_v2%s.ko' % ENDPOINTS[endpoint]
        target, staged = self.directory(name, [module], PRIVCMD_NATIVE, PRIVCMD_DRIVERS, ['libargon2.so.1'])
        executor = {'admitted_source_manifest_sha256': self.tool['source_manifest_sha256'],
                    'executor_source_sha256': self.manifest['kernel/bashos-auth/authority/v2/executor.c'],
                    'executor_protocol_sha256': self.manifest['kernel/bashos-auth/authority/v2/executor-protocol.h']}
        members = [module] + PRIVCMD_NATIVE + list(PRIVCMD_DRIVERS) + ['libargon2.so.1']
        base = self.receipt(target, 'privcmd-build-receipt.json', 'authority-privcmd-v2-build-only', endpoint,
                            members, staged, executor)
        return base, executor

    def executor(self, base, executor):
        target, staged = self.directory('executor', [], EXECUTOR_NATIVE, EXECUTOR_DRIVERS, [])
        extra = dict(executor, base_receipt_sha256=base,
                     controls={'actual_consumer': 27, 'deliberate_bad_executor_rejections': 2})
        self.receipt(target, 'executor-observer-build-receipt.json', 'authority-executor-observer-build-only',
                     'production', EXECUTOR_NATIVE + list(EXECUTOR_DRIVERS), staged, extra)

    def identity(self, name, endpoint):
        module = 'bashos_auth_v2%s.ko' % ENDPOINTS[endpoint]
        target, staged = self.directory(name, ['bashos_auth_stage1.ko', module], IDENTITY_NATIVE, IDENTITY_DRIVERS,
                                        ['libargon2.so.1', 'libseccomp.so.2'])
        self.receipt(target, 'build-receipt.json', 'authority-protocol-v2-build-only', endpoint,
                     [module] + PROTOCOL_MEMBERS, staged, {})
        members = ['bashos_auth_stage1.ko', module] + IDENTITY_NATIVE + list(IDENTITY_DRIVERS) + \
                  ['libargon2.so.1', 'libseccomp.so.2']
        self.receipt(target, 'consumer-build-receipt.json', 'authority-consumer-v2-build-only', endpoint,
                     members, staged, {'guest_tools': self.pins['guest_tools'],
                                       'login_state_overlay': {'name': 'login-state-ssh-merge-r1'},
                                       'ssh_restrictions_overlay': {'name': 'ssh-restrictions-r1'},
                                       'ssh_completion_overlay': {'name': 'ssh-completion-r1'}})

    def run(self):
        require(not self.args.output.exists(), '--output must not exist')
        self.args.output.mkdir(parents=True)
        base, executor = self.privcmd('privcmd', 'production')
        self.executor(base, executor)
        self.privcmd('privcmd-test', 'qualification')
        self.identity('authority-consumers', 'production')
        self.identity('authority-consumers-test', 'qualification')


def refresh_suite(stage, suite):
    """Rewrite the receipt, driver and inventory pins of one suite file."""
    references = stage.args.output
    matrix = json.loads(MATRIX.read_text())['cases'] if MATRIX.exists() else {}
    data = json.loads(suite.read_text())
    changed = []
    for case in data['cases']:
        if 'authority-inputs.json' not in case.get('files', {}):
            continue
        spec = json.loads(case['files']['authority-inputs.json'])
        before = dict(spec)
        spec['receipt_sha256'] = sha(references / spec['receipt'])
        spec['driver_sha256'] = sha(references / spec['driver'])
        if 'observer_receipt' in spec:
            spec['observer_receipt_sha256'] = sha(references / spec['observer_receipt'])
        if case['id'] in matrix:
            ids = matrix[case['id']]['controls']
            spec['expected_controls'] = len(ids)
            spec['control_ids_sha256'] = hashlib.sha256(('\n'.join(ids) + '\n').encode()).hexdigest()
            spec['not_run'] = matrix[case['id']].get('not_run', [])
            if not spec['not_run']:
                del spec['not_run']
        case['files']['authority-inputs.json'] = json.dumps(spec, sort_keys=True) + '\n'
        case['stdout'] = 'PASS endpoint=%s controls=%d\n' % (spec['endpoint'], spec['expected_controls'])
        if TRANSPORT in case.get('helpers_sha256', {}):
            case['helpers_sha256'][TRANSPORT] = sha(HARNESS / TRANSPORT)
        if spec != before:
            changed.append(case['id'])
        print('pin %s receipt=%s driver=%s controls=%d' % (case['id'], spec['receipt_sha256'], spec['driver_sha256'],
                                                           spec['expected_controls']))
    suite.write_text(json.dumps(data, indent=2) + '\n')
    print('suite %s: %d case pin set(s) changed' % (suite, len(changed)))


def registry(stage, suites):
    """Source pins for the executor observer placement (vm.py --ancestor-executor-observer)."""
    args = stage.args
    harness = Path(args.registry).resolve().parent
    names = ['executor_observer_broker_r2.py', 'executor_observer_client_r2.py', 'executor_observer_contract_r2.py',
             'executor_observer_launcher_r2.py', 'executor_observer_transport_r2.py', 'guest.py', 'schema.py',
             'vm.py', 'image.lock.json', TRANSPORT] + ['suites/' + Path(suite).name for suite in suites]
    files = {GUEST_ROOT + '/harness/' + name: sha(harness / name) for name in names}
    for directory in ('privcmd', 'executor'):
        for path in sorted((args.output / directory).iterdir()):
            if path.suffix in ('.py', '.json'):
                files['%s/reference-data/%s/%s' % (GUEST_ROOT, directory, path.name)] = sha(path)
    addon = json.loads((args.output / 'executor/executor-observer-build-receipt.json').read_text())
    base = json.loads((args.output / 'privcmd/privcmd-build-receipt.json').read_text())
    value = {'schema': 'ancestor-observer-source-pins-r1', 'kernel_release': stage.tool['kernel_release'],
             'candidates': {'dynamic': sha(regular(args.dynamic)), 'static': sha(regular(args.static))},
             'files': files, 'target_sha256': base['files']['privcmd-target']['sha256'],
             'executors': {name: addon['files'][name]['sha256'] for name in EXECUTOR_NATIVE}}
    require(len(json.dumps(value, indent=2, sort_keys=True).encode()) + 1 <= 8192 and
            len(json.dumps(files).encode()) <= 5000, 'source registry would exceed the observer wire bounds')
    write(Path(args.registry), value)
    print('registry %s sha256=%s' % (args.registry, sha(args.registry)))
    print('  candidates dynamic=%s static=%s' % (value['candidates']['dynamic'], value['candidates']['static']))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--build', type=Path, required=True, help='build-authority.sh --qualification output')
    parser.add_argument('--output', type=Path, required=True, help='reference directory to create')
    parser.add_argument('--libargon2', type=Path, required=True, help='the pinned libargon2.so.1')
    parser.add_argument('--libseccomp', type=Path, required=True, help='the pinned libseccomp.so.2')
    parser.add_argument('--route', choices=('default', 'explicit'), default='default',
                        help='production doas/sudo invocation: no authority flag (default) or --authority-v2')
    parser.add_argument('--suite', type=Path, action='append', default=[], help='suite file whose pins to rewrite')
    parser.add_argument('--registry', type=Path, help='write the executor observer source-pin registry here')
    parser.add_argument('--dynamic', type=Path, help='dynamic candidate (registry only)')
    parser.add_argument('--static', type=Path, help='static candidate (registry only)')
    args = parser.parse_args()
    require(bool(args.registry) == bool(args.dynamic) == bool(args.static),
            '--registry, --dynamic and --static go together')
    stage = Stage(args)
    stage.run()
    for name, digest in sorted(stage.written.items()):
        print('receipt %s sha256=%s' % (name, digest))
    for suite in args.suite:
        refresh_suite(stage, suite)
    if args.registry:
        registry(stage, args.suite)
    return 0


if __name__ == '__main__':
    sys.exit(main())
