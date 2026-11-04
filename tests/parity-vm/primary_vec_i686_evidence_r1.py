#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the pinned i686 qualification pair as source-artifact coverage only.

No subprocesses, guest imports, device access or subject execution. Integrating
this exact reader accepts the coordinator's issued pair for vec r4; it does not
assert that either native ELF64 candidate can execute without SSE2.
"""
from decimal import Decimal
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

FORMAT = 'primary-qualified-vec-i686-r1'
CASE_SHA = '0f4de9a26fa1cbce56f9751572813c8ae7f82fe71a8ce2532100802e12fcc2a6'
CASE_ID = 'qualification-014-vec-i686-no-sse2'
INVENTORY_SHA = 'f5ee16117ebbc759688982a49ba2de6bd0440c767a861edf6ded88e31ebbbc5a'
VEC_SHA = 'fba407cc9d386e66a1d83370bf6fab32e19f9e0524ec28997bc55fd88f21b9df'
VERSIONS_SHA = '47d54f053002d4de072e51fb04d02f2d2644a9c998b64742ebbc44320ca5b0f7'
CORES = {
    'static': '2e3a622e6a18e2a215a6672c99e35ce12bb58268bf5539f0d6d79faba4055468',
    'dynamic': '04587baa95655f203395dc778bc7346873fd9682e2727c6c13226e46ac7661c7',
}
SHELL = '/home/qual/stock-i686/bash-stock'
MODULE = '/home/qual/variants-i686/vec-i686.so'
PROBE = '/home/qual/variants-i686/cpu-i686'
BACKENDS = (None, 'auto', 'scalar', 'sse2', 'avx2')
SCRIPT_SHA = 'a8120f6e77c07d414e8a4dd35c7e77db5277ed98388f8be03be5d4a22ac22dfb'
SCOPE = 'separate-i686-source-artifact'
LIMITATIONS = [
    'The tested subject is the separate i686 vec module in stock Bash 5.3.20.',
    'Native static/dynamic r2 builds are bound by identical vec source, not by execution of ELF64 without SSE2.',
    'This registration covers vec r4 only; independent r1-r3 companion results remain required.',
    'The earlier Pentium III CPUID-only environment failed the instruction gate and remains historical.',
]


def require(condition, message):
    if not condition:
        raise ValueError('vec i686 evidence: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('invalid JSON numeric constant: ' + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def digest(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'canonical absolute file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'ordinary file required: ' + path.name)
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            'file changed while hashing: ' + path.name)
    return value


def stream(row, field):
    value = bytes.fromhex(row[field + '_hex'])
    require(sha(value) == row[field + '_sha256'], 'raw ' + field + ' digest')
    return value


def oracle():
    """Independent exact arithmetic; no candidate or driver code is imported."""
    expected = []
    for kind in ('i32', 'u32', 'i64', 'u64', 'f32', 'f64'):
        for length in (1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65):
            left = [Decimal((17*i+3) % 41-20) for i in range(length)]
            right = [Decimal((11*i+7) % 29-14) for i in range(length)]
            if kind[0] == 'u':
                left = [v+20 for v in left]; right = [v+14 for v in right]
            elif kind[0] == 'f':
                left = [v/2 for v in left]; right = [v/2 for v in right]
            expected.extend((sum(left), min(left), max(left), sum(a*b for a, b in zip(left, right))))
    require(len(expected) == 408, 'oracle cardinality')
    return expected


def validate_observations(positive, negative, artifacts):
    require(positive.get('result') == 'PASS' and positive.get('scope') ==
            'new i686 shell/module, not x86-64 release evidence', 'positive scope/result')
    require(positive['binaries'] == {p: artifacts[p] for p in (SHELL, MODULE, PROBE)}, 'subject identities')
    for report, flags, code in (
            (positive, dict(pointer_bits=32, sse2=0, avx=0, avx2=0, sse2_sigill=1), 0),
            (negative, dict(pointer_bits=32, sse2=1, avx=0, avx2=0, sse2_sigill=0), 125)):
        cpu = report['cpu']
        require(cpu['argv'] == [PROBE] and type(cpu['status']) is int and cpu['status'] == code,
                'instruction probe attribution/status')
        actual_flags = decode(stream(cpu, 'stdout'))
        require(not stream(cpu, 'stderr') and actual_flags == flags and
                all(type(v) is int for v in actual_flags.values()),
                'actual instruction rejection/negative control')
        require(cpu['stdin_sha256'] == sha(b''), 'probe stdin')
    require(set(negative) == {'cpu', 'reason', 'result'} and negative['result'] == 'ERROR' and
            negative['reason'] == 'non-SSE2 prerequisite missing', 'negative must stop before vector behavior')
    version = positive['bash_version']
    require(version['status'] == 0 and version['shell_sha256'] == artifacts[SHELL] and
            stream(version, 'stdout') == b'5.3.20\n' and not stream(version, 'stderr') and
            version['argv'][:4] == [SHELL, '--noprofile', '--norc', '-c'], 'stock shell version')
    rows = positive['observations']
    require(len(rows) == 5 and [r['backend'] for r in rows] == list(BACKENDS) and
            positive['exact_assertions_per_backend'] == 408, 'backend/cardinality coverage')
    expected = oracle()
    command_hashes = set()
    for row in rows:
        args = row['argv']
        require(len(args) == 7 and args[:4] == [SHELL, '--noprofile', '--norc', '-c'] and
                args[5:] == ['qualification', MODULE], 'vector subject command')
        command_hashes.add(sha(args[4].encode()))
        values = stream(row, 'stdout').decode('ascii').splitlines()
        require(row['status'] == 0 and row['matches'] is True and not stream(row, 'stderr') and
                row['stdin_sha256'] == sha(b'') and len(values) == 409 and values[0] == 'scalar',
                'backend or raw execution result')
        require([Decimal(s) for s in values[1:]] == expected, 'independent exact reductions')
    require(command_hashes == {SCRIPT_SHA}, 'executed vector script differs')
    return {'assertions': 2040, 'backends': list(BACKENDS), 'cpu_sigill': True,
            'sse2_enabled_control_rejected': True, 'script_sha256': next(iter(command_hashes))}


def cleanup(row):
    require(row.get('clean_poweroff') is True and row.get('forced_stop') is False and
            type(row.get('qemu_exit_status')) is int and row['qemu_exit_status'] == 0 and
            row.get('poweroff_request') == 0, 'clean shutdown')


def archive_storage(path):
    """True for a path under an archive-only root named in BASH_OS_ARCHIVE_PATHS."""
    roots = [Path(entry).resolve() for entry in
             os.environ.get('BASH_OS_ARCHIVE_PATHS', '').split(':') if entry]
    return any(path == root or root in path.parents for root in roots)


def inspect(spec, repo):
    """Data-only full-pair audit. Caller cannot supply replacement trusted pins."""
    inventory_path = Path(spec['inventory_path'])
    require(digest(inventory_path) == INVENTORY_SHA, 'inventory is not the reviewed exact inventory')
    inventory = decode(inventory_path.read_bytes())
    require(inventory['schema'] == 'vec-i686-evidence-inventory-v1' and
            set(inventory['roots']) == set(spec['roots']) == {'i686', 'native', 'lifecycle'}, 'inventory roots')
    roots = {name: Path(value) for name, value in spec['roots'].items()}
    for root in roots.values():
        require(root.is_absolute() and root.resolve() == root and root.is_dir() and
                not archive_storage(root), 'canonical active-storage evidence root')
    verified = {}
    for group, files in inventory['roots'].items():
        verified[group] = {}
        for name, entry in files.items():
            rel = PurePosixPath(name)
            require(not rel.is_absolute() and '..' not in rel.parts and str(rel) == name, 'inventory member name')
            path = roots[group]/name
            value = digest(path)
            require(path.stat().st_size == entry['bytes'] and value == entry['sha256'], 'pinned file: ' + name)
            verified[group][name] = value
    def read(group, name):
        require(name in verified[group], 'unbound evidence read: ' + name)
        data = (roots[group]/name).read_bytes()
        require(sha(data) == verified[group][name], 'evidence changed: ' + name)
        return decode(data)
    def pin(group, name):
        return verified[group][name]

    build = read('i686', 'built/build.json'); stock = read('i686', 'built/stock-build.json')
    inputs = read('i686', 'runtime-inputs.json'); settings = read('i686', 'settings.json')
    status = read('i686', 'built/status.json'); preparation = read('lifecycle', 'receipt.json')
    native = read('native', 'build-receipt.json'); sources = read('native', 'source-inputs.json')
    require(native['state'] == 'built' and native['bash'] == '5.3.20' and
            native['source_inputs_sha256'] == pin('native', 'source-inputs.json'), 'native r2 source binding')
    for name, value in native['files'].items():
        require(pin('native', 'out/'+Path(name).name) == value, 'native build artifact binding')
    for side, value in CORES.items():
        name = 'bash-migration014-r2-' + ('static-static' if side == 'static' else 'dynamic')
        require(pin('native', 'out/'+name) == value, 'native r2 build identity')
    repo = Path(repo).resolve()
    require(sources['loadables/vec.c'] == pin('i686', 'payload/repo/loadables/vec.c') ==
            digest(repo/'loadables/vec.c') == VEC_SHA, 'current/native/i686 vec source mismatch')
    require(sources['config/versions.sh'] == stock['versions_sha256'] ==
            pin('i686', 'payload/repo/config/versions.sh') == digest(repo/'config/versions.sh') == VERSIONS_SHA,
            'Bash 5.3.20 source configuration mismatch')
    require(build['mode'] == stock['mode'] == 'i686' and
            build['required_bash'] == stock['required_bash'] == '5.3.20' and
            build['config_h_sha256'] == stock['config_h_sha256'] and
            build['patchlevel_h_sha256'] == stock['patchlevel_h_sha256'] and
            set(stock['patch_inputs_sha256']) == {f'bash53-{n:03}' for n in range(1, 21)}, 'i686 build/header/patch scope')
    require({'-m32', '-march=i686', '-mno-sse', '-mno-sse2', '-mfpmath=387', '-fno-tree-vectorize'} <=
            set(build['common_flags']), 'i686 compile flags')
    for name, value in build['source_inputs_sha256'].items():
        require(pin('i686', 'payload/repo/'+name) == value, 'i686 source input: ' + name)
    require(status['stage'] == 'complete' and preparation['state'] == 'complete' and
            preparation['parent_unchanged'] is True and preparation['base_unchanged'] is True,
            'build/lifecycle preparation incomplete')
    cleanup(status['teardown']); cleanup(preparation['teardown'])
    for name, value in status['files'].items():
        require(pin('i686', 'built/'+name) == value, 'built image/kernel/archive identity')
    require(preparation['parent_image_sha256'] == status['files']['built-i386.qcow2'] and
            preparation['image_sha256'] == pin('lifecycle', 'built-i386.qcow2'), 'prepared VM image chain')

    members = {}
    archive_bytes = (roots['i686']/'built/build-evidence.tar.gz').read_bytes()
    require(sha(archive_bytes) == pin('i686', 'built/build-evidence.tar.gz'), 'build archive changed')
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as archive:
        for member in archive:
            rel = PurePosixPath(member.name)
            require(not rel.is_absolute() and '..' not in rel.parts and member.name not in members,
                    'unsafe/duplicate build archive member')
            if member.isdir():
                continue
            require(member.isfile() and 0 <= member.size <= 2*1024*1024, 'unexpected archive member type/size')
            with archive.extractfile(member) as source:
                members[member.name] = source.read()
    prefix = 'rootfs/home/qual/variants-i686/'
    require(sha(members[prefix+'build.json']) == pin('i686', 'built/build.json') and
            sha(members['rootfs/home/qual/stock-i686/stock-build.json']) == pin('i686', 'built/stock-build.json'),
            'saved build manifests differ from archive')
    for name, value in build['files_sha256'].items():
        require(sha(members[prefix+name]) == value, 'archived build output: ' + name)
    original = decode(members[prefix+'inputs.json'])
    require(original['source_sha256']['loadables/vec.c'] == VEC_SHA, 'compiled vec source differs')
    for name in ('vec-i686.so', 'cpu-i686'):
        data = members[prefix+name]
        require(data[:6] == b'\x7fELF\x01\x01' and int.from_bytes(data[18:20], 'little') == 3,
                'portability artifact is not little-endian ELF32 i386')
    require(b'ELF32' in members['rootfs/home/qual/stock-i686/elf-header.txt'] and
            b'#define __SSE2__' not in members[prefix+'vec-macros.txt'], 'i686 loader/compiler data')
    artifacts = inputs['files']
    require(artifacts[SHELL] == stock['shell_sha256'] and
            artifacts[MODULE] == build['files_sha256']['vec-i686.so'] and
            artifacts[PROBE] == build['files_sha256']['cpu-i686'] and
            inputs['stock_build_sha256'] == pin('i686', 'built/stock-build.json') and
            inputs['native_build_sha256'] == pin('i686', 'built/build.json'), 'runtime/build bindings')
    require(set(artifacts) == {SHELL, MODULE, PROBE,
            '/home/qual/payload/repo/tests/qualification-limits/guest.py',
            '/home/qual/payload/repo/tests/qualification-limits/vec-nosse2.py'}, 'exact runtime inputs')
    for name in ('guest.py', 'vec-nosse2.py'):
        require(artifacts['/home/qual/payload/repo/tests/qualification-limits/'+name] ==
                pin('i686', 'payload/repo/tests/qualification-limits/'+name) ==
                digest(repo/'tests/qualification-limits'/name), 'current/executed driver differs')

    summary = read('i686', 'tcg-runs-r3/summary.json')
    require([r['label'] for r in summary] == ['no-sse2', 'sse2-negative-control'], 'paired run selection')
    reports = []
    for index, (label, cpu, result, code) in enumerate((
            ('no-sse2', 'pentium2', 'PASS', 0),
            ('sse2-negative-control', 'pentium2,+sse,+sse2', 'ERROR', 125))):
        prefix = 'tcg-runs-r3/'+label+'/'
        receipt = read('i686', prefix+'receipt.json'); report = read('i686', prefix+'qualification.json')
        machine = read('i686', prefix+'vm/vm.json'); identity = read('i686', prefix+'vm/identity.json')
        require(receipt == summary[index] and receipt['state'] == 'qualified' and
                receipt['label'] == label and receipt['cpu'] == cpu and receipt['result'] == result and
                receipt['driver_status'] == code and receipt['overlay_discarded'] is True and
                receipt['image_unchanged'] is True, 'pair status/lifecycle')
        require(not (roots['i686']/prefix/'overlay.qcow2').exists(), 'overlay still present')
        require(receipt['inputs'] == inputs and receipt['verified_guest_inputs'] == artifacts and
                receipt['image_sha256'] == preparation['image_sha256'] and
                receipt['preparation_sha256'] == pin('lifecycle', 'receipt.json') and
                receipt['controller_sha256'] == pin('i686', 'run-tcg-r3.py'), 'controller/image/input receipt')
        require(receipt['identity'] == identity and identity['marker_matches'] is True and
                identity['product_uuid_matches'] is True and identity['virtualization'] == 'qemu' and
                identity['sys_vendor'] == 'QEMU' and identity['host_shared_mounts'] == [], 'VM identity/isolation')
        require(pin('i686', prefix+'vm/identity-root.raw') == identity['identity_root_raw_sha256'], 'raw VM identity')
        require(identity['attestation']['status'] == 'validated', 'VM attestation')
        for action in ('write', 'read'):
            proof = identity['attestation']['phases'][action]
            require(proof['status'] == 'validated' and proof['exit_status'] == 0 and
                    proof['stdout_sha256'] == pin('i686', prefix+'vm/'+proof['stdout_file']) and
                    proof['stderr_sha256'] == pin('i686', prefix+'vm/'+proof['stderr_file']) == sha(b''),
                    'attestation raw binding')
            raw = read('i686', prefix+'vm/'+proof['stdout_file'])
            require(raw == proof['proof'] and raw['token'] == machine['uuid'] == settings['guest_uuid'] and
                    raw['dmi_hex'] == raw['marker_hex'] == raw['attestation_hex'] == (raw['token']+'\n').encode().hex(),
                    'attestation token')
        args = machine['argv']
        require(machine['cpu'] == cpu and machine['provisioning'] is False and
                args[args.index('-machine')+1] == 'pc-i440fx-9.2,accel=tcg' and
                args[args.index('-cpu')+1] == cpu and args[args.index('-uuid')+1] == settings['guest_uuid'] and
                '-enable-kvm' not in args and args[args.index('-smp')+1] == '1' and
                'restrict=on' in args[args.index('-netdev')+1], 'actual TCG argv')
        network = receipt['network']
        require(network['canary_accepted'] == 0 and
                all(str(network[k]).startswith('blocked:') for k in ('dns', 'host_canary', 'public_tcp')),
                'network isolation controls')
        cleanup(receipt['teardown'])
        require(receipt['teardown'] == read('i686', prefix+'vm/teardown.json'), 'teardown binding')
        for name in ('driver.stdout', 'driver.stderr', 'collection.stderr'):
            require(pin('i686', prefix+name) == sha(b''), 'transport diagnostics: ' + name)
        reports.append(report)
    detail = validate_observations(*reports, artifacts)
    return {'scope': SCOPE, 'source_vec_sha256': VEC_SHA, 'inventory_sha256': INVENTORY_SHA,
            'tested_artifacts': {p: artifacts[p] for p in (SHELL, MODULE, PROBE)},
            'vm_image_sha256': preparation['image_sha256'], 'detail': detail,
            'limitations': LIMITATIONS, 'host_candidate_execution': False}


def load_qualified_vec_i686(spec, expected_binary, expected_build, repo=None):
    require(expected_build in CORES and expected_binary == CORES[expected_build], 'selected native r2 identity')
    require(spec.get('evidence_format') == FORMAT and spec.get('artifact_scope') == SCOPE and
            spec.get('groups') == ['shell'] and spec.get('ids') == [CASE_ID] and
            not spec.get('exclude_ids'), 'explicit source-artifact selection required')
    require(digest(spec['core_binary_path']) == expected_binary, 'selected core hash')
    repo = Path(repo) if repo is not None else Path(__file__).resolve().parents[2]
    metadata = inspect(spec, repo)
    definition = decode((Path(__file__).parent/'evidence-suites/migration-vec-i686-r1.json').read_bytes())['cases'][0]
    require(definition['id'] == CASE_ID and definition['artifact_scope'] == SCOPE and
            sha(json.dumps(definition, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()) == CASE_SHA,
            'registration scope/definition')
    row = {'group': 'shell', 'id': CASE_ID, 'status': 'PASS',
           'artifact_scope': SCOPE, 'exact_assertions': 2040, 'native_binary_executed': False}
    selected = [{'record': row, 'definition': definition, 'sources': {}, 'run': spec['name']}]
    metadata.update(name=spec['name'], groups=['shell'], selected_records=1,
                    evidence_format=FORMAT, candidate_sha256=expected_binary,
                    native_binary_executed=False)
    return selected, metadata
