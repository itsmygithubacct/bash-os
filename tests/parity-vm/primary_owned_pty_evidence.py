#!/usr/bin/env python3
"""Receipt-bound owned-PTY evidence reader. Data only; empty authority registry."""
import base64, hashlib, json, os, re, stat, sys, tarfile, types
from pathlib import Path

class IncompleteEvidence(ValueError):
    pass

def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result

class _Optional:
    @staticmethod
    def parse_json(data, limit=8*1024**2):
        if not isinstance(data, bytes) or len(data) > limit:
            raise ValueError('JSON size bound exceeded')
        return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs)
    @staticmethod
    def open_single(path, limit):
        fd = os.dup(path) if type(path) is int else os.open(path, os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
        f = os.fdopen(fd, 'rb')
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
            f.close(); raise ValueError('expected bounded single-link regular file')
        f.seek(0)
        return f, st.st_size
    @staticmethod
    def stream_sha(stream):
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(1024*1024), b''): h.update(block)
        return h.hexdigest()
    @staticmethod
    def sha_bytes(data): return hashlib.sha256(data).hexdigest()

optional = _Optional()
def optional_sha_path(path, limit):
    stream, _ = optional.open_single(path, limit)
    with stream: return optional.stream_sha(stream)

# Only these exact local validator sources are permitted; receipt registry must
# separately authorize one for each static/dynamic run. Both are data-only.
_VALIDATORS = {
    '4591c9a07113de118d2689a5ff923cef3ec638391202151e3bcb7923ede58ac6': 'primary_owned_crypto_validator.py',
    'abe1dd268d8fbe1ffc11f3b797a46c38e40397c68c50bac3daa73d21c309ccaf': 'primary_owned_passive_validator.py',
}
def load_reviewed_module(name, expected):
    if name != 'standard_terminal213' or expected not in _VALIDATORS:
        raise IncompleteEvidence('terminal evidence validator not source-authorized')
    path = Path(__file__).resolve().parent / _VALIDATORS[expected]
    stream, size = optional.open_single(path, 2*1024**2)
    with stream: data = stream.read(2*1024**2+1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != expected:
        raise IncompleteEvidence('terminal evidence validator hash differs')
    module = types.ModuleType('primary_owned_pty_validator')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module

OPTIONAL_SELFCHECKS = frozenset('selfcheck-'+name for name in (
    'bounded-output','bounded-time','invalid-oracle-is-error','candidate-mismatch-is-fail',
    'network-isolation','orphan-cleanup','detached-orphan-cleanup','scratch-isolation',
    'migration-is-metadata-252','setup-classification','diagnostic-capture',
    'file-size-allowance','syscall-sequence-observer'))
OWNED_PTY_SELFCHECKS = OPTIONAL_SELFCHECKS | frozenset({'selfcheck-owned-pty-observer'})
# Empty until primary issues the actual paired receipts and this source is
# reviewed and refrozen. Each digest has a 'runs' dict with two exact contexts.
OWNED_PTY_RECEIPT_BINDINGS = {'91dd3f3afa73e13864817418bfa9ae6d0eb53468c636a22e6572f57ed66fa565': {'runs': {'pty-session-dynamic': {'evidence': {'archive_sha256': '93b54cd505d8c753b9af84e154776d53a52074555248c2209bf989e9acf12200',
                                                                                                                    'candidate_sha256': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
                                                                                                                    'case_order': ['migration-pty-session-setsid-errno-r3',
                                                                                                                                   'migration-terminal213-pty-foreground-passive-r4'],
                                                                                                                    'case_sha256': {'migration-pty-session-setsid-errno-r3': '53ff81f4ab82b1fbe663659ef042c04c157a9ea9e3a18cba40f915a7c261a512',
                                                                                                                                    'migration-terminal213-pty-foreground-passive-r4': '231e05df846c7cdf4a7c488de1647f2ce405d016c73a776203bd983e1bf37dc5'},
                                                                                                                    'fixture_sha256': '48c6d5a09397ed5664c8d76b61c06d1ba49272baa00d97b774337fac781ff2bb',
                                                                                                                    'guest_status': 0,
                                                                                                                    'reference_sha256': '9010aa2e3e2e37a25bbc68b6223d29486e79580e827866debd13749f1c28d508',
                                                                                                                    'summary_sha256': '7c0b609b7ba47bf35806e686a6149efd287a6de97521ffe529442050a51f2b42',
                                                                                                                    'vm_uuid': 'cbecd893-fef0-4324-81f0-dfa621254e5a'},
                                                                                                       'terminal_module_sha256': 'abe1dd268d8fbe1ffc11f3b797a46c38e40397c68c50bac3daa73d21c309ccaf'},
                                                                               'pty-session-static': {'evidence': {'archive_sha256': '9a125ba5106be338e145d1e90ddf0fab3699af8fe7853205a6161d207b708371',
                                                                                                                   'candidate_sha256': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
                                                                                                                   'case_order': ['migration-pty-session-setsid-errno-r3',
                                                                                                                                  'migration-terminal213-pty-foreground-passive-r4'],
                                                                                                                   'case_sha256': {'migration-pty-session-setsid-errno-r3': '53ff81f4ab82b1fbe663659ef042c04c157a9ea9e3a18cba40f915a7c261a512',
                                                                                                                                   'migration-terminal213-pty-foreground-passive-r4': '231e05df846c7cdf4a7c488de1647f2ce405d016c73a776203bd983e1bf37dc5'},
                                                                                                                   'fixture_sha256': '48c6d5a09397ed5664c8d76b61c06d1ba49272baa00d97b774337fac781ff2bb',
                                                                                                                   'guest_status': 0,
                                                                                                                   'reference_sha256': '9010aa2e3e2e37a25bbc68b6223d29486e79580e827866debd13749f1c28d508',
                                                                                                                   'summary_sha256': '3b14e1737a48067f23fc894840ff0c2e0ecdb1b7a1d224c92cc3e83c3846392d',
                                                                                                                   'vm_uuid': 'f67d6992-df65-4f04-8830-d132ec278496'},
                                                                                                      'terminal_module_sha256': 'abe1dd268d8fbe1ffc11f3b797a46c38e40397c68c50bac3daa73d21c309ccaf'}}},
 'f10a597f80d7ff45c3fe5d820f94999e6e7f2e299ebc5af0a1ae4af04b87a763': {'runs': {'crypto-secret-dynamic': {'evidence': {'archive_sha256': '51e970c8164c792a2c215262303a572426cc45d28b9806d6e236c6d9e5bad4cf',
                                                                                                                      'candidate_sha256': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
                                                                                                                      'case_order': ['migration-terminal213-crypto-secret-lf-r3',
                                                                                                                                     'migration-terminal213-crypto-secret-cr-r3'],
                                                                                                                      'case_sha256': {'migration-terminal213-crypto-secret-cr-r3': 'b9b33bae340461cc844ec6124f22b94125f7d4242391c1bf68c856cbc8f86555',
                                                                                                                                      'migration-terminal213-crypto-secret-lf-r3': '34e3690faf246309c5d95e2b61f726fae901f1ffbc4c168ffab552eb7eafc7b8'},
                                                                                                                      'fixture_sha256': 'c0b76e1f206876d93becb2e1967643594da9035d60e8782f9aa141e7926797c0',
                                                                                                                      'guest_status': 0,
                                                                                                                      'reference_sha256': '9010aa2e3e2e37a25bbc68b6223d29486e79580e827866debd13749f1c28d508',
                                                                                                                      'summary_sha256': '01e923007b36750ffcfec03533bde3db7845778ec406102d26d6d087fede7b5f',
                                                                                                                      'vm_uuid': 'd94d5a23-d15e-466a-98b0-bb1998171981'},
                                                                                                         'terminal_module_sha256': '4591c9a07113de118d2689a5ff923cef3ec638391202151e3bcb7923ede58ac6'},
                                                                               'crypto-secret-static': {'evidence': {'archive_sha256': '9a195ded3866a48c04ab4066eac902c960a1f71e294bc6f4b60417b13393690a',
                                                                                                                     'candidate_sha256': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
                                                                                                                     'case_order': ['migration-terminal213-crypto-secret-lf-r3',
                                                                                                                                    'migration-terminal213-crypto-secret-cr-r3'],
                                                                                                                     'case_sha256': {'migration-terminal213-crypto-secret-cr-r3': 'b9b33bae340461cc844ec6124f22b94125f7d4242391c1bf68c856cbc8f86555',
                                                                                                                                     'migration-terminal213-crypto-secret-lf-r3': '34e3690faf246309c5d95e2b61f726fae901f1ffbc4c168ffab552eb7eafc7b8'},
                                                                                                                     'fixture_sha256': 'c0b76e1f206876d93becb2e1967643594da9035d60e8782f9aa141e7926797c0',
                                                                                                                     'guest_status': 0,
                                                                                                                     'reference_sha256': '9010aa2e3e2e37a25bbc68b6223d29486e79580e827866debd13749f1c28d508',
                                                                                                                     'summary_sha256': '65cf1eb2ba4348f88575d1b463158f83c7e1b3c37b308894f636243f8cb374e3',
                                                                                                                     'vm_uuid': '504c633e-69fe-4fb9-8151-765e45de0e19'},
                                                                                                        'terminal_module_sha256': '4591c9a07113de118d2689a5ff923cef3ec638391202151e3bcb7923ede58ac6'}}}}

def owned_pty_receipt_checks(receipt_raw, run_key, context):
    if not isinstance(receipt_raw, bytes) or not 0 < len(receipt_raw) < 1024 * 1024:
        raise IncompleteEvidence('owned PTY receipt is absent or exceeds cap')
    paired = OWNED_PTY_RECEIPT_BINDINGS.get(hashlib.sha256(receipt_raw).hexdigest())
    if not isinstance(run_key, str) or not re.fullmatch('[A-Za-z0-9_-]+', run_key):
        raise IncompleteEvidence('invalid owned PTY receipt run')
    if not isinstance(paired, dict) or set(paired) != {'runs'} or (not isinstance(paired['runs'], dict)):
        raise IncompleteEvidence('owned PTY receipt is not source-authorized')
    bound = paired['runs'].get(run_key)
    if not isinstance(bound, dict) or set(bound) != {'evidence', 'terminal_module_sha256'} or bound['evidence'] != context or (not isinstance(bound['terminal_module_sha256'], str)) or (not re.fullmatch('[0-9a-f]{64}', bound['terminal_module_sha256'])):
        raise IncompleteEvidence('owned PTY receipt or evidence binding is not source-authorized')
    return (OWNED_PTY_SELFCHECKS, bound['terminal_module_sha256'])

def validate_diagnostic_records(case, diagnostics, *, status, side, terminal213=False):
    """Preserve reached failures while checking PASS/noncontinuation consistency."""
    import base64
    sides = ('candidate', 'reference') if case.get('kind', 'parity') == 'parity' else ('candidate',)
    if status not in ('PASS', 'FAIL') or side not in sides:
        raise IncompleteEvidence('invalid diagnostic result status or side')
    absent = {('optional-evidence-bashperl-exec-replaces-shell-r1', 'candidate'): 'optional144-perl-after.json', ('optional-evidence-bashpython-sigint-unhandled-r1', 'candidate'): 'optional144-shell-after.json', ('optional-evidence-bashpython-sigint-unhandled-r1', 'reference'): 'optional144-shell-after.json'}.get((case['id'], side))
    names = case.get('diagnostic_files', [])
    if not isinstance(diagnostics, dict) or set(diagnostics) != set(names):
        raise IncompleteEvidence('requested diagnostics are missing')
    remaining = 4 * 1024 ** 2
    for name in names:
        item = diagnostics[name]
        if terminal213 and case.get('id') == 'migration-terminal213-top-three-redraws' and (side == 'candidate') and (status == 'FAIL') and (name == 'top181-writer.json') and isinstance(item, dict) and (item == {'missing': True}):
            continue
        if name == absent and isinstance(item, dict) and (set(item) == {'missing'}) and (item['missing'] is True):
            continue
        if name == absent and status == 'PASS':
            raise IncompleteEvidence('PASS contradicts expected noncontinuation')
        limit = min(1024 ** 2, remaining)
        if not isinstance(item, dict) or set(item) != {'base64', 'captured_bytes', 'truncated'} or item['truncated'] is not False or (type(item['captured_bytes']) is not int) or (not 0 <= item['captured_bytes'] < limit) or (not isinstance(item['base64'], str)):
            raise IncompleteEvidence('diagnostic reached a cap or was not captured')
        try:
            raw = base64.b64decode(item['base64'], validate=True)
        except (ValueError, TypeError) as error:
            raise IncompleteEvidence('invalid diagnostic encoding') from error
        if len(raw) != item['captured_bytes']:
            raise IncompleteEvidence('diagnostic length does not match retained bytes')
        remaining -= len(raw)

def validate_144_runtime_observations(case, diagnostics, identities, manifest_bytes):
    """Bind retained 144 UV observations to authenticated build data only."""
    import base64
    module_id = 'optional-evidence-uv-module-relative-path-after-cd-r1'
    project_id = 'optional-evidence-uv-local-project-operation-r1'
    if case['id'] not in (module_id, project_id):
        return
    if not isinstance(manifest_bytes, bytes) or not isinstance(identities, dict) or identities.get('runtime_manifest_sha256') != optional.sha_bytes(manifest_bytes):
        raise IncompleteEvidence('144 runtime manifest is not the validated build identity')
    try:
        uv = identities['packages']['uv']
        entries = optional.validate_manifest(manifest_bytes, 'runtime')
        package_name = uv['package']
        pkg_entry = entries['runtime/packages/' + package_name]
        helper_entry = entries['runtime/uv/libexec/uv/uv']
        if pkg_entry['sha256'] != uv['package_sha256'] or helper_entry['sha256'] != uv['helper']['sha256'] or helper_entry['size'] != uv['helper']['size'] or (helper_entry['mode'] != uv['helper']['mode']):
            raise IncompleteEvidence('144 package/helper differs from the validated output identities')

        def read_record(name):
            item = diagnostics[name]
            return optional.parse_json(base64.b64decode(item['base64'], validate=True), 1024 ** 2)
        observation = read_record('optional144-uv-observations.json')
        preflight = read_record('optional144-uv-runtime-preflight.json')
        if not isinstance(observation, dict) or not isinstance(preflight, dict):
            raise IncompleteEvidence('144 UV observations are not objects')

        def binding(value):
            if not isinstance(value, dict):
                raise IncompleteEvidence('144 runtime binding is missing')
            for key, path, digest, size in (('runtime_manifest', OPTIONAL_GUEST + '/runtime-manifest.json', optional.sha_bytes(manifest_bytes), len(manifest_bytes)), ('package', '/opt/bashos-optional/packages/' + package_name, uv['package_sha256'], pkg_entry['size']), ('runtime_uv', '/opt/bashos-optional/uv/libexec/uv/uv', uv['helper']['sha256'], helper_entry['size'])):
                item = value.get(key)
                if not isinstance(item, dict) or item.get('path') != path or item.get('sha256') != digest or (type(item.get('size')) is not int) or (item['size'] != size):
                    raise IncompleteEvidence('144 runtime observation identity mismatch: ' + key)
        if case['id'] == module_id:
            if observation.get('scenario') != 'module' or preflight.get('scenario') != 'preflight-module':
                raise IncompleteEvidence('144 module observations identify the wrong scenario')
            for data in (preflight.get('package_binding'), observation.get('package_binding')):
                binding(data)
                if data.get('module_sha256') != uv['module']['sha256'] or data.get('packaged_helper_sha256') != uv['helper']['sha256']:
                    raise IncompleteEvidence('144 module or packaged helper identity mismatch')
            binding(observation.get('runtime_binding_after'))
            fixture = observation.get('fixture_module')
            path = '/tmp/parity-case/optional144-module/usr/lib/bash-os/loadables/uv.so'
            if not isinstance(fixture, dict) or fixture.get('path') != path or fixture.get('sha256') != uv['module']['sha256'] or (fixture.get('sha256_after') != uv['module']['sha256']) or (fixture.get('original_packaged_helper_sha256') != uv['helper']['sha256']) or (not isinstance(observation.get('native_stub'), dict)) or (fixture.get('standin_sha256') != observation['native_stub'].get('sha256')) or (type(fixture.get('device')) is not int) or (fixture['device'] < 0) or (type(fixture.get('inode')) is not int) or (fixture['inode'] <= 0):
                raise IncompleteEvidence('144 copied module identity mismatch')
            run = observation['run']
            snapshots = run['shell_snapshots']
            births = []
            for stage in ('before', 'loaded', 'after'):
                text = snapshots[stage]['stat']
                lines = text.splitlines()
                if len(lines) < 2 or not re.fullmatch('pid=[0-9]+', lines[0]):
                    raise IncompleteEvidence('144 shell birth observation is missing')
                pid = int(lines[0][4:])
                fields = lines[1].rsplit(')', 1)[1].split()
                if int(lines[1].split(' ', 1)[0]) != pid:
                    raise IncompleteEvidence('144 shell PID observation differs')
                births.append((pid, int(fields[19])))
            if len(set(births)) != 1 or births[0][0] <= 0 or births[0][1] <= 0 or (int(run['stub']['fields']['ppid']) != births[0][0]):
                raise IncompleteEvidence('144 shell or helper parent identity changed')
            stub = run['stub']['fields']
            if stub.get('argc') != '1' or stub.get('arg0') != b'module-probe'.hex() or stub.get('cwd') != b'/'.hex() or (stub.get('mark') != 'unset') or (stub.get('local') != 'unset'):
                raise IncompleteEvidence('144 module stand-in arguments or cwd differ')

            def mapped(raw):
                if not isinstance(raw, str) or not raw:
                    raise IncompleteEvidence('144 module maps evidence is missing')
                for line in raw.splitlines():
                    fields = line.split()
                    if len(fields) < 6 or fields[-1] != path or int(fields[4]) != fixture['inode']:
                        continue
                    device = fields[3].split(':')
                    if len(device) == 2 and (int(device[0], 16), int(device[1], 16)) == (os.major(fixture['device']), os.minor(fixture['device'])):
                        return True
                return False
            if not mapped(snapshots['loaded']['maps']) or mapped(snapshots['after']['maps']):
                raise IncompleteEvidence('144 exact module load/unload maps are inconsistent')
            if run.get('absolute_helper_absence') != 'absolute-helper=absent\n' or type(run.get('returncode')) is not int or run['returncode'] != 0 or (bytes.fromhex(run['stdout_hex']) != b'call=42 unload=0\n'):
                raise IncompleteEvidence('144 module call/unload control is incomplete')
        else:
            if observation.get('scenario') != 'project' or preflight.get('scenario') != 'preflight-project':
                raise IncompleteEvidence('144 project observations identify the wrong scenario')
            binding(preflight.get('runtime_binding'))
            binding(observation.get('runtime_binding'))
            binding(observation.get('runtime_binding_after'))
            project = read_record('optional144-project.json')
            binding(project.get('runtime_binding'))
            trees = project['trees']
            runs = observation['runs']
            if not isinstance(trees, dict) or set(trees) != {'reference', 'candidate'} or trees['reference'] != trees['candidate'] or (not trees['reference']) or (not any((name.endswith('pyproject.toml') for name in trees['reference']))):
                raise IncompleteEvidence('144 project trees are missing or unequal')
            a, b = (runs['reference'], runs['candidate'])
            if type(a.get('returncode')) is not int or type(b.get('returncode')) is not int or a['returncode'] != 0 or (b['returncode'] != 0) or (a.get('recorded_builtin_status') != '0\n') or (b.get('recorded_builtin_status') != '0\n') or (a.get('stdout_hex') != b.get('stdout_hex')) or (a.get('stderr_hex') != b.get('stderr_hex')) or any((row.get('stdout_truncated') is not False or row.get('stderr_truncated') is not False for row in (a, b))):
                raise IncompleteEvidence('144 real UV project streams/status are incomplete or unequal')
            for row in (a, b):
                for stream in ('stdout', 'stderr'):
                    data = bytes.fromhex(row[stream + '_hex'])
                    if type(row.get(stream + '_length')) is not int or row[stream + '_length'] != len(data) or len(data) >= 32768:
                        raise IncompleteEvidence('144 real UV stream length or cap is invalid')
            total = 0
            for name, item in trees['reference'].items():
                if not isinstance(name, str) or not isinstance(item, dict):
                    raise IncompleteEvidence('144 project tree entry is invalid')
                if item.get('type') == 'file':
                    content = base64.b64decode(item['base64'], validate=True)
                    if optional.sha_bytes(content) != item.get('sha256'):
                        raise IncompleteEvidence('144 project file hash differs from retained bytes')
                    total += len(content)
                elif item.get('type') != 'dir':
                    raise IncompleteEvidence('144 project tree contains an unsupported entry')
            if len(trees['reference']) > 128 or total > 120000:
                raise IncompleteEvidence('144 project tree exceeded its bound')
    except (KeyError, TypeError, ValueError, IndexError, AttributeError, OverflowError) as error:
        raise IncompleteEvidence('malformed or incomplete 144 runtime observations') from error

def validate_optional_evidence(path, summary_bytes, cases, fixture_sha, candidate_sha, reference_sha, vm_uuid, guest_status, *, output_identities=None, runtime_manifest=None, terminal213=False, owned_pty_receipt_raw=None, owned_pty_run_key=None):
    """Read evidence; 14-control profile requires an exact authorized receipt."""
    import base64
    if len(summary_bytes) >= 8 * 1024 ** 2:
        raise IncompleteEvidence('summary reached its capture cap')
    report = optional.parse_json(summary_bytes, 8 * 1024 ** 2)
    if not isinstance(report, dict) or type(report.get('schema')) is not int or report.get('schema') != 1:
        raise IncompleteEvidence('invalid runtime summary')
    expected_ids = sorted((case['id'] for case in cases))
    selfchecks = OPTIONAL_SELFCHECKS
    if owned_pty_receipt_raw is not None:
        if not terminal213:
            raise IncompleteEvidence('owned PTY receipt outside terminal route')
        binding = {'archive_sha256': optional_sha_path(path, 512 * 1024 ** 2), 'summary_sha256': hashlib.sha256(summary_bytes).hexdigest(), 'fixture_sha256': fixture_sha, 'candidate_sha256': candidate_sha, 'reference_sha256': reference_sha, 'vm_uuid': vm_uuid, 'case_order': [case['id'] for case in cases], 'case_sha256': {case['id']: hashlib.sha256(json.dumps(case, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest() for case in cases}, 'guest_status': guest_status}
        selfchecks, authorized_module_sha256 = owned_pty_receipt_checks(owned_pty_receipt_raw, owned_pty_run_key, binding)
    elif owned_pty_run_key is not None:
        raise IncompleteEvidence('owned PTY run key without receipt')
    if len(expected_ids) != len(set(expected_ids)) or report.get('selected_case_ids') != expected_ids or report.get('groups') != ['selfcheck', 'shell', 'terminal'] or (report.get('fixture_sha256') != {'optional-frozen.json': fixture_sha}) or (report.get('binary_sha256') != candidate_sha) or (report.get('reference_shell_sha256') != reference_sha) or (report.get('vm_uuid') != vm_uuid) or (report.get('root_fixtures_allowed') is not False):
        raise IncompleteEvidence('summary does not bind the selected definitions and VM identities')
    isolation = report.get('isolation')
    if not isinstance(isolation, dict) or type(isolation.get('uid')) is not int or isolation.get('uid') != 0 or (isolation.get('virtualization') not in ('qemu', 'kvm')) or (isolation.get('links') != ['lo']) or (isolation.get('vm_uuid_matches') is not True) or any((not isinstance(isolation.get(key), str) or not re.fullmatch(prefix + ':\\[[0-9]+\\]', isolation[key]) for key, prefix in [('pid_namespace', 'pid'), ('network_namespace', 'net'), ('mount_namespace', 'mnt')])):
        raise IncompleteEvidence('guest evaluator identity/isolation is incomplete')
    records = report.get('cases')
    if not isinstance(records, list) or any((not isinstance(r, dict) or not isinstance(r.get('id'), str) for r in records)):
        raise IncompleteEvidence('invalid result records')
    by_id = {r['id']: r for r in records}
    if len(by_id) != len(records) or set(by_id) != set(expected_ids) | selfchecks:
        raise IncompleteEvidence('missing, duplicate or unexpected result records')
    for case in cases:
        record = by_id[case['id']]
        if record.get('group') != case['group'] or record.get('loadable') != case['loadable'] or record.get('kind') != case.get('kind', 'parity') or (record.get('covers') != case.get('covers', [])):
            raise IncompleteEvidence('selected result does not match its frozen definition')
        if record.get('status') not in ('PASS', 'FAIL'):
            raise IncompleteEvidence('selected case was skipped, errored or not reached: ' + case['id'])
    for name in selfchecks:
        if by_id[name].get('group') != 'selfcheck' or by_id[name].get('kind') != 'selfcheck' or by_id[name].get('status') != 'PASS':
            raise IncompleteEvidence('required selfcheck did not pass: ' + name)
    statuses = ('PASS', 'FAIL', 'ERROR', 'SKIP', 'DEFERRED', 'MIGRATED', 'COLLECTED')
    counts = {status: sum((r.get('status') == status for r in records)) for status in statuses}
    by_group = {group: {status: sum((r.get('status') == status and r.get('group') == group for r in records)) for status in statuses} for group in ['selfcheck', 'shell', 'terminal']}
    kinds = sorted({r.get('kind') for r in records})
    by_kind = {kind: {status: sum((r.get('status') == status and r.get('kind') == kind for r in records)) for status in statuses} for kind in kinds}
    parity_groups = sorted({r['group'] for r in records if r.get('kind') == 'parity'})
    parity = {group: {status: sum((r.get('status') == status and r.get('kind') == 'parity' and (r.get('group') == group) for r in records)) for status in statuses} for group in parity_groups}

    def exact_counts(actual, expected):
        return isinstance(actual, dict) and set(actual) == set(expected) and all((type(actual[key]) is int and actual[key] == value for key, value in expected.items()))

    def exact_matrix(actual, expected):
        return isinstance(actual, dict) and set(actual) == set(expected) and all((exact_counts(actual[key], value) for key, value in expected.items()))
    if not exact_counts(report.get('summary'), counts) or not exact_matrix(report.get('summary_by_group'), by_group) or (not exact_matrix(report.get('summary_by_kind'), by_kind)) or (not exact_matrix(report.get('parity_summary_by_group'), parity)) or (type(guest_status) is not int) or (guest_status != int(bool(counts['FAIL'] or counts['ERROR']))):
        raise IncompleteEvidence('summary totals or evaluator status are inconsistent')
    wanted = {'results/summary.json'} | {'results/selfcheck/' + name[len('selfcheck-'):] + '.json' for name in selfchecks}
    nested = {'classification-ERROR': ('reference', 'candidate'), 'classification-FAIL': ('reference', 'candidate'), 'setup-success': ('candidate',), 'setup-failure': ('candidate',), 'diagnostics': ('reference', 'candidate'), 'diagnostics-setup-failure': ('reference', 'candidate'), 'file-limit-8388608': ('reference', 'candidate'), 'file-limit-75497472': ('reference', 'candidate'), 'syscall-sequence-observer': ('reference', 'candidate')}
    nested_raw = {'results/selfcheck/' + folder + '/' + side + '.json' for folder, sides in nested.items() for side in sides}
    nested_raw.add('results/selfcheck/syscall-sequence-observer/feature-checks.json')
    wanted |= nested_raw
    for case in cases:
        wanted.add('results/' + case['id'] + '/candidate.json')
        if case.get('kind', 'parity') == 'parity':
            wanted.add('results/' + case['id'] + '/reference.json')
    stream, size = optional.open_single(path, 512 * 1024 ** 2)
    if size >= 512 * 1024 ** 2 or size < 1024 or size % 512:
        stream.close()
        raise IncompleteEvidence('evidence archive reached cap or has invalid size')
    found, seen = ({}, set())
    with stream:
        initial_sha = optional.stream_sha(stream)
        metadata = os.fstat(stream.fileno())
        if owned_pty_receipt_raw is not None and initial_sha != binding['archive_sha256']:
            raise IncompleteEvidence('opened archive differs from source-authorized receipt')
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size != size:
            raise IncompleteEvidence('evidence changed before validation')
        offset = 0
        while offset < size:
            stream.seek(offset)
            block = stream.read(512)
            if len(block) != 512:
                raise IncompleteEvidence('truncated evidence header')
            if not block.strip(b'\x00'):
                if size - offset < 1024:
                    raise IncompleteEvidence('evidence trailer is too short')
                while offset < size:
                    stream.seek(offset)
                    chunk = stream.read(min(1024 ** 2, size - offset))
                    if not chunk or chunk.strip(b'\x00'):
                        raise IncompleteEvidence('nonzero or truncated evidence trailer')
                    offset += len(chunk)
                break
            member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
            name = member.name.rstrip('/') if member.isdir() else member.name
            parts = name.split('/')
            if not name or len(name.encode()) > 255 or parts[0] != 'results' or any((not re.fullmatch('[A-Za-z0-9._+-]{1,128}', part) or part in ('.', '..') for part in parts)) or (name in seen) or (member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)) or member.linkname or (member.size < 0) or (member.size >= 64 * 1024 ** 2):
                raise IncompleteEvidence('unsafe, duplicate or oversized evidence member')
            if member.isdir() and member.size:
                raise IncompleteEvidence('nonempty directory header')
            padding = -member.size % 512
            if padding:
                stream.seek(offset + 512 + member.size)
                pad = stream.read(padding)
                if len(pad) != padding or pad.strip(b'\x00'):
                    raise IncompleteEvidence('nonzero or truncated evidence member padding')
            seen.add(name)
            if len(seen) > 20000:
                raise IncompleteEvidence('evidence member count exceeded')
            offset += 512 + (member.size + 511) // 512 * 512
            if offset > size:
                raise IncompleteEvidence('evidence member exceeds archive')
        else:
            raise IncompleteEvidence('missing evidence trailer')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            for member in archive:
                if member.name in wanted:
                    if not member.isfile() or member.name in found:
                        raise IncompleteEvidence('required raw evidence is not a unique file')
                    data = archive.extractfile(member).read(member.size + 1)
                    if len(data) != member.size:
                        raise IncompleteEvidence('truncated required raw evidence')
                    found[member.name] = data
        if owned_pty_receipt_raw is not None:
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode='r:') as archive:
                reviewed = load_reviewed_module('standard_terminal213', authorized_module_sha256)
                reviewed.validate_owned_pty_control(sys.modules[__name__], archive)
        if set(found) != wanted or found['results/summary.json'] != summary_bytes:
            raise IncompleteEvidence('archived summary differs or required raw evidence is missing')
        if owned_pty_receipt_raw is not None:
            reviewed.validate_terminal_observations(sys.modules[__name__], stream.fileno(), report, cases, initial_sha, {'selected_case_ids': [case['id'] for case in cases], 'control_case_ids': []})
        stream.seek(0)
        archive_sha = optional.stream_sha(stream)
        final_metadata = os.fstat(stream.fileno())
        if archive_sha != initial_sha or not stat.S_ISREG(final_metadata.st_mode) or final_metadata.st_nlink != 1 or (final_metadata.st_size != size) or ((final_metadata.st_dev, final_metadata.st_ino, final_metadata.st_mtime_ns) != (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns)):
            raise IncompleteEvidence('evidence archive changed during validation')
    for name in nested_raw:
        if not isinstance(optional.parse_json(found[name], 64 * 1024 ** 2), dict):
            raise IncompleteEvidence('invalid nested selfcheck raw evidence: ' + name)
    for name in selfchecks:
        raw = optional.parse_json(found['results/selfcheck/' + name[len('selfcheck-'):] + '.json'], 8 * 1024 ** 2)
        if raw != {k: v for k, v in by_id[name].items() if k != 'kind'}:
            raise IncompleteEvidence('selfcheck raw record differs from summary: ' + name)
    for case in cases:
        sides = ('candidate', 'reference') if case.get('kind', 'parity') == 'parity' else ('candidate',)
        for side in sides:
            raw = optional.parse_json(found['results/' + case['id'] + '/' + side + '.json'], 64 * 1024 ** 2)
            if not isinstance(raw, dict) or type(raw.get('status')) is not int or (not isinstance(raw.get('tree'), dict)):
                raise IncompleteEvidence('invalid side evidence')
            if owned_pty_receipt_raw is not None:
                if raw.get('harness_error'):
                    raise IncompleteEvidence('owned PTY side has a harness error')
                if raw.get('stray_processes') != [] or raw.get('cleanup_error') is not None:
                    raise IncompleteEvidence('owned PTY side cleanup is incomplete or has strays')
                if 'setup_script' in case:
                    setup = raw.get('setup')
                    if not isinstance(setup, dict) or type(setup.get('status')) is not int or setup['status'] != 0 or ('error' not in setup) or (setup['error'] is not None) or setup.get('harness_error') or setup.get('stray_processes') != [] or setup.get('cleanup_error') is not None:
                        raise IncompleteEvidence('declared owned PTY setup incomplete')
                elif 'setup' in raw:
                    raise IncompleteEvidence('unexpected owned PTY setup record')
            if by_id[case['id']]['status'] == 'PASS' and (raw['status'] != case.get('expected_status', 0) or raw.get('error') is not None or raw.get('harness_error') or (case.get('restore_terminal', True) and raw.get('terminal_restored') is False)):
                raise IncompleteEvidence('PASS contradicts retained side evidence')
            error = raw.get('error')
            if isinstance(error, str) and ('output limit' in error or 'wall-clock limit' in error or 'file-size limit' in error):
                reached_terminal_timeout = terminal213 and case['id'].startswith('migration-terminal213-') and (case['driver'] == 'pty') and (side == 'candidate') and (by_id[case['id']]['status'] == 'FAIL') and error.startswith('PTY wall-clock limit waiting for step ')
                if not reached_terminal_timeout:
                    raise IncompleteEvidence('side hit a capture or time limit')
            if type(raw.get('captured_bytes')) is int and raw['captured_bytes'] >= case.get('output_limit', 8 * 1024 ** 2):
                raise IncompleteEvidence('side reached its byte capture cap')
            if case['driver'] == 'pty':
                try:
                    screen = base64.b64decode(raw['screen_base64'], validate=True)
                except (KeyError, ValueError, TypeError) as error:
                    raise IncompleteEvidence('invalid PTY raw bytes') from error
                if len(screen) >= 2 * 1024 ** 2:
                    raise IncompleteEvidence('PTY reached its byte capture cap')
                if owned_pty_receipt_raw is not None and (by_id[case['id']]['status'] == 'PASS' or side == 'reference'):
                    for step, action in enumerate(case.get('steps', [])):
                        if 'output_lacks' not in action:
                            continue
                        events = [event for event in raw.get('events', []) if event.get('step') == step and event.get('action') == 'output_lacks']
                        if len(events) != 1 or type(events[0].get('offset')) is not int or (not 0 <= events[0]['offset'] <= len(screen)) or re.search(action['output_lacks'].encode(), screen[:events[0]['offset']]):
                            raise IncompleteEvidence('terminal output-lacks observation differs')
            if owned_pty_receipt_raw is not None and (by_id[case['id']]['status'] == 'PASS' or side == 'reference'):
                if case['driver'] == 'plain':
                    for name in ('stdout', 'stderr'):
                        if name in case:
                            try:
                                actual = base64.b64decode(raw[name + '_base64'], validate=True)
                            except (KeyError, TypeError, ValueError) as error:
                                raise IncompleteEvidence('invalid terminal plain stream') from error
                            if not isinstance(case[name], str) or actual != case[name].encode():
                                raise IncompleteEvidence('terminal plain stream differs')
                        if name + '_regex' in case:
                            raise IncompleteEvidence('unreviewed terminal plain stream regex')
                for name, value in case.get('expected_files', {}).items():
                    expected = value['base64'] if isinstance(value, dict) else base64.b64encode(value.encode()).decode()
                    item = raw['tree'].get(name, {})
                    if item.get('kind') != 'file' or item.get('base64') != expected:
                        raise IncompleteEvidence('terminal expected file differs')
            diagnostics = raw.get('diagnostics', {})
            if case.get('diagnostic_files'):
                validate_diagnostic_records(case, diagnostics, status=by_id[case['id']]['status'], side=side, terminal213=terminal213)
                if by_id[case['id']]['status'] == 'PASS':
                    validate_144_runtime_observations(case, diagnostics, output_identities, runtime_manifest)
    return {'summary': counts, 'archive_sha256': archive_sha, 'selfchecks': sorted(selfchecks), 'selected_ids': expected_ids, 'fixture_sha256': fixture_sha}
