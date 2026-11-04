#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Index the exact independently reviewed native /dev/kmsg receipt pair.

Data only: no subprocess, device, runtime-helper import or archive extraction.
This is an immutable receipt adapter, not an alternative behavioral evaluator.
The pinned strict review and every transitive input must still match. New runs,
including failures, require a new review; arbitrary summaries cannot earn credit.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

FORMAT = 'primary-qualified-dmesg-native-r1'
ORDINARY_FORMAT = 'primary-qualified-dmesg-ordinary-r2'
ORDINARY_SCOPE = 'ordinary-dmesg-live-fixture-hook-separate'
ORDINARY = {'mig-w6-dmesg-since-until-root': {'batch': 'limits-companions', 'definition_sha256': '2de3da5bb43d1e17f52c72577484be96d3851a2a407e83ce7d46aa9c90fd0448', 'scope': 'ordinary-live-devkmsg', 'suite': 'mig-w6-dmesg.json'}, 'migration-dmesg-live-ring-root-014-r2': {'batch': 'dmesg-corrected', 'definition_sha256': 'f3cf82bacff6538e2a01254b5f257cee0564828e4e570cff0248afbd1c019726', 'scope': 'ordinary-live-devkmsg', 'suite': 'migration-dmesg-live-hook-014-r2.json'}, 'qualification-014-dmesg': {'batch': 'qualification', 'definition_sha256': 'fcd6e6f7acca297f7367a12f3b6fda228e76701a16cd66af29a1106960384fea', 'scope': 'regular-file-fixture', 'suite': 'ordinary-qualification-limits-014.json'}, 'qualification-014-dmesg-decoded-records-r3': {'batch': 'completion', 'definition_sha256': '5719e44345485bcdc73e379da7a9c2498be361c4834635ec9c00e2c09abdf19d', 'scope': 'regular-file-fixture', 'suite': 'ordinary-dmesg-completion-014-r3.json'}, 'qualification-014-dmesg-facility-level-filters-r3': {'batch': 'completion', 'definition_sha256': 'b897495087fc60a6fbf0bfa08e17afa53bb8a01d097e53dc1fe93fbfc34c90a1', 'scope': 'regular-file-fixture', 'suite': 'ordinary-dmesg-completion-014-r3.json'}, 'qualification-014-dmesg-hook-r2': {'batch': 'dmesg-corrected', 'definition_sha256': '49eadf6bcb3f119a49d4f49dad960f96726255d315854dbd685e160bd592072f', 'scope': 'candidate-only-hook', 'suite': 'migration-dmesg-live-hook-014-r2.json'}, 'qualification-014-dmesg-raw-priority': {'batch': 'dmesg-corrected', 'definition_sha256': '1112889301ee7cc466c808e58a09398a3ed72903bb41da10d97e1de932bc15a3', 'scope': 'regular-file-fixture', 'suite': 'ordinary-dmesg-raw-014.json'}, 'qualification-014-dmesg-raw-priority-prefix-r3': {'batch': 'completion', 'definition_sha256': '14ecf5273bb7374e7b336baef879571af550f8bef64602e934f22a1aef7aaf69', 'scope': 'regular-file-fixture', 'suite': 'ordinary-dmesg-completion-014-r3.json'}, 'qualification-014-dmesg-split-read-boundary-r3': {'batch': 'completion', 'definition_sha256': '0c8a4d231a0408f987369a7bf4c89c1f59a84dc2a3facb89ea583e6ecb14279d', 'scope': 'regular-file-fixture', 'suite': 'ordinary-dmesg-completion-014-r3.json'}, 'qualification-014-dmesg-time-filter-boundaries-r3': {'batch': 'completion', 'definition_sha256': '97d1588d9220a5afa649d58fdcbf1325f6cc0336ec1c625e1a4c40ed2c0fe5c8', 'scope': 'regular-file-fixture', 'suite': 'ordinary-dmesg-completion-014-r3.json'}, 'qualification-014-dmesg-live-format-r17-r1': {'batch': 'completion', 'definition_sha256': 'db6343e78cdc12b79ce5d815a49816e1ef119dd3d768eb2a081a52415c3e1023', 'scope': 'ordinary-live-devkmsg', 'suite': 'ordinary-dmesg-live-format-r17-r1.json'}}
CASE_ID = 'qualification-014-dmesg-native-large-records-r17-r1'
SCOPE = 'native-devkmsg-bounded-ascii-8191-8192-8193'
CASE_SHA = 'a8f5686ea30e8f59d366279bed158b2cb3624bdb909ee8e73b2145d25ef9b715'
INVENTORY_SHA = '31bb4641c6813ec97c7ab6b90700422025d81c312f0b5baa455100bad2544a51'
REPORT_SHA = 'da7bc91f12a6ae6df3fc49d108f5da36c8c1951f0dab3b9cde6b1e5ac4bb19b3'
PLAN_SHA = 'b8ccd54624dc8139db85a518ad9df782a9ffbba3844aaf098614320b1bfd4db7'
READER_SHA = 'bd134704f24c07dddf17d92f95ef3889932b330bb8118ef4fd06bfc3327813e7'
DMESG_SHA = 'f77aef972a044b0ee4c33de48c06ff9a98e8626ff2a92649ae44ac52355a8c66'
VERSIONS_SHA = '47d54f053002d4de072e51fb04d02f2d2644a9c998b64742ebbc44320ca5b0f7'
CORES = {
    'static': '69ac1d064fa538a1d73f4936c700dc095a8962eb78bb77323f2a412aa7c0946c',
    'dynamic': '0473e17de70cc467bd96210910b1f979cf05e3889dabaee8247d1c6c9e9b77ef',
}
OLD = {
    'static': 'b5c796892080d3544358278604e124b3fe625dc9c4c6bd6a732350c0e48a6b4d',
    'dynamic': '7fb0602c075658efbc642a07ddcb8c61cb1ca402915a0e48d7958161d69c3390',
}
SIZES = ('8191', '8192', '8193')
ATTEMPT = 'native-r17-r1'
LIMITATIONS = [
    'Native execution of both final Bash 5.3.20 binaries in a disposable guest with the separate large-record kernel profile.',
    'Only bounded ASCII /dev/kmsg records of exactly 8191, 8192 and 8193 bytes are registered here.',
    'The independent util-linux 2.41.5 reader uses a 16385-byte array and a 16384-byte read; the stock reader is not the large-record oracle.',
    'Regular-file decoding, synthetic decoder checks, ordinary live formatting and filters have separate registrations.',
    'This index adds no behavioral run; the original mixed live/hook FAILs remain historical.',
]


def archive_storage(path):
    """True for a path under an archive-only root named in BASH_OS_ARCHIVE_PATHS."""
    roots = [Path(entry).resolve() for entry in
             os.environ.get('BASH_OS_ARCHIVE_PATHS', '').split(':') if entry]
    return any(path == root or root in path.parents for root in roots)


def require(condition, message):
    if not condition:
        raise ValueError('dmesg native evidence: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    require(len(data) <= 32 * 1024 * 1024, 'oversized JSON')
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('invalid JSON constant: ' + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def file(path, retain=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'canonical absolute file required')
    require(not archive_storage(path), 'archive-only storage is not an evidence work root')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'regular file required: ' + path.name)
        require(not retain or before.st_size <= 32 * 1024 * 1024, 'oversized retained input')
        data = stream.read() if retain else None
        value = sha(data) if retain else hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, f) == getattr(after, f) for f in fields), 'input changed during read')
    return value, before.st_size, data


def selection(spec, expected_binary, expected_build):
    require(expected_build in CORES and expected_binary == CORES[expected_build], 'selected release binary')
    require(spec.get('evidence_format') == FORMAT and spec.get('artifact_scope') == SCOPE and
            spec.get('groups') == ['shell'] and spec.get('ids') == [CASE_ID] and
            not spec.get('exclude_ids'), 'explicit native-only selection required')


def ordinary_selection(spec, expected_binary, expected_build):
    require(expected_build in CORES and expected_binary == CORES[expected_build], 'selected release binary')
    require(spec.get('evidence_format') == ORDINARY_FORMAT and spec.get('artifact_scope') == ORDINARY_SCOPE and
            spec.get('groups') == ['shell'] and isinstance(spec.get('ids'), list) and
            len(spec['ids']) == len(ORDINARY) and set(spec['ids']) == set(ORDINARY) and
            not spec.get('exclude_ids'), 'exact ordinary selection; no synthetic/native substitution')


def validate_review(report):
    """Defensive scope checks in addition to the immutable reviewed byte pins."""
    require(report['schema'] == 'dmesg-evidence-review-r2' and
            report['topic'] == 'dmesg/live-ring-buffer' and report['release_target'] == '0.1.4' and
            report['status'] == 'PASS' and report['release_eligible'] is True and
            report['errors'] == [] and report['candidates'] == CORES and
            report['registration_sha256'] == PLAN_SHA, 'accepted review identity/status')
    require(report['build']['status'] == 'PASS' and report['build']['errors'] == [] and
            report['build']['production_dmesg_sha256'] == DMESG_SHA, 'release build binding')
    require(report['selected_native_attempt'] == ATTEMPT and
            set(report['native_attempts']) == {ATTEMPT}, 'native attempt missing/replaced')
    native = report['native_attempts'][ATTEMPT]
    require(native['status'] == 'PASS' and native['errors'] == [] and
            native['reached_failures'] == native['reported_candidate_failures'] ==
            native['boundary_mismatch_claims'] == [], 'native failures or incomplete observer')
    require(native['lifecycle']['status'] == 'PASS' and native['lifecycle']['errors'] == [],
            'native lifecycle incomplete')
    require(set(native['targets']) == set(SIZES), 'exact native record sizes required')
    for size in SIZES:
        row = native['targets'][size]
        require(row['status'] == 'PASS' and row['errors'] == row['reached_failures'] == [] and
                row['by_build'] == {v: 'PASS' for v in CORES} and
                row['control'] == {'one_byte_read_errno': 22, 'next_errno': 11,
                                   'next_record_observed': False}, 'native observation/control: ' + size)
    require(len(report['atoms']) == 23 and len({a['id'] for a in report['atoms']}) == 23 and
            all(a['by_build'][v]['status'] == 'PASS' for a in report['atoms'] for v in CORES),
            'complete reviewed obligation set')
    history = report['historical_retained']
    require(set(history) == {'mixed-' + v + '-r1' for v in CORES}, 'historical failures dropped')
    for variant in CORES:
        old = history['mixed-' + variant + '-r1']
        require(old['status'] == 'HISTORICAL_FAIL' and old['retained'] is True and
                old['candidate_sha256'] == OLD[variant] and old['differences'] and
                old['replacement_pair_qualified'] is True and
                old['superseded_by'] == ['dmesg-corrected-' + variant + '-r17'] and old['reason'],
                'historical failure/supersession: ' + variant)
    return native


def inspect(spec, repo):
    value, _, data = file(spec['inventory_path'], retain=True)
    require(value == INVENTORY_SHA, 'inventory is not the exact reviewed inventory')
    inventory = decode(data)
    require(inventory['schema'] == 'dmesg-native-evidence-inventory-r1' and
            set(inventory['roots']) == set(spec['roots']) ==
            {'review', 'release', 'historical', 'native', 'completion'}, 'inventory roots')
    roots = {name: Path(path) for name, path in spec['roots'].items()}
    for root in roots.values():
        require(root.is_absolute() and root.resolve() == root and root.is_dir() and
                not archive_storage(root), 'canonical active-storage root')
    verified = {}
    for group, records in inventory['roots'].items():
        for name, pin in records.items():
            rel = PurePosixPath(name)
            require(name == str(rel) and not rel.is_absolute() and '..' not in rel.parts,
                    'unsafe inventory member')
            actual, size, _ = file(roots[group] / name)
            require(actual == pin['sha256'] and size == pin['bytes'], 'changed raw input: ' + group + '/' + name)
            verified[group + '/' + name] = actual
    def read(group, name):
        actual, _, data = file(roots[group] / name, retain=True)
        require(actual == verified[group + '/' + name], 'input changed after inventory check')
        return decode(data)
    require(verified['review/qualification.json'] == REPORT_SHA and
            verified['review/REGISTRATION.json'] == PLAN_SHA and
            verified['review/read-dmesg-evidence-r17-r1.py'] == READER_SHA,
            'strict reader/review/registration pins')
    report = read('review', 'qualification.json')
    native = validate_review(report)
    sources = read('release', 'source-manifest.json')
    for name, expected in (('loadables/dmesg.c', DMESG_SHA), ('config/versions.sh', VERSIONS_SHA)):
        require(sources[name] == file(repo / name)[0] == expected, 'current release source changed: ' + name)
    manifest = read('native', 'kernel/printk-build-manifest.json')
    metadata = {
        'scope': SCOPE, 'inventory_sha256': INVENTORY_SHA, 'review_sha256': REPORT_SHA,
        'registration_sha256': PLAN_SHA, 'reviewed_input_files': len(verified),
        'kernel_release': manifest['kernel_release'], 'kernel_image_sha256': manifest['kernel_image_sha256'],
        'source_deb_sha256': manifest['source_deb_sha256'], 'config_sha256': manifest['config_sha256'],
        'native_attempt': ATTEMPT, 'targets': native['targets'], 'lifecycle': native['lifecycle'],
        'historical_retained': report['historical_retained'],
        'limitations': LIMITATIONS, 'host_candidate_execution': False,
    }
    return metadata, report


def load_qualified_dmesg_native(spec, expected_binary, expected_build, repo=None):
    selection(spec, expected_binary, expected_build)
    require(file(spec['core_binary_path'])[0] == expected_binary, 'configured core hash')
    repo = Path(repo).resolve() if repo is not None else Path(__file__).resolve().parents[2]
    metadata, _ = inspect(spec, repo)
    path = repo / 'tests/parity-vm/evidence-suites/migration-dmesg-native-r17-r1.json'
    definition = decode(file(path, retain=True)[2])['cases'][0]
    require(sha(json.dumps(definition, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()) ==
            CASE_SHA and definition['id'] == CASE_ID and definition['artifact_scope'] == SCOPE,
            'native definition/scope changed')
    row = {'group': 'shell', 'id': CASE_ID, 'status': 'PASS', 'artifact_scope': SCOPE,
           'native_binary_executed': True, 'record_bytes': [int(n) for n in SIZES],
           'candidate_observations': 9, 'reference_observations': 9,
           'counting': 'index into existing native receipts; no additional behavior execution'}
    metadata.update(name=spec['name'], groups=['shell'], selected_records=1,
                    evidence_format=FORMAT, candidate_sha256=expected_binary,
                    native_binary_executed=True)
    return [{'record': row, 'definition': definition, 'sources': {}, 'run': spec['name']}], metadata


def load_qualified_dmesg_ordinary(spec, expected_binary, expected_build, repo=None):
    """Index exact prior ordinary receipts without pretending a missing payload exists.

    The strict review independently bound the raw archived process results,
    suite/helper source pins, release build and VM lifecycle. This distinct
    adapter accepts only those fixed reviewed bytes; the generic reader is
    unchanged and still requires its payload archive.
    """
    ordinary_selection(spec, expected_binary, expected_build)
    require(file(spec['core_binary_path'])[0] == expected_binary, 'configured core hash')
    repo = Path(repo).resolve() if repo is not None else Path(__file__).resolve().parents[2]
    metadata, report = inspect(spec, repo)
    selected = []
    for cid, binding in ORDINARY.items():
        suite = decode(file(repo / 'tests/parity-vm/suites' / binding['suite'], retain=True)[2])
        definitions = [c for c in suite['cases'] if c['id'] == cid]
        require(len(definitions) == 1 and sha(json.dumps(definitions[0], sort_keys=True,
                separators=(',', ':'), ensure_ascii=True).encode()) == binding['definition_sha256'],
                'ordinary definition changed: ' + cid)
        if binding['batch'] == 'completion':
            batch = report['completion_ports'][expected_build]
        else:
            batch = report['ordinary_batches'][binding['batch'] + '-' + expected_build + '-r17']
        require(batch['cases'][cid]['status'] == 'PASS' and batch['cases'][cid]['errors'] == [],
                'ordinary raw result incomplete: ' + cid)
        row = {'group': 'shell', 'id': cid, 'status': 'PASS', 'artifact_scope': binding['scope'],
               'native_large_record_execution': False,
               'counting': 'index into existing ordinary receipts; no additional behavior execution'}
        selected.append({'record': row, 'definition': definitions[0], 'sources': {}, 'run': spec['name']})
    metadata.update(name=spec['name'], groups=['shell'], selected_records=len(selected),
                    scope=ORDINARY_SCOPE, evidence_format=ORDINARY_FORMAT,
                    candidate_sha256=expected_binary, native_large_record_execution=False)
    return selected, metadata
