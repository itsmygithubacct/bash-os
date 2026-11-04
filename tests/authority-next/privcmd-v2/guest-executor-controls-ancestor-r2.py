#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real module and actual Bash consumers with independent executor fault traces.

Run only in the existing attested disposable evaluator. The test bootstrap,
positive executor source and deliberately broken controls are separately pinned.
The latter are confined to this fixture and must produce rejected verdicts.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import time
sys.dont_write_bytecode = True


def require(ok, reason):
    if not ok: raise RuntimeError(reason)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def checked_receipt(base, path, pin, kind):
    base.protected(path, pin); data = json.loads(path.read_text())
    require(data['schema'] == 1 and data['kind'] == kind, 'receipt kind differs')
    for name, record in data['files'].items():
        require(Path(name).name == name, 'non-local artifact name')
        base.protected(path.parent / name, record['sha256'])
        require((path.parent / name).stat().st_size == record['bytes'], 'artifact length differs')
    return data


def swap_executor(rt, path):
    base = rt.base
    if rt.loaded:
        result = rt.command(['/usr/sbin/rmmod', base.MODULE])
        require(result.returncode == 0 and not Path('/sys/module', base.MODULE).exists(), 'module unload failed')
        rt.loaded = False
    pending = rt.root / 'executor.next'
    rt.install(pending, path.read_bytes(), 0o700)
    pending.replace(rt.root / 'executor')
    argv = ['/usr/sbin/insmod', rt.artifacts / (base.MODULE + '.ko'), 'test_only=1']
    for name in ('accounts', 'groups', 'profiles', 'policy', 'verifier', 'executor'):
        argv += [name + '_path=' + str(rt.root / name), name + '_sha256=' + base.sha(rt.root / name)]
    result = rt.command(argv)
    rt.loaded = result.returncode == 0 and Path('/sys/module', base.MODULE).exists()
    require(rt.loaded, 'pinned observer executor module load failed')
    for _ in range(100):
        if os.path.lexists(base.DEVICE): break
        time.sleep(.01)
    require(os.path.lexists(base.DEVICE), 'qualification device missing')


def observed_case(rt, observer, verb, fault, negative=None):
    base = rt.base
    name = ('negative-' + negative if negative else verb + '-' + fault)
    st = rt.nopass.stat()
    config = {'fault': fault, 'negative': negative, 'uid': base.TARGET, 'gid': base.TARGET,
              'groups': [base.TARGET, base.SHARED], 'target': str(rt.nopass),
              'target_sha256': base.sha(rt.nopass), 'target_identity': [st.st_dev, st.st_ino],
              'executor_sha256': base.sha(rt.root / 'executor')}
    config['network_namespace'] = os.readlink('/proc/self/ns/net')
    result_path = rt.args.output / (name + '-observer.json')
    rt.observer_broker.begin(name, config)
    consumer_result = None
    try:
        command = shlex.quote(str(rt.nopass)) + ' exit-7'
        if verb == 'auth':
            script = 'auth privcmd-v2-exec --qualification -n %d %d -- %s' % (base.TARGET, base.TARGET, command)
        else: script = verb + ' --authority-v2-qualification -n -u pcv2target ' + command
        positive = fault == 'none' and negative is None
        # A missing/broken observer is setup ERROR, not a reached credential
        # verdict. Retain an actual consumer assertion failure, but classify it
        # only after the independent observer has completed its protocol.
        consumer_failure = None
        try:
            consumer_result = rt.bash(name, script, 7 if positive else 126, 1 if positive else 0)
        except AssertionError as error:
            consumer_failure = error
        broker_receipt = rt.observer_broker.finish()
        result = json.loads(result_path.read_text())
        require(result.get('completed') is True and result['status'] != 'ERROR', 'observer incomplete')
        if consumer_failure is not None:
            raise consumer_failure
        rows = [json.loads(line) for line in result_path.with_suffix('.jsonl').read_text().splitlines()]
        # Reclassify the exact retained observations in the coordinator process.
        verdict = observer.verdict(config, rows)
        require(all(result[k] == verdict[k] for k in verdict), 'recorded verdict differs from retained trace')
        if negative:
            base.check(verdict['status'] == 'FAIL', 'deliberately broken executor was accepted')
            if negative == 'continue-after-fault':
                base.check(verdict['selected_fault_count'] == 1 and verdict['guard_denials'] > 0 and
                           any(r.get('syscall') == 'setresgid' and r.get('phase') == 'child-setup' for r in rows),
                           'bad continue control did not reach the forbidden next call')
            elif negative == 'saved-root-id':
                attempts = [r for r in rows if r.get('phase') == 'target-exec-attempt']
                base.check(any(r.get('negative_control_real_saved_root_call') for r in rows) and len(attempts) == 1 and
                           attempts[0]['identity']['Uid'] == [base.TARGET, base.TARGET, 0, base.TARGET] and
                           attempts[0]['reply_origin'] == 'containment-guard',
                           'bad saved-ID control did not expose a real retained saved root ID')
            else: raise RuntimeError('unknown deliberate negative')
        else: base.check(verdict['status'] == 'PASS', 'executor fault verdict rejected: ' + '; '.join(verdict['problems']))
        rt.audit_drain()
        return {'consumer': consumer_result, 'observer': verdict, 'broker': broker_receipt,
                'expected_observer_rejection': bool(negative), 'report_sha256': base.sha(result_path),
                'trace_sha256': base.sha(result_path.with_suffix('.jsonl'))}
    finally:
        rt.observer_broker.cancel()


def main():
    parser = argparse.ArgumentParser()
    for name in ('receipt', 'observer-receipt', 'bash', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('receipt-sha256', 'observer-receipt-sha256', 'bash-sha256', 'expected-uuid'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(args.receipt.is_absolute() and args.observer_receipt.is_absolute(), 'absolute receipts required')
    # Before importing a fixture implementation, verify its bytes through the
    # independently supplied immutable receipt pins.
    import hashlib, stat
    def initial(path, pin):
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022 and
                hashlib.sha256(path.read_bytes()).hexdigest() == pin, 'unprotected initial fixture input')
    initial(args.receipt, args.receipt_sha256)
    raw = json.loads(args.receipt.read_text())
    initial(args.receipt.parent / 'guest-privcmd-controls.py', raw['files']['guest-privcmd-controls.py']['sha256'])
    base = load('privcmd_base', args.receipt.parent / 'guest-privcmd-controls.py')
    receipt = checked_receipt(base, args.receipt, args.receipt_sha256, 'authority-privcmd-v2-build-only')
    addon = checked_receipt(base, args.observer_receipt, args.observer_receipt_sha256, 'authority-executor-observer-build-only')
    require(addon['executor_source_sha256'] == '25719311d2c9e8dff0f3bfece2387393b28596e3888a92eb2cb1ebb2233d8cf5',
            'observer built for a different executor')
    require(addon['base_receipt_sha256'] == args.receipt_sha256 and
            addon['admitted_source_manifest_sha256'] == receipt['admitted_source_manifest_sha256'] and
            addon['executor_source_sha256'] == receipt['executor_source_sha256'] and
            addon['executor_protocol_sha256'] == receipt['executor_protocol_sha256'] and
            addon['input_readback_unchanged'] is True and receipt['input_readback_unchanged'] is True,
            'fresh base/observer source and build receipt chain differs')
    # Keep the original receipt and its driver intact; bind this additive driver
    # through the root launcher registry and the exact new build receipt chain.
    client_path = Path('/opt/bashos-parity/harness/executor_observer_client_r2.py')
    initial(client_path, '99a8ad4bb8a4b8dd325acbe2b8dc4a8c4380f2babb583f5da17e557700bc684a')
    client_module = load('ancestor_observer_client', client_path)
    registry = client_module.c.decode(client_module.t.raw(
        Path(client_module.c.directory(args.expected_uuid)) / 'registry.json', 8192, True))
    require(registry['token'] == args.expected_uuid and
            base.sha(__file__) == registry['files'][client_module.c.DRIVER], 'additive guest controls source differs')
    base.guard(args.expected_uuid, receipt['kernel_release']); base.protected(args.bash, args.bash_sha256)
    require(args.bash.is_absolute() and args.output.is_absolute() and args.output.resolve().is_relative_to(base.HOME) and
            not args.output.exists(), 'fresh private output required')
    observer = load('executor_observer', args.observer_receipt.parent / 'executor-observer.py')
    args.output.mkdir(mode=0o700)
    rt = base.Runtime(args, receipt); rt.base = base; rt.observer_broker = None
    rt.report.update(scope='actual auth/doas/sudo native credential-fault observations',
                     observer_receipt_sha256=args.observer_receipt_sha256,
                     blocking_gaps=['safeedit', 'interactive replacement/session requirements',
                                    'complete consumer obligation matrix and runtime qualification'])
    before = rt.command(['/usr/bin/dmesg', '--raw']); require(before.returncode == 0, 'kernel log unavailable')
    (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        rt.setup()
        rt.observer_broker = client_module.Client(args.expected_uuid)
        swap_executor(rt, args.observer_receipt.parent / 'executor-observed')
        for verb in ('auth', 'doas', 'sudo'):
            for fault in observer.FAULTS:
                rt.note(verb + '-' + fault, lambda v=verb, f=fault: observed_case(rt, observer, v, f),
                        'actual-consumer-real-kernel-credentials-with-one-selected-fault' if fault != 'none' else
                        'actual-consumer-real-kernel-credentials')
        for negative, image, fault in [('continue-after-fault', 'executor-bad-continue', 'setgroups'),
                                       ('saved-root-id', 'executor-bad-saved', 'none')]:
            swap_executor(rt, args.observer_receipt.parent / image)
            rt.note('negative-' + negative,
                    lambda n=negative, f=fault: observed_case(rt, observer, 'sudo', f, n),
                    'deliberate-bad-executor-verdict-rejection')
        require(len(rt.cases) == 29 and all(r['status'] == 'PASS' for r in rt.cases), 'observer matrix incomplete')
        rt.report.update(status='PASS', all_nine_topics_qualified=False, production_features_enabled=False)
    except AssertionError as error: rt.report.update(status='FAIL', reason=str(error))
    except Exception as error: rt.report.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error))
    finally:
        # Preserve every reached failure even if shutdown subsequently errors.
        rt.report['status_before_broker_cleanup'] = rt.report['status']
        rt.report['reached_failure_ids'] = [row['id'] for row in rt.cases if row['status'] == 'FAIL']
        try:
            require(rt.observer_broker is not None, 'broker client was not admitted')
            rt.report['ancestor_broker_cleanup'] = rt.observer_broker.close()
        except Exception as error: rt.report.update(status='ERROR', broker_cleanup_error=repr(error))
        try:
            rt.cleanup(); after = rt.command(['/usr/bin/dmesg', '--raw'])
            require(after.returncode == 0 and after.stdout.startswith(before.stdout), 'kernel log lost/wrapped')
            delta = after.stdout[len(before.stdout):]
            (args.output / 'dmesg-after.txt').write_bytes(after.stdout); (args.output / 'dmesg-delta.txt').write_bytes(delta)
            require(not any(word in delta.lower() for word in (b'warning:', b'bug:', b'kasan:', b'kcsan:', b'ubsan:',
                b'held lock', b'oops:', b'possible recursive locking', b'inconsistent lock state',
                b'general protection fault', b'info: task ')), 'kernel warning/fault evidence')
        except Exception as error: rt.report.update(status='ERROR', cleanup_or_kernel_error=repr(error))
        (args.output / 'commands.json').write_text(json.dumps(rt.commands, indent=2) + '\n')
        (args.output / 'report.json').write_text(json.dumps(rt.report, indent=2) + '\n')
    print(json.dumps({'status': rt.report['status'], 'report': str(args.output / 'report.json')}))
    return 0 if rt.report['status'] == 'PASS' else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error: print('executor observer preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
