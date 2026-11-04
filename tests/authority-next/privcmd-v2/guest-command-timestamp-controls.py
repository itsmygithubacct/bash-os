#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Command and timestamp controls; execute only in an attested disposable guest.

Real policy, native verifier, timestamp store, audit and executor throughout.
The separately identified reset-error cases use a load-time denial-only switch.
This file neither enables the production endpoint nor qualifies shell replacement.
"""
import argparse
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shlex
import signal
import stat
import struct
import sys
import time
import traceback

sys.dont_write_bytecode = True


def require(value, reason):
    if not value: raise RuntimeError(reason)


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protected(path, pin):
    st = Path(path).lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022 and sha(path) == pin,
            'unprotected or mismatched input: ' + str(path))


def reload_policy(rt, *, timeout=1, reset_error=False):
    base = rt.base
    if rt.loaded:
        result = rt.command(['/usr/sbin/rmmod', base.MODULE])
        require(result.returncode == 0, 'owned module unload failed')
        rt.loaded = False
    # Only this caller's command rules are NOPASSWD. The target-user rule is
    # needed to test caller isolation with two real standard-PHC accounts.
    lines = ['Defaults timestamp_timeout=%d' % timeout,
             'Defaults env_keep=KEEP_ME',
             'pcv2caller ALL = (pcv2target) NOPASSWD: %s' % rt.nopass,
             'pcv2caller ALL = (pcv2target) %s' % rt.password,
             'pcv2caller ALL = (root) %s' % rt.password,
             'pcv2caller ALL = (pcv2target:pcv2shared) %s' % rt.password,
             'pcv2target ALL = (pcv2target) %s' % rt.password]
    (rt.root / 'policy').write_text('\n'.join(lines) + '\n')
    argv = ['/usr/sbin/insmod', rt.artifacts / (base.MODULE + '.ko'),
            'test_only=1', 'test_reset_fail=' + str(int(reset_error))]
    for name in ('accounts', 'groups', 'profiles', 'policy', 'verifier', 'executor'):
        argv += [name + '_path=' + str(rt.root / name), name + '_sha256=' + sha(rt.root / name)]
    result = rt.command(argv)
    rt.loaded = result.returncode == 0 and Path('/sys/module', base.MODULE).exists()
    require(rt.loaded, 'command/timestamp module load failed')
    require(Path('/sys/module', base.MODULE, 'parameters/test_reset_fail').read_text().strip() ==
            ('Y' if reset_error else 'N'), 'reset-only fault selection differs')
    for _ in range(100):
        if os.path.lexists(base.DEVICE): break
        time.sleep(.01)
    st = Path(base.DEVICE).lstat()
    require(stat.S_ISCHR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o666,
            'private qualification node differs')
    pins = {name: sha(rt.root / name) for name in ('accounts', 'groups', 'profiles', 'policy', 'verifier', 'executor')}
    index = sum(row['argv'][0] == '/usr/sbin/insmod' for row in rt.commands)
    (rt.args.output / ('module-%02d.json' % index)).write_text(json.dumps(
        {'pins': pins, 'policy_hex': (rt.root / 'policy').read_bytes().hex(),
         'test_reset_fail': reset_error, 'timestamp_timeout_minutes': timeout}, indent=2) + '\n')
    return pins


def audit(rt, name):
    rows = rt.audit_drain()
    (rt.args.output / (name + '-audit.bin')).write_bytes(b''.join(rows))
    return rows


def outcome(row): return struct.unpack_from('<I', row, 64)[0]
def reason(row): return struct.unpack_from('<I', row, 248)[0]


def actual_ioctl(function, *arguments):
    # Setup/proc/transport failures stay ERROR. An unexpected errno from a
    # reached, well-formed actual authority operation is a contract FAIL.
    try: return function(*arguments)
    except OSError as error: raise AssertionError('actual authority operation returned errno %s' % error.errno) from error


def bash_case(rt, name, script, expected, targets, *, password=None, audit_rule=None):
    # Each case gets a complete HMAC-checked log, without previous case rows.
    previous = rt.audit_drain()
    if previous: (rt.args.output / (name + '-unassigned-audit.bin')).write_bytes(b''.join(previous))
    require(not previous, 'unassigned previous audit records')
    details = rt.bash(name, script, expected, targets, password)
    rows = audit(rt, name)
    rt.base.check(sum(outcome(row) == 5 for row in rows) == targets and
                  sum(outcome(row) == 6 for row in rows) == targets,
                  'independent audit execution count differs from observed target count')
    if audit_rule: audit_rule(rows)
    details.update(audit_records=len(rows), audit_outcomes=[outcome(row) for row in rows])
    return details


def consumer_matrix(rt):
    base = rt.base; q = shlex.quote
    denied = rt.root / 'target-not-in-policy'
    rt.install(denied, (rt.artifacts / 'privcmd-target').read_bytes(), 0o755)
    for verb in ('doas', 'sudo'):
        reset = '%s --authority-v2-qualification %s' % (verb, '-L' if verb == 'doas' else '-k')
        command = verb + ' --authority-v2-qualification -u pcv2target '
        cases = [
            ('policy-denied', command + '-n ' + q(str(denied)), 1, 0, None, 1),
            ('noninteractive-denied', reset + ' || exit 94; ' + command + '-n ' + q(str(rt.password)), 1, 0, None, 2),
            ('verification-success', reset + ' || exit 94; ' + command + q(str(rt.password)) + ' exit-9', 9, 1, base.PASSWORD, 4),
            ('verification-failure', reset + ' || exit 94; ' + command + q(str(rt.password)), 1, 0, b'wrong-command-password', 3)]
        for suffix, script, status, count, password, required_outcome in cases:
            name = verb + '-' + suffix
            def one(n=name, s=script, e=status, c=count, p=password, wanted=required_outcome):
                def check_rows(rows):
                    base.check(any(outcome(row) == wanted for row in rows), 'required policy/verifier audit event missing')
                    if wanted == 2:
                        base.check(any(outcome(row) == 2 and reason(row) == 3 for row in rows),
                                   'noninteractive denial reason missing')
                return bash_case(rt, n, s, e, c, password=p, audit_rule=check_rows)
            rt.note(name, one, 'actual-consumer')

    prefix = 'sudo --authority-v2-qualification '
    command = prefix + '-u pcv2target ' + q(str(rt.password))
    validate = prefix + '-u pcv2target -v'
    def validation_rows(rows):
        values = [outcome(row) for row in rows]
        base.check(values.count(7) == values.count(8) == 1 and values.index(7) < values.index(8),
                   'reset/validation order or count differs')
        base.check(values.index(8) < values.index(5), 'command began before validation completed')
        base.check(any(outcome(row) == 4 and struct.unpack_from('<I', row, 92)[0] == 1 for row in rows),
                   'later command did not independently report a cache hit')
    script = (prefix + '-k || exit 94; ' + validate + ' || exit 95; ' +
              prefix + '-n -u pcv2target ' + q(str(rt.password)) + ' exit-7')
    rt.note('sudo-validate-then-cached-command', lambda: bash_case(rt, 'sudo-validate-then-cached-command',
        script, 7, 1, password=base.PASSWORD, audit_rule=validation_rows), 'actual-consumer')

    for suffix, flag in (('k-command-resets-first', 'command'), ('k-clears-cache', '-k'), ('K-clears-cache', '-K')):
        name = 'sudo-' + suffix
        second = (prefix + '-k -n -u pcv2target ' + q(str(rt.password))) if flag == 'command' else (
            prefix + flag + ' || exit 95; ' + prefix + '-n -u pcv2target ' + q(str(rt.password)))
        script = (prefix + '-k || exit 94; ' + command + ' exit-7; first=$?; ' + second +
                  '; second=$?; [[ $first == 7 && $second == 1 ]]')
        def reset_order(rows):
            values = [outcome(row) for row in rows]
            resets = [i for i, value in enumerate(values) if value == 7]
            base.check(len(resets) == 2 and values.count(5) == 1 and values.count(6) == 1 and
                       values.index(6) < resets[1] < len(values) - 1 and
                       values[resets[1] + 1:] == [2, 12] and reason(rows[resets[1] + 1]) == 3,
                       'cached-command reset ordering differs')
        rt.note(name, lambda n=name, s=script: bash_case(rt, n, s, 0, 1,
                password=base.PASSWORD, audit_rule=reset_order), 'actual-consumer')

    for suffix, password, noninteractive in (('validate-noninteractive-denied', None, True),
                                             ('validate-wrong-password', b'wrong-validation-password', False)):
        name = 'sudo-' + suffix
        script = prefix + '-k || exit 94; ' + validate + (' -n' if noninteractive else '')
        def no_validation(rows):
            base.check(all(outcome(row) != 8 for row in rows), 'denied validation returned a validated event')
        rt.note(name, lambda n=name, s=script, p=password: bash_case(rt, n, s, 1, 0,
                password=p, audit_rule=no_validation), 'actual-consumer')

    name = 'sudo-reset-precedes-target-lookup'
    require(not any(line.split(b':', 1)[0] == b'pcv2-absent-user' for line in Path('/etc/passwd').read_bytes().splitlines()),
            'absent target-name prerequisite differs')
    script = prefix + '-k -n -u pcv2-absent-user ' + q(str(rt.nopass))
    rt.note(name, lambda: bash_case(rt, name, script, 1, 0, audit_rule=lambda rows:
        base.check([outcome(row) for row in rows] == [7], 'target lookup occurred without successful reset')),
        'actual-consumer')


def validation_prepare(base, fd, *, uid, user, target='pcv2target', target_uid=None, target_gid=None, explicit=False):
    """Independent fixed-size wire encoder; no candidate function supplies expectations."""
    target_uid = base.TARGET if target_uid is None else target_uid
    target_gid = target_uid if target_gid is None else target_gid
    value = base.Prepare(); value.size = 888; value.version = 2
    row = value.request; row.size = 832; row.mode = 4; row.flags = 2 if explicit else 0
    row.caller_uid = row.caller_gid = uid; row.target_uid = target_uid; row.target_gid = target_gid
    row.caller_user = user.encode(); row.target_user = target.encode(); row.cwd = os.fsencode(os.getcwd())
    frame = b'bashos-privcmd-v' + struct.pack('<11I', 4, row.flags, 0, uid, uid, target_uid, target_gid, 0, 0, 0, 0)
    for field in (row.caller_user, row.target_user, row.cwd): frame += struct.pack('<I', len(field)) + field
    row.request_digest[:] = hashlib.sha256(frame).digest()
    result = actual_ioctl(base.ioctl_struct, fd, base.PREPARE, value)
    base.check(bytes(result.request.request_digest) == bytes(row.request_digest), 'independent validation framing differs')
    return result


class Peer:
    """Owned, stable children with real distinct sessions and credentials."""
    def __init__(self, rt, name, uid):
        self.rt, self.name, self.uid = rt, name, uid
        self.events = []; self.raw = bytearray(); self.buffer = bytearray(); self.closed = False
        incoming, send = os.pipe(); receive, outgoing = os.pipe()
        self.pid = os.fork()
        if not self.pid:
            os.close(send); os.close(receive)
            try: self.worker(incoming, outgoing)
            except BaseException:
                traceback.print_exc(); os._exit(97)
            os._exit(0)
        os.close(incoming); os.close(outgoing); self.send, self.receive = send, receive
        try:
            ready = self.read()
            require(ready.get('ready') is True and ready['pid'] == self.pid and ready['sid'] == self.pid,
                    'fresh timestamp session prerequisite missing')
            status = dict(line.split(':', 1) for line in Path('/proc', str(self.pid), 'status').read_text().splitlines() if ':' in line)
            require([int(x) for x in status['Uid'].split()] == [uid] * 4 and
                    [int(x) for x in status['Gid'].split()] == [uid] * 4, 'live peer credentials differ')
            self.identity = ready
        except BaseException:
            os.kill(self.pid, signal.SIGKILL); os.waitpid(self.pid, 0); self.closed = True
            os.close(self.send); os.close(self.receive)
            (self.rt.args.output / (self.name + '-peer.jsonl')).write_bytes(self.raw)
            raise

    def worker(self, incoming, outgoing):
        base = self.rt.base; os.setsid(); os.chdir(self.rt.work)
        # Later siblings must not retain pipe ends belonging to earlier peers.
        descriptors = [int(path.name) for path in Path('/proc/self/fd').iterdir()]
        require(len(descriptors) <= 256, 'peer descriptor enumeration bound')
        for descriptor in descriptors:
            if descriptor > 2 and descriptor not in (incoming, outgoing):
                try: os.close(descriptor)
                except OSError as error:
                    if error.errno != errno.EBADF: raise
        os.setgroups([self.uid, base.SHARED]); os.setresgid(self.uid, self.uid, self.uid)
        os.setresuid(self.uid, self.uid, self.uid)
        user = 'pcv2caller' if self.uid == base.CALLER else 'pcv2target'
        def emit(value):
            data = json.dumps(value, sort_keys=True).encode() + b'\n'
            require(len(data) < 4096 and os.write(outgoing, data) == len(data), 'peer response bound/write')
        def fork_probe():
            reader, writer = os.pipe(); child = os.fork(); reaped = False
            if not child:
                os.close(reader)
                try:
                    child_fd = os.open(base.DEVICE, os.O_RDWR | os.O_CLOEXEC)
                    try: prepared = validation_prepare(base, child_fd, uid=self.uid, user=user)
                    finally: os.close(child_fd)
                    result = {'decision': prepared.decision, 'cache_hit': prepared.cache_hit}
                except BaseException as error:
                    result = {'error_kind': type(error).__name__, 'error': str(error)}
                try:
                    result.update(pid=os.getpid(), sid=os.getsid(0))
                    data = json.dumps(result).encode() + b'\n'
                    require(len(data) < 4096 and os.write(writer, data) == len(data), 'fork probe response write')
                    os._exit(0)
                except BaseException: os._exit(97)
            os.close(writer)
            try:
                data = bytearray(); deadline = time.monotonic() + 10
                while b'\n' not in data:
                    require(time.monotonic() < deadline and len(data) < 4096, 'fork probe timeout/output bound')
                    if not select.select([reader], [], [], .05)[0]: continue
                    chunk = os.read(reader, 4096); require(chunk, 'fork probe ended without response'); data.extend(chunk)
                result = json.loads(data)
                status = dict(line.split(':', 1) for line in Path('/proc', str(child), 'status').read_text().splitlines() if ':' in line)
                result['observed_uid'] = [int(x) for x in status['Uid'].split()]
                result['observed_gid'] = [int(x) for x in status['Gid'].split()]
                base.check(result['pid'] == child and result['sid'] == os.getsid(child) == os.getsid(0) and
                           result['observed_uid'] == result['observed_gid'] == [self.uid] * 4,
                           'same-session child identity differs')
                while True:
                    waited, status = os.waitpid(child, os.WNOHANG)
                    if waited:
                        reaped = True; base.check(waited == child and status == 0, 'fork probe child failed'); break
                    require(time.monotonic() < deadline, 'fork probe reap timeout'); time.sleep(.01)
                if result.get('error_kind') == 'AssertionError': raise AssertionError(result['error'])
                require('error' not in result, 'fork probe observer/setup error: ' + str(result))
                return result
            finally:
                if not reaped:
                    os.kill(child, signal.SIGKILL); os.waitpid(child, 0)
                os.close(reader)
        emit({'ready': True, 'pid': os.getpid(), 'sid': os.getsid(0), 'uid': self.uid})
        try:
            stream = os.fdopen(incoming, 'rb', buffering=0)
            while True:
                line = stream.readline(4097)
                require(line.endswith(b'\n') and len(line) <= 4096, 'peer command framing')
                command = json.loads(line); operation = command['operation']
                if operation == 'stop': emit({'stopped': True}); break
                if operation == 'fork-probe':
                    try: result = fork_probe()
                    except BaseException as error: result = {'error_kind': type(error).__name__, 'error': str(error)}
                    emit(result); continue
                fd = os.open(base.DEVICE, os.O_RDWR | os.O_CLOEXEC)
                try:
                    if operation in ('reset', 'reset-all'):
                        actual_ioctl(base.reset, fd, operation == 'reset-all'); result = {'reset': operation}
                    else:
                        options = command.get('target', {})
                        prepared = validation_prepare(base, fd, uid=self.uid, user=user, **options)
                        result = {'decision': prepared.decision, 'cache_hit': prepared.cache_hit,
                                  'request_id': prepared.request_id, 'deadline_ns': prepared.deadline_ns}
                        if operation == 'seed':
                            base.check(prepared.decision == 2 and not prepared.cache_hit, 'seed was not a fresh real verification')
                            actual_ioctl(base.verify, fd, prepared)
                            validated = actual_ioctl(base.redeem, fd, prepared)
                            base.check(validated[0] == 7 and validated[1:4] == (0, 0, 0), 'validation did not finish without execution')
                            result['validated'] = True
                        elif operation != 'probe': raise RuntimeError('unknown timestamp operation')
                    result['boottime_ns'] = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                except BaseException as error:
                    result = {'error_kind': type(error).__name__, 'error': str(error)}
                finally: os.close(fd)
                # Closing a pending request emits a terminal audit record.
                # Acknowledge only afterwards so the observer cannot drain
                # between the response and that last record.
                emit(result)
        finally:
            os.close(outgoing)

    def read(self):
        deadline = time.monotonic() + 40
        while b'\n' not in self.buffer:
            require(time.monotonic() < deadline, 'timestamp peer response timeout')
            if not select.select([self.receive], [], [], .05)[0]: continue
            chunk = os.read(self.receive, 4096)
            require(chunk and len(self.raw) + len(chunk) <= 262144, 'timestamp peer EOF/output bound')
            self.raw.extend(chunk); self.buffer.extend(chunk)
        line, _, tail = self.buffer.partition(b'\n'); self.buffer = bytearray(tail)
        result = json.loads(line)
        if result.get('error_kind') == 'AssertionError': raise AssertionError(result['error'])
        require('error' not in result, 'timestamp peer setup/operation error: ' + str(result))
        return result

    def request(self, operation, **fields):
        message = dict(operation=operation, **fields); data = json.dumps(message).encode() + b'\n'
        event = {'request': message, 'response': None}; self.events.append(event)
        require(len(data) < 4096 and os.write(self.send, data) == len(data), 'peer request bound/write')
        response = self.read(); event['response'] = response; return response

    def close(self):
        if self.closed: return
        try:
            self.request('stop')
            deadline = time.monotonic() + 5
            while True:
                waited, status = os.waitpid(self.pid, os.WNOHANG)
                if waited:
                    self.closed = True
                    require(waited == self.pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                            'timestamp peer did not exit cleanly')
                    break
                require(time.monotonic() < deadline, 'timestamp peer exit timeout'); time.sleep(.01)
        finally:
            if not self.closed:
                os.kill(self.pid, signal.SIGKILL); os.waitpid(self.pid, 0); self.closed = True
            os.close(self.send); os.close(self.receive)
            (self.rt.args.output / (self.name + '-peer.jsonl')).write_bytes(self.raw)
            (self.rt.args.output / (self.name + '-peer-events.json')).write_text(json.dumps(self.events, indent=2) + '\n')


def scopes(rt):
    base = rt.base; peers = []
    try:
        for name, uid in (('scope-a', base.CALLER), ('scope-b', base.CALLER), ('scope-other-caller', base.TARGET)):
            peers.append(Peer(rt, name, uid))
        a, b, other = peers
        def expect(peer, wanted, **target):
            result = peer.request('probe', target=target)
            base.check(result['decision'] == wanted and result['cache_hit'] == int(wanted == 3),
                       'actual session/caller/target cache isolation differs')
            return result
        a.request('seed'); expect(a, 3); expect(b, 2); expect(other, 2)
        same_session = a.request('fork-probe')
        base.check(same_session['decision'] == 3 and same_session['cache_hit'] == 1 and
                   same_session['pid'] != a.pid and same_session['sid'] == a.pid,
                   'cache did not survive a new process in the same retained session')
        expect(a, 2, target='root', target_uid=0, target_gid=0)
        expect(a, 2, target_gid=base.SHARED, explicit=True)
        b.request('seed'); other.request('seed')
        a.request('reset'); expect(a, 2); expect(b, 3); expect(other, 3)
        a.request('seed'); a.request('reset-all'); expect(a, 2); expect(b, 2); expect(other, 3)
        rows = audit(rt, 'timestamp-scope-reset-matrix')
        base.check(not any(outcome(row) in (5, 6) for row in rows), 'scope controls unexpectedly executed a command')
        return {'peers': [{'identity': p.identity, 'events': p.events} for p in peers],
                'audit_records': len(rows), 'scope': 'real uid plus retained POSIX session identity',
                'namespace_or_tty_scope_claim': False}
    finally:
        errors = []
        for peer in reversed(peers):
            try: peer.close()
            except Exception as error: errors.append(repr(error))
        require(not errors, 'timestamp peer cleanup failed: ' + str(errors))


def cache_lifetime(rt, expiry):
    base = rt.base; peer = Peer(rt, 'cache-expiry' if expiry else 'cache-default-zero', base.CALLER)
    try:
        seed = peer.request('seed')
        if expiry:
            current = peer.request('probe')
            base.check(current['decision'] == 3 and current['cache_hit'] == 1, 'positive policy did not cache')
            # Real boottime and the actual one-minute policy; no test clock,
            # timeout override, busy loop or shortened production lifetime.
            finish = seed['boottime_ns'] + 61_000_000_000
            while time.clock_gettime_ns(time.CLOCK_BOOTTIME) < finish: time.sleep(.1)
        final = peer.request('probe')
        base.check(final['decision'] == 2 and final['cache_hit'] == 0, 'expired/default-zero cache was usable')
        name = 'timestamp-real-boottime-expiry' if expiry else 'timestamp-default-zero'
        rows = audit(rt, name)
        base.check(not any(outcome(row) in (5, 6) for row in rows), 'lifetime control executed a command')
        return {'identity': peer.identity, 'events': peer.events, 'audit_records': len(rows),
                'elapsed_boottime_ns': final['boottime_ns'] - seed['boottime_ns'], 'test_clock': False}
    finally: peer.close()


def reset_failure_matrix(rt):
    base = rt.base; q = shlex.quote
    pins = reload_policy(rt, reset_error=True)
    common = 'sudo --authority-v2-qualification -n -u pcv2target '
    for suffix, script, expected, targets in (
            ('positive-before', common + q(str(rt.nopass)) + ' exit-7', 7, 1),
            ('k-command', 'sudo --authority-v2-qualification -k -n -u pcv2target ' + q(str(rt.nopass)), 1, 0),
            ('k-validate', 'sudo --authority-v2-qualification -k -v -u pcv2target', 1, 0),
            ('k-alone', 'sudo --authority-v2-qualification -k', 1, 0),
            ('K-alone', 'sudo --authority-v2-qualification -K', 1, 0),
            ('positive-after', common + q(str(rt.nopass)) + ' exit-9', 9, 1)):
        name = 'reset-error-' + suffix
        def one(n=name, s=script, e=expected, t=targets):
            def rejected(rows):
                base.check(len(rows) == 1 and outcome(rows[0]) == 12 and reason(rows[0]) == 6 and
                           struct.unpack_from('<II', rows[0], 96) == (0, errno.EIO),
                           'failed reset was not the sole operation; authorization/action followed')
            details = bash_case(rt, n, s, e, t, audit_rule=rejected if not t else None)
            details.update(denial_only_reset_fault=True, snapshot_pins=pins)
            return details
        rt.note(name, one, 'actual-consumer-with-denial-only-reset-fault')


def main():
    parser = argparse.ArgumentParser()
    for name in ('receipt', 'bash', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('receipt-sha256', 'bash-sha256', 'expected-uuid'): parser.add_argument('--' + name, required=True)
    args = parser.parse_args(); protected(args.receipt, args.receipt_sha256)
    receipt = json.loads(args.receipt.read_text())
    require(receipt['schema'] == 1 and receipt['kind'] == 'authority-privcmd-v2-build-only', 'receipt kind differs')
    for name, entry in receipt['files'].items():
        require(Path(name).name == name, 'invalid artifact name'); protected(args.receipt.parent / name, entry['sha256'])
        require((args.receipt.parent / name).stat().st_size == entry['bytes'], 'artifact size differs')
    require(sha(__file__) == receipt['files']['guest-command-timestamp-controls.py']['sha256'], 'new driver pin differs')
    spec = importlib.util.spec_from_file_location('privcmd_base', args.receipt.parent / 'guest-privcmd-controls.py')
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    base.guard(args.expected_uuid, receipt['kernel_release']); protected(args.bash, args.bash_sha256)
    require(args.receipt.is_absolute() and args.bash.is_absolute() and args.output.is_absolute() and
            args.output.resolve().is_relative_to(base.HOME) and not args.output.exists(), 'fresh private absolute output required')
    args.output.mkdir(mode=0o700); rt = base.Runtime(args, receipt); rt.base = base
    rt.report.update(scope='command denial/verification and explicit session timestamp matrix',
                     blocking_gaps=['shell/login replacement', 'caller-filtered authority listing',
                                    'production activation', 'complete retained obligation reconciliation'])
    before = rt.command(['/usr/bin/dmesg', '--raw'])
    require(before.returncode == 0, 'kernel log unavailable'); (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        rt.setup(); rt.report['matrix_snapshot_pins'] = reload_policy(rt)
        consumer_matrix(rt)
        rt.note('timestamp-scope-reset-matrix', lambda: scopes(rt), 'actual-device-and-native-verifier')
        rt.note('timestamp-real-boottime-expiry', lambda: cache_lifetime(rt, True), 'actual-device-and-native-verifier')
        reload_policy(rt, timeout=0)
        rt.note('timestamp-default-zero', lambda: cache_lifetime(rt, False), 'actual-device-and-native-verifier')
        reset_failure_matrix(rt)
        require(len(rt.cases) == 24 and all(row['status'] == 'PASS' for row in rt.cases), 'new command/timestamp matrix incomplete')
        rt.report.update(status='PASS', original_topic_credit=0)
    except AssertionError as error: rt.report.update(status='FAIL', reason=str(error))
    except Exception as error: rt.report.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error))
    finally:
        try:
            if rt.loaded: audit(rt, 'final-retained')
            rt.cleanup(); after = rt.command(['/usr/bin/dmesg', '--raw'])
            require(after.returncode == 0 and after.stdout.startswith(before.stdout), 'kernel log lost/wrapped')
            delta = after.stdout[len(before.stdout):]
            (args.output / 'dmesg-after.txt').write_bytes(after.stdout); (args.output / 'dmesg-delta.txt').write_bytes(delta)
            require(not any(value in delta.lower() for value in (b'warning:', b'bug:', b'kasan:', b'kcsan:', b'ubsan:',
                b'held lock', b'oops:', b'possible recursive locking', b'inconsistent lock state',
                b'general protection fault', b'info: task ', b'panic:')), 'kernel warning/fault evidence')
            protected(args.bash, args.bash_sha256); protected(args.receipt, args.receipt_sha256)
            for name, entry in receipt['files'].items(): protected(args.receipt.parent / name, entry['sha256'])
        except Exception as error: rt.report.update(status='ERROR', cleanup_or_kernel_error=repr(error))
        (args.output / 'commands.json').write_text(json.dumps(rt.commands, indent=2) + '\n')
        (args.output / 'report.json').write_text(json.dumps(rt.report, indent=2) + '\n')
    print(json.dumps({'status': rt.report['status'], 'report': str(args.output / 'report.json')}))
    return 0 if rt.report['status'] == 'PASS' else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error: print('command/timestamp preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
