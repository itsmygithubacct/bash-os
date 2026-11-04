#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Owned, real-syscall consumer observer for an attested disposable guest.

Does not emulate any authority ioctl or verifier result. Exec notifications and
exit notifications capture live IDs; an attempted forbidden exec is a failure
even when the observer prevents it. The caller separately evaluates the trace.
"""
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import stat
import struct
import sys
import time
import types
import uuid

HOME = Path('/tmp/parity-home')
CASE = Path('/tmp/parity-case')
NOTIF_RECV, NOTIF_SEND, NOTIF_VALID = 0xc0502100, 0xc0182101, 0x40082102
SYSCALLS = ('execve', 'execveat', 'exit', 'exit_group', 'setgroups', 'setresgid',
            'setresuid', 'setgid', 'setuid', 'setregid', 'setreuid',
            'fork', 'vfork', 'clone', 'clone3', 'wait4', 'waitid', 'ioctl')
STATE_FAULTS = {'login-state-file-sync': 'fsync', 'login-state-rename': 'renameat',
                'login-state-directory-sync': 'fsync', 'login-state-clear': 'unlinkat'}


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def protected(path, pin):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'unprotected observer input: ' + str(path))
    require(digest(path) == pin, 'observer input pin differs: ' + str(path))


def guard(config):
    require(__debug__ and platform.machine() == 'x86_64', 'debug x86-64 required')
    require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'guest root required')
    require(Path.cwd() == CASE and os.environ.get('HOME') == str(HOME), 'private parity scratch required')
    token = str(uuid.UUID(config['uuid']))
    require(Path('/etc/bashos-parity-vm').read_text().strip() == token and
            Path('/run/bashos-parity-vm-identity').read_text().strip() == token, 'live guest identity differs')
    command = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    require(b'/opt/bashos-parity/harness/guest.py' in command and token.encode() in command,
            'owned guest evaluator required')
    require(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU' and
            platform.release() == config['kernel'], 'guest/kernel differs')
    caps = next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:'))
    require(int(caps, 16) & (1 << 19), 'observer needs guest CAP_SYS_PTRACE to read non-dumpable owned tasks')


def identity(pid):
    directory = Path('/proc') / str(pid)
    fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in (directory / 'status').read_text().splitlines())
    return {'pid': pid, 'ppid': int(fields[1]), 'birth': int(fields[19]),
            'uid': list(map(int, status['Uid'].split())), 'gid': list(map(int, status['Gid'].split())),
            'groups': list(map(int, status['Groups'].split())), 'caps': status['CapEff'].strip()}


def pathname(pid, address):
    fd = os.open('/proc/%d/mem' % pid, os.O_RDONLY | os.O_CLOEXEC)
    try:
        data = bytearray()
        while len(data) < 4096:
            position = address + len(data)
            chunk = os.pread(fd, min(128, 4096 - position % 4096, 4096 - len(data)), position)
            require(chunk, 'unreadable exec pathname')
            end = chunk.find(b'\0')
            if end >= 0:
                return os.fsdecode(bytes(data) + chunk[:end])
            data.extend(chunk)
        raise RuntimeError('overlong exec pathname')
    finally:
        os.close(fd)


def public_request(pid, address, length):
    fd = os.open('/proc/%d/mem' % pid, os.O_RDONLY | os.O_CLOEXEC)
    try:
        data = os.pread(fd, length, address)
        require(len(data) == length, 'short public identity request')
        return data
    finally:
        os.close(fd)


def state_fault_event(config, pid, name, args):
    """Identify only the selected real operation in the held private store."""
    fault = config.get('fault')
    if name != STATE_FAULTS.get(fault): return None
    directory = Path(config['login_state_directory'])
    wanted = config['expected']['state_directory_identity']
    actual = directory.stat()
    require([actual.st_dev, actual.st_ino] == wanted, 'state directory replaced during observation')

    def same_directory(fd):
        st = Path('/proc/%d/fd/%d' % (pid, fd)).stat()
        return stat.S_ISDIR(st.st_mode) and [st.st_dev, st.st_ino] == wanted

    if fault == 'login-state-file-sync':
        link = Path('/proc/%d/fd/%d' % (pid, args[0]))
        target, st = Path(os.readlink(link)), link.stat()
        if (target.parent != directory or not re.fullmatch(r'\.state-[0-9a-f]{32}', target.name) or
                not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or
                stat.S_IMODE(st.st_mode) != 0o600): return None
        state_name = target.name
    elif fault == 'login-state-directory-sync':
        if not same_directory(args[0]): return None
        state_name = '.'
    elif fault == 'login-state-rename':
        if not same_directory(args[0]) or not same_directory(args[2]): return None
        source, state_name = pathname(pid, args[1]), pathname(pid, args[3])
        if (not re.fullmatch(r'\.state-[0-9a-f]{32}', source) or
                state_name != config['expected']['state_file']): return None
    else:
        if not same_directory(args[0]) or args[2] != 0: return None
        state_name = pathname(pid, args[1])
        if state_name != config['expected']['state_file']: return None
    return {'state_operation': fault, 'state_directory_identity': wanted, 'state_name': state_name}


def evaluate(events, expected):
    """Pure trace oracle; deliberately bad actors must fail this same predicate."""
    errors = []
    if not events or [x.get('sequence') for x in events] != list(range(1, len(events) + 1)):
        errors.append('incomplete event sequence')
    if not events or events[-1].get('phase') != 'supervisor-end' or events[-1].get('error'):
        errors.append('observer did not complete')
    notifications = [x for x in events if 'notification_id' in x]
    if any(not x.get('identity_rechecked') for x in notifications):
        errors.append('identity not rechecked')
    boot = [x for x in events if x.get('phase') == 'bootstrap']
    if len(boot) != 1:
        errors.append('bootstrap count differs')
    # A rejected incomplete observation is not a reached product failure, nor
    # evidence that a deliberately bad actor exercised the denial oracle.
    observation_complete = (not errors and events[-1].get('bootstrap_seen') is True and
                            events[-1].get('bootstrap_confirmed') is True)
    if not observation_complete and not errors:
        errors.append('bootstrap completion absent')
    if not events or events[-1].get('descendant_cleanup_complete') is not True:
        observation_complete = False
        errors.append('owned descendant cleanup incomplete')
    orphans = [x for x in events if x.get('phase') == 'orphaned-descendant']
    if orphans:
        errors.append('launcher exited before an owned descendant')
    attempts = [x for x in events if x.get('phase') == 'target-exec']
    denials = [x for x in events if x.get('guard_denial')]
    if denials:
        errors.append('observer guard denied an attempted operation')
    if len(attempts) != expected['exec_count']:
        errors.append('target exec attempt count differs')
    for event in attempts:
        who = event['notifying']
        if who['uid'] != [expected['uid']] * 4 or who['gid'] != [expected['gid']] * 4:
            errors.append('target live real/effective/saved/fs IDs differ')
    faults = [x for x in events if x.get('selected_fault')]
    if len(faults) != int(bool(expected.get('fault'))):
        errors.append('selected fault count differs')
    if faults:
        fault = faults[0]
        wanted_call = STATE_FAULTS.get(expected['fault'],
            'ioctl' if expected['fault'] == 'tty-hide' else expected['fault'])
        if fault['syscall'] != wanted_call or fault.get('reply') != 'errno:13':
            errors.append('selected fault origin differs')
        if expected['fault'] == 'tty-hide':
            if (fault['args'][1] != 0x5404 or fault.get('terminal_lflag', 0) & 0x0a or
                    fault['notifying']['uid'] != [0] * 4 or fault['notifying']['gid'] != [0] * 4):
                errors.append('terminal suppression fault origin differs')
            if any(x['syscall'] in ('setgroups', 'setresgid', 'setresuid') or
                   x.get('identity_operation') for x in notifications):
                errors.append('authentication or credentials reached after failed terminal setup')
        if expected['fault'] in STATE_FAULTS:
            if (fault.get('state_operation') != expected['fault'] or
                    fault.get('state_directory_identity') != expected.get('state_directory_identity') or
                    fault['notifying']['uid'] != [0] * 4 or fault['notifying']['gid'] != [0] * 4):
                errors.append('persistent state fault origin differs')
            selected_name = fault.get('state_name', '')
            if ((expected['fault'] == 'login-state-file-sync' and
                 not re.fullmatch(r'\.state-[0-9a-f]{32}', selected_name)) or
                (expected['fault'] == 'login-state-directory-sync' and selected_name != '.') or
                (expected['fault'] in ('login-state-rename', 'login-state-clear') and
                 selected_name != expected.get('state_file'))):
                errors.append('persistent state fault pathname differs')
            actor = fault['notifying']['pid']
            exits = [x for x in notifications if x['syscall'] in ('exit', 'exit_group') and
                     x['notifying']['pid'] == actor and x['sequence'] > fault['sequence']]
            if (len(exits) != 1 or exits[0]['args'][0] != 1 or
                    exits[0]['notifying']['uid'] != [0] * 4 or exits[0]['notifying']['gid'] != [0] * 4):
                errors.append('persistent state failure did not exit with unchanged IDs/status 1')
            if any(x['syscall'] in ('setgroups', 'setresgid', 'setresuid') for x in notifications):
                errors.append('credentials attempted despite persistent state failure')
    if faults and expected['fault'] in ('setgroups', 'setresgid', 'setresuid'):
        fault = faults[0]
        # The credential fault may follow only this exact transition prefix in
        # its own actor; no later credential or exec attempt is acceptable.
        actor = fault['notifying']['pid']
        transitions = [x for x in notifications if x['notifying']['pid'] == actor and
                       x['syscall'] in ('setgroups', 'setresgid', 'setresuid')]
        prefix = ['setgroups', 'setresgid', 'setresuid']
        if [x['syscall'] for x in transitions] != prefix[:prefix.index(expected['fault']) + 1]:
            errors.append('credential fault prefix differs')
        exits = [x for x in notifications if x.get('syscall') in ('exit', 'exit_group') and
                 x['notifying']['pid'] == actor and x['sequence'] > fault['sequence']]
        if len(exits) != 1:
            errors.append('fault actor exit IDs were not observed')
        else:
            ids = fault['notifying']
            wanted_gid = expected['gid'] if expected['fault'] == 'setresuid' else 0
            if (ids['uid'] != [0] * 4 or ids['gid'] != [wanted_gid] * 4 or
                    exits[0]['notifying']['uid'] != ids['uid'] or exits[0]['notifying']['gid'] != ids['gid'] or
                    exits[0]['args'][0] != 126):
                errors.append('fault/exit live IDs or exit status differ')
    if expected.get('require_proof'):
        # Actual kernel operations are continued, never synthesized. Successful
        # target execution is separately required; these events alone are not
        # proof of ioctl success or authentication.
        verifications = [x for x in notifications if x.get('identity_operation') == 'verify']
        consumptions = [x for x in notifications if x.get('identity_operation') == 'consume']
        if len(verifications) != 1 or len(consumptions) != 1:
            errors.append('versioned verify/consume path absent')
        else:
            first, last = verifications[0], consumptions[0]
            if (first['sequence'] >= last['sequence'] or first['identity_request'] != last['identity_request'] or
                    first['args'][0] != last['args'][0] or not first['actual_authority_fd'] or not last['actual_authority_fd'] or
                    last['identity_request'][1:3] != [expected['uid'], expected['gid']]):
                errors.append('identity target/context/operation order differs')
            if expected.get('delegated'):
                delegations = [x for x in notifications if x.get('identity_operation') == 'delegate']
                if (len(delegations) != 1 or delegations[0]['notifying']['pid'] != first['notifying']['pid'] or
                        delegations[0]['child_pid'] != last['notifying']['pid'] or
                        last['notifying']['ppid'] != first['notifying']['pid'] or
                        not first['sequence'] < delegations[0]['sequence'] < last['sequence'] or
                        first['identity_request'][0] != 4):
                    errors.append('explicit SSH delegation lineage differs')
            elif first['notifying']['pid'] != last['notifying']['pid'] or first['identity_request'][0] != 1:
                errors.append('login proof crossed actors/purposes')
            if attempts and any(event['sequence'] <= last['sequence'] for event in attempts):
                errors.append('target exec preceded proof consumption')
            if faults and (faults[0]['notifying']['pid'] != last['notifying']['pid'] or
                           faults[0]['sequence'] <= last['sequence']):
                errors.append('credential fault preceded proof consumption or changed actor')
    return {'accepted': not errors, 'observation_complete': observation_complete,
            'reasons': errors, 'target_exec_attempts': len(attempts),
            'guard_denials': len(denials), 'selected_faults': len(faults),
            'orphaned_descendants': len(orphans)}


def main():
    config_path = Path(sys.argv[1]).resolve()
    require(config_path.is_relative_to(HOME), 'config outside private HOME')
    config = json.loads(config_path.read_text())
    guard(config)
    require(config['schema'] == 1 and 1 <= config['timeout'] <= 60, 'observer config differs')
    for key in ('listener', 'libseccomp', 'program', 'target'):
        protected(config[key], config[key + '_sha256'])
    trace = Path(config['trace']).resolve()
    require(trace.is_relative_to(HOME) and not trace.exists(), 'fresh private trace required')
    require(config.get('fault') in (None, 'setgroups', 'setresgid', 'setresuid', 'tty-hide', *STATE_FAULTS),
            'unsupported fault')
    if config.get('fault') in STATE_FAULTS:
        directory = Path(config['login_state_directory'])
        allowed = Path('/run') / ('bashos-consumer-v2-' + str(uuid.UUID(config['uuid']))) / 'lock'
        require(directory == allowed and directory.resolve() == directory, 'unexpected state fault directory')
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700 and
                [info.st_dev, info.st_ino] == config['expected']['state_directory_identity'] and
                re.fullmatch(r'fail\.[a-zA-Z0-9_-]{1,63}', config['expected']['state_file']),
                'unprotected state fault fixture')
    spec = importlib.util.spec_from_file_location('owned_listener', config['listener'])
    seq = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seq)
    # Reuse the already reviewed raw-filter bootstrap, with explicit root guest
    # attestation and a separately pinned library. No device emulation hooks.
    seq.guest_guard = lambda: guard(config)
    real_cdll = ctypes.CDLL
    seq.ctypes = types.SimpleNamespace(**{name: getattr(ctypes, name) for name in dir(ctypes)})
    seq.ctypes.CDLL = lambda name, **kw: real_cdll(config['libseccomp'] if name == 'libseccomp.so.2' else name, **kw)
    seq.BOOTSTRAP_LOG = Path(str(trace) + '.bootstrap')
    # This private supervisor creates exactly one launcher. Become its
    # subreaper before the fork so a premature launcher exit cannot silently
    # abandon the connection subtree or escape the trace's lifetime gate.
    children_file = Path('/proc/self/task/%d/children' % os.getpid())
    require(not children_file.read_text().split(), 'observer already has children')
    libc = real_cdll(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, 'cannot become owned subtree subreaper')
    subreaper = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(subreaper), 0, 0, 0) == 0 and subreaper.value == 1,
            'owned subtree subreaper was not established')

    def supervise(lib, listener, child, *unused):
        status, error, sequence, bootstrapped, faults = None, None, 0, False, 0
        bootstrap_confirmed = False
        descendant_cleanup_complete = False
        owned = {child: (identity(child), os.pidfd_open(child))}
        deadline = time.monotonic() + config['timeout']
        with trace.open('x') as log:
            def emit(event):
                nonlocal sequence
                sequence += 1
                require(sequence <= 8192, 'notification bound exceeded')
                event.update(sequence=sequence, monotonic_ns=time.monotonic_ns())
                log.write(json.dumps(event, sort_keys=True) + '\n'); log.flush()

            try:
                while status is None:
                    require(time.monotonic() < deadline, 'consumer observer timeout')
                    done, value = os.waitpid(child, os.WNOHANG)
                    if done:
                        status = value; break
                    ready, _, _ = select.select([listener], [], [], .05)
                    if not ready:
                        continue
                    request = bytearray(80)
                    try:
                        fcntl.ioctl(listener, NOTIF_RECV, request, True)
                    except OSError as failure:
                        if failure.errno in (errno.EINTR, errno.ENOENT): continue
                        raise
                    ident, pid, _, nr, arch, ip = struct.unpack_from('<QIIiIQ', request)
                    require(arch == 0xc000003e, 'notification architecture differs')
                    args = list(struct.unpack_from('<6Q', request, 32))
                    raw = lib.seccomp_syscall_resolve_num_arch(0, nr)
                    name = ctypes.cast(raw, ctypes.c_char_p).value.decode() if raw else str(nr)
                    who = identity(pid)
                    if pid not in owned:
                        parent = who['ppid']
                        require(parent in owned and identity(parent)['birth'] == owned[parent][0]['birth'],
                                'notification is not from an owned descendant')
                        owned[pid] = (who, os.pidfd_open(pid))
                    require(who['birth'] == owned[pid][0]['birth'], 'actor PID recycled')
                    event = {'notification_id': ident, 'syscall': name, 'notifying': who,
                             'args': args, 'reply': 'continue', 'phase': 'native-operation'}
                    if bootstrapped and not bootstrap_confirmed:
                        # A continued exec notification proves only an attempt.
                        # For example, a noexec mount returns to the Python
                        # launcher, whose exit(126) must be a setup ERROR.
                        actual = Path('/proc/%d/exe' % pid).stat()
                        pinned = Path(config['program']).stat()
                        require(pid == child and (actual.st_dev, actual.st_ino) == (pinned.st_dev, pinned.st_ino),
                                'initial exec did not enter the pinned program')
                        bootstrap_confirmed = True
                        event['bootstrap_image_identity'] = [actual.st_dev, actual.st_ino]
                    code = 0
                    state_event = state_fault_event(config, pid, name, args) if not faults else None
                    if name in ('execve', 'execveat'):
                        path = pathname(pid, args[0] if name == 'execve' else args[1])
                        event['path'] = path
                        if not bootstrapped:
                            require(pid == child and name == 'execve' and path == config['program'], 'unexpected bootstrap exec')
                            bootstrapped = True; event['phase'] = 'bootstrap'
                        else:
                            event['phase'] = 'target-exec'
                            expected = config['expected']
                            if (path != config['target'] or not expected['exec_count'] or
                                    who['uid'] != [expected['uid']] * 4 or who['gid'] != [expected['gid']] * 4):
                                code = errno.EACCES; event['guard_denial'] = True
                    elif name == config.get('fault') and not faults:
                        require(bootstrapped, 'fault before bootstrap')
                        faults += 1; code = errno.EACCES; event['selected_fault'] = True
                    elif state_event:
                        require(bootstrapped and pid == child, 'state fault must belong to bootstrapped actor')
                        faults += 1; code = errno.EACCES
                        event.update(state_event, selected_fault=True)
                    elif name == 'ioctl' and args[1] == 0x5404 and config.get('fault') == 'tty-hide' and not faults:
                        flags = struct.unpack_from('<I', public_request(pid, args[2], 16), 12)[0]
                        if not flags & 0x0a:  # ECHO | ICANON; termios only, no secret bytes.
                            require(bootstrapped, 'terminal fault before bootstrap')
                            faults += 1; code = errno.EACCES
                            event.update(selected_fault=True, terminal_lflag=flags)
                    elif name == 'ioctl' and args[1] in (0x4060bc01, 0x4060bc02, 0x4080bc03, 0x4010bc05):
                        actual = Path('/proc/%d/fd/%d' % (pid, args[0])).stat()
                        device = Path('/dev/bashos-auth-v2-test').stat()
                        event['actual_authority_fd'] = (stat.S_ISCHR(actual.st_mode) and actual.st_rdev == device.st_rdev and
                                                        actual.st_dev == device.st_dev and actual.st_ino == device.st_ino)
                        if args[1] == 0x4010bc05:
                            event['identity_operation'] = 'delegate'
                            event['child_pid'] = struct.unpack('<4I', public_request(pid, args[2], 16))[2]
                        else:
                            # Read only the 16-byte envelope and 80-byte public
                            # identity. Never read/log reference or secret bytes.
                            request = public_request(pid, args[2], 96)
                            purpose, uid, gid, encoding, user = struct.unpack_from('<4I64s', request, 16)
                            event['identity_operation'] = 'consume' if args[1] == 0x4080bc03 else 'verify'
                            event['identity_request'] = [purpose, uid, gid, encoding, user.split(b'\0', 1)[0].decode('ascii')]
                    fcntl.ioctl(listener, NOTIF_VALID, struct.pack('<Q', ident))
                    require(identity(pid) == who, 'notifying task identity changed')
                    event['identity_rechecked'] = True
                    if code: event['reply'] = 'errno:%d' % code
                    emit(event)
                    fcntl.ioctl(listener, NOTIF_SEND, struct.pack('<QqiI', ident, 0, -code, 0 if code else 1))
            except BaseException as failure:
                error = type(failure).__name__ + ': ' + str(failure)
            finally:
                # Even on a normal launcher exit, reject and reap adopted
                # descendants. Signal only birth-checked direct children via
                # pidfds; killing an adopted parent exposes its next generation
                # here. Never scan or signal unrelated guest tasks.
                cleanup_deadline, orphaned = time.monotonic() + 2, set()
                try:
                    while True:
                        children = list(map(int, children_file.read_text().split()))
                        if not children:
                            descendant_cleanup_complete = True
                            break
                        require(time.monotonic() < cleanup_deadline, 'owned descendant cleanup timeout')
                        for pid in children:
                            who = identity(pid)
                            require(who['ppid'] == os.getpid(), 'cleanup task is not a direct owned child')
                            if pid not in owned:
                                owned[pid] = (who, os.pidfd_open(pid))
                            require(identity(pid) == who and who['birth'] == owned[pid][0]['birth'],
                                    'cleanup child identity changed')
                            if pid != child and pid not in orphaned:
                                orphaned.add(pid)
                                emit({'phase': 'orphaned-descendant', 'notifying': who})
                            try: signal.pidfd_send_signal(owned[pid][1], signal.SIGKILL)
                            except ProcessLookupError: pass
                        for pid in children:
                            done, value = os.waitpid(pid, os.WNOHANG)
                            if done == child: status = value
                            elif done:
                                emit({'phase': 'orphan-reaped', 'pid': done, 'raw_wait_status': value})
                        time.sleep(.01)
                except BaseException as failure:
                    cleanup_error = type(failure).__name__ + ': ' + str(failure)
                    error = error + '; cleanup: ' + cleanup_error if error else cleanup_error
                for _, fd in owned.values(): os.close(fd)
                emit({'phase': 'supervisor-end', 'raw_wait_status': status, 'error': error,
                      'selected_faults': faults, 'bootstrap_seen': bootstrapped,
                      'bootstrap_confirmed': bootstrap_confirmed,
                      'descendant_cleanup_complete': descendant_cleanup_complete})
        return status if not error else 125 << 8

    seq.supervise = supervise
    extra = ('fsync', 'renameat', 'unlinkat') if config.get('fault') in STATE_FAULTS else ()
    rules = [value for name in (*SYSCALLS, *extra) for value in ('--notify', name)]
    sys.argv = [config['listener'], *rules, '--', config['program'], *config['arguments']]
    seq.main()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('consumer observer incomplete: ' + repr(error), file=sys.stderr)
        sys.exit(125)
