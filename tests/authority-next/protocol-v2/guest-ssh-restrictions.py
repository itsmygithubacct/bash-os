#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Encrypted SSH restriction controls; attested disposable guest execution only.

Uses the actual Bash SSH server, independent OpenSSH client and unchanged
consumer execution observer. No synthetic authentication replies or topic credit.
"""
import argparse
import base64
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import shutil
import signal
import shlex
import socket
import stat
import subprocess
import sys
import termios
import time
import uuid

sys.dont_write_bytecode = True
HOME = Path('/tmp/parity-home')


def require(ok, reason):
    if not ok: raise RuntimeError(reason)


def check(ok, reason):
    if not ok: raise AssertionError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guard(args, receipt):
    require(__debug__ and platform.machine() == 'x86_64' and
            os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'root x86-64 guest required')
    require(Path.cwd() == Path('/tmp/parity-case') and os.environ.get('HOME') == str(HOME), 'guest scratch differs')
    token = str(uuid.UUID(args.expected_uuid))
    require(Path('/etc/bashos-parity-vm').read_text().strip() == token and
            Path('/run/bashos-parity-vm-identity').read_text().strip() == token, 'live guest UUID differs')
    command = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    require(b'/opt/bashos-parity/harness/guest.py' in command and token.encode() in command,
            'owned disposable evaluator required')
    require(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU' and
            platform.release() == receipt['kernel_release'], 'guest/kernel differs')


def controls(runtime, base):
    for pin in runtime.receipt['guest_tools'].values(): base.protected(pin['path'], pin['sha256'])
    ssh = runtime.receipt['guest_tools']['ssh']['path']
    keygen = runtime.receipt['guest_tools']['ssh-keygen']['path']
    version = runtime.command([ssh, '-V'])
    require(version.returncode == 0, 'independent OpenSSH version query failed')
    runtime.report['independent_openssh'] = {'version': version.stderr.decode(errors='replace'),
                                           'pins': runtime.receipt['guest_tools']}
    keys = {}
    for label in ('host', 'listed', 'unlisted'):
        path = runtime.trusted / ('ssh-' + label)
        require(runtime.command([keygen, '-q', '-t', 'ed25519', '-N', '', '-f', path]).returncode == 0,
                'independent key generation failed')
        keys[label] = path
    authorized = runtime.root / 'av2root/.ssh'
    authorized.mkdir(mode=0o700)
    key_file = authorized / 'authorized_keys'
    runtime.install(key_file, b'')
    public = keys['listed'].with_suffix('.pub').read_bytes().rstrip(b'\n')
    requested = 'ssh-requested-command'
    line = lambda options: (options.encode() + b' ' if options else b'') + public + b'\n'
    at_limit = '127.0.0.1,' + 'x' * (511 - len('127.0.0.1,'))
    cases = [
        ('listed-key', line(''), True, requested, 'listed'),
        ('unlisted-key', line(''), False, None, 'unlisted'),
        ('from-exact', line('from="127.0.0.1"'), True, requested, 'listed'),
        ('from-wildcard', line('from="127.*"'), True, requested, 'listed'),
        ('from-other-address', line('from="192.0.2.*"'), False, None, 'listed'),
        ('from-exclusion-after-positive', line('from="*,!127.0.0.1"'), False, None, 'listed'),
        ('from-exclusion-before-positive', line('from="!127.0.0.1,*"'), False, None, 'listed'),
        ('from-negative-only', line('from="!192.0.2.*"'), False, None, 'listed'),
        ('from-511-byte-boundary', line('from="' + at_limit + '"'), True, requested, 'listed'),
        ('from-512-byte-refused', line('from="' + at_limit + 'x"'), False, None, 'listed'),
        ('forced-command', line('command="forced command with spaces"'), True, 'forced command with spaces', 'listed'),
        ('forced-command-1023-byte-boundary', line('command="' + 'x' * 1023 + '"'), True, 'x' * 1023, 'listed'),
        ('forced-command-1024-byte-refused', line('command="' + 'x' * 1024 + '"'), False, None, 'listed'),
        ('options-2048-plus-refused', line('command="' + 'x' * 2040 + '"'), False, None, 'listed'),
        ('duplicate-command-refused', line('command="first",command="second"'), False, None, 'listed'),
        ('quoted-command-trailing-junk', line('command="forced"junk'), False, None, 'listed'),
        ('boolean-option-value-refused', line('no-pty=ignored'), False, None, 'listed'),
        ('unknown-restriction-refused', line('no-fixture-unknown'), False, None, 'listed'),
        ('empty-option-refused', line('no-pty,,no-agent-forwarding'), False, None, 'listed'),
        ('trailing-option-comma-refused', line('no-pty,'), False, None, 'listed'),
        ('overlong-physical-line-refused', b'#' + b'x' * 8190 + public + b'\n', False, None, 'listed'),
        ('nul-physical-line-refused', public + b'\0ignored\n', False, None, 'listed'),
        ('bad-record-drained-next-valid-key', b'#' + b'x' * 8190 + public + b'\n' + line(''), True, requested, 'listed'),
        ('final-record-without-newline', public, True, requested, 'listed'),
    ]
    runtime.report['control_inventory'] = [row[0] for row in cases]
    for label, record_bytes, allowed, target_command, key_name in cases:
        def scenario(label=label, record_bytes=record_bytes, allowed=allowed,
                     target_command=target_command, key_name=key_name):
            key_file.write_bytes(record_bytes)
            check(key_file.read_bytes() == record_bytes and stat.S_IMODE(key_file.stat().st_mode) == 0o600,
                  'authorized key fixture bytes/mode differ')
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]; listener.close()
            policy = runtime.root / ('ssh-restriction-' + label + '.conf')
            runtime.install(policy, b'PasswordAuthentication no\nPermitRootLogin prohibit-password\nLoginGraceTime 12\nMaxAuthTries 1\n')
            options = ['sshd', 'run', '--encrypted', '--authority-v2', '--authority-v2-qualification',
                       '--once', '-a', '127.0.0.1', '-p', str(port), '-k', str(keys['host']),
                       '-F', str(policy), '--auth-method', 'publickey', '-u', 'av2root']
            want = base.expected(int(allowed), 0, 0, False)
            directory, config = runtime.config('restriction-' + label,
                ['--noprofile', '--norc', '-c', shlex.join(options)], want)
            (directory / 'authorized_keys.input').write_bytes(record_bytes)
            output = (directory / 'server-output.bin').open('wb')
            server = subprocess.Popen(['/usr/bin/python3', '-B', str(runtime.artifacts / 'consumer-observer.py'), str(config)],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                env=runtime.environment, start_new_session=True)
            try:
                deadline = time.monotonic() + 8
                while True:
                    require(server.poll() is None and time.monotonic() < deadline, 'SSH listener did not start')
                    rows = Path('/proc/net/tcp').read_text().splitlines()[1:]
                    if any(row.split()[1].split(':')[1] == '%04X' % port and row.split()[3] == '0A' for row in rows): break
                    time.sleep(.02)
                argv = [ssh, '-vv', '-E', str(directory / 'client-debug.txt'), '-F', '/dev/null',
                        '-p', str(port), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                        '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                        '-o', 'RequestTTY=no', '-o', 'PreferredAuthentications=publickey',
                        '-o', 'PubkeyAuthentication=yes', '-o', 'IdentitiesOnly=yes',
                        '-o', 'PasswordAuthentication=no', '-i', str(keys[key_name]),
                        'av2root@127.0.0.1', requested]
                (directory / 'client-argv.json').write_text(json.dumps(argv, indent=2) + '\n')
                client = runtime.terminal(argv, directory, [], timeout=25)
                server_status = server.wait(timeout=10)
                exchange = {'server_status': server_status, 'client_status': client['exit_code'],
                            'authorized_keys_sha256': sha(key_file), 'allowed': allowed}
                (directory / 'exchange.json').write_text(json.dumps(exchange, indent=2) + '\n')
                verdict = runtime.trace_result(directory, want)
                check(server_status == (0 if allowed else 1), 'SSH connection status differs')
                check(client['exit_code'] == (37 if allowed else 255), 'independent SSH client status differs')
                events = [json.loads(row) for row in (directory / 'trace.jsonl').read_text().splitlines()]
                check(not any(row.get('identity_operation') for row in events), 'key-only case invoked password authority')
                completed = [row for row in client['transcript'].splitlines() if b'AUTHORITY_TARGET_V2 ' in row]
                check(len(completed) == int(allowed), 'actual SSH target count differs')
                if allowed:
                    value = json.loads(completed[0].split(b'AUTHORITY_TARGET_V2 ', 1)[1])
                    check(value['uid'] == [0] * 3 and value['gid'] == [0] * 3 and value['groups'] == [0],
                          'actual key-authenticated target credentials differ')
                    argv_seen = [bytes.fromhex(item).decode() for item in value['argv_hex']]
                    check(argv_seen[1:] == ['-c', target_command], 'forced/requested command bytes differ')
                output.flush()
                text = (directory / 'server-output.bin').read_bytes()
                check((b'accepted publickey for av2root' in text) == allowed, 'SSH authentication acknowledgement differs')
                return dict(exchange, verdict=verdict)
            finally:
                if server.poll() is None: os.killpg(server.pid, signal.SIGKILL); server.wait()
                output.close()
        runtime.note('ssh-restriction-' + label, scenario, 'actual-encrypted-ssh')



def main():
    parser = argparse.ArgumentParser()
    for name in ('receipt', 'bash', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('receipt-sha256', 'bash-sha256', 'expected-uuid'): parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(sha(args.receipt) == args.receipt_sha256, 'receipt pin differs')
    receipt = json.loads(args.receipt.read_text())
    require(receipt['schema'] == 1 and receipt['kind'] == 'authority-consumer-v2-build-only' and
            receipt.get('ssh_restrictions_overlay', {}).get('name') == 'ssh-restrictions-r1' and
            receipt.get('login_state_overlay', {}).get('name') == 'login-state-ssh-merge-r1',
            'wrong additive SSH restriction receipt')
    guard(args, receipt)
    artifacts = args.receipt.resolve().parent
    require(args.output.is_absolute() and args.output.resolve().is_relative_to(HOME) and not args.output.exists(),
            'fresh private output required')
    for name, pin in receipt['files'].items():
        path = artifacts / name
        require(Path(name).name == name and path.is_file() and not path.is_symlink() and
                sha(path) == pin['sha256'] and path.stat().st_size == pin['bytes'], 'artifact pin differs')
        info = path.stat(); require(info.st_uid == 0 and not info.st_mode & 0o022, 'artifact not protected')
    require(sha(Path(__file__)) == receipt['files']['guest-ssh-restrictions.py']['sha256'], 'driver source pin differs')
    spec = importlib.util.spec_from_file_location('identity_consumers', artifacts / 'guest-consumers.py')
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    base.protected(args.bash, args.bash_sha256)
    require(args.bash.is_absolute(), 'absolute candidate required')
    args.output.mkdir(mode=0o700)
    runtime = base.Runtime(args, receipt)
    runtime.report.update(suite='ssh-restrictions-r1', original_topic_credit=0)
    before = runtime.command(['/usr/bin/dmesg', '--raw'])
    require(before.returncode == 0, 'kernel log unavailable')
    (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        runtime.prepare(); controls(runtime, base)
        require(len(runtime.cases) == 24 and all(row['status'] == 'PASS' for row in runtime.cases), 'control inventory incomplete')
        runtime.report.update(status='PASS', control_counts={'actual_encrypted_ssh': 24, 'existing_negative_observers_required_separately': 7})
    except AssertionError as error: runtime.report.update(status='FAIL', reason=str(error))
    except Exception as error: runtime.report.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error))
    finally:
        # Preserve a reached case failure if a later teardown/kernel gate also
        # errors, as in the pinned SSH baseline. Every gate remains mandatory.
        runtime.report['behavior_status'] = runtime.report['status']
        runtime.report['secondary_failures'] = []
        try:
            runtime.cleanup()
            runtime.report['cleanup_status'] = 'PASS'
        except Exception as error:
            runtime.report['cleanup_status'] = 'ERROR'
            runtime.report['secondary_failures'].append({'phase': 'cleanup', 'reason': repr(error)})
        try:
            after = runtime.command(['/usr/bin/dmesg', '--raw'])
            require(after.returncode == 0 and after.stdout.startswith(before.stdout), 'kernel log lost/wrapped')
            delta = after.stdout[len(before.stdout):]
            (args.output / 'dmesg-after.txt').write_bytes(after.stdout); (args.output / 'dmesg-delta.txt').write_bytes(delta)
            bad = (b'WARNING:', b'BUG:', b'KASAN:', b'KCSAN:', b'UBSAN:', b'held lock', b'Oops:',
                   b'possible recursive locking', b'inconsistent lock state', b'general protection fault', b'INFO: task ')
            require(not any(term.lower() in delta.lower() for term in bad), 'kernel diagnostic failure')
            runtime.report['kernel_status'] = 'PASS'
        except Exception as error:
            runtime.report['kernel_status'] = 'ERROR'
            runtime.report['secondary_failures'].append({'phase': 'kernel', 'reason': repr(error)})
        if runtime.report['secondary_failures'] and runtime.report['behavior_status'] == 'PASS':
            runtime.report['status'] = 'ERROR'
        runtime.report['qualification_eligible'] = (runtime.report['status'] == 'PASS' and
                                                   not runtime.report['secondary_failures'])
        (args.output / 'commands.json').write_text(json.dumps(runtime.commands, indent=2) + '\n')
        (args.output / 'report.json').write_text(json.dumps(runtime.report, indent=2) + '\n')
    print(json.dumps({'status': runtime.report['status'], 'report': str(args.output / 'report.json')}))
    return 0 if runtime.report['status'] == 'PASS' else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error:
        print('SSH restrictions preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
