#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Encrypted SSH completion controls; attested disposable guest execution only.

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
    # A completed first channel is not permission to terminate a connection
    # carrying another channel. Conversely, authentication alone is not a
    # completed session for the server's --once completion status.
    for channels in (0, 2):
        label = 'auth-only-close-refused' if channels == 0 else 'two-command-channels-complete'
        def multiplex(channels=channels, label=label):
            key_file.write_bytes(line(''))
            listener = socket.socket(); listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]; listener.close()
            policy = runtime.root / ('ssh-lifetime-' + label + '.conf')
            runtime.install(policy, b'PasswordAuthentication no\nPermitRootLogin prohibit-password\nLoginGraceTime 12\nMaxAuthTries 1\n')
            options = ['sshd', 'run', '--encrypted', '--authority-v2', '--authority-v2-qualification',
                       '--once', '-a', '127.0.0.1', '-p', str(port), '-k', str(keys['host']),
                       '-F', str(policy), '--auth-method', 'publickey', '-u', 'av2root']
            want = base.expected(channels, 0, 0, False)
            directory, config = runtime.config('lifetime-' + label,
                ['--noprofile', '--norc', '-c', shlex.join(options)], want)
            # Keep the UNIX socket below sockaddr_un's path limit.
            control = runtime.root / ('mux' + str(channels))
            output = (directory / 'server-output.bin').open('wb')
            master_out = (directory / 'master-output.bin').open('wb')
            server = subprocess.Popen(['/usr/bin/python3', '-B', str(runtime.artifacts / 'consumer-observer.py'), str(config)],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                env=runtime.environment, start_new_session=True)
            master = None
            try:
                deadline = time.monotonic() + 8
                while True:
                    require(server.poll() is None and time.monotonic() < deadline, 'SSH listener did not start')
                    rows = Path('/proc/net/tcp').read_text().splitlines()[1:]
                    if any(row.split()[1].split(':')[1] == '%04X' % port and row.split()[3] == '0A' for row in rows): break
                    time.sleep(.02)
                client_options = [ssh, '-F', '/dev/null', '-p', str(port), '-S', str(control),
                    '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'BatchMode=yes',
                    '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
                    '-o', 'IdentitiesOnly=yes', '-i', str(keys['listed'])]
                master_argv = [*client_options, '-M', '-N', '-vv', '-E', str(directory / 'master-debug.txt'),
                               'av2root@127.0.0.1']
                (directory / 'master-argv.json').write_text(json.dumps(master_argv, indent=2) + '\n')
                master = subprocess.Popen(master_argv, stdin=subprocess.DEVNULL, stdout=master_out,
                                          stderr=subprocess.STDOUT, env=runtime.environment, start_new_session=True)
                deadline = time.monotonic() + 8
                while not control.exists():
                    require(master.poll() is None and server.poll() is None and time.monotonic() < deadline,
                            'independent multiplex authentication did not complete')
                    time.sleep(.02)
                for index in range(channels):
                    wanted = 'sequential-command-' + str(index)
                    result = runtime.command([*client_options, 'av2root@127.0.0.1', wanted])
                    (directory / ('channel-%d.stdout' % index)).write_bytes(result.stdout)
                    check(result.returncode == 37, 'multiplex command status differs')
                    records = [r for r in result.stdout.splitlines() if b'AUTHORITY_TARGET_V2 ' in r]
                    check(len(records) == 1, 'multiplex target record absent/duplicated')
                    value = json.loads(records[0].split(b'AUTHORITY_TARGET_V2 ', 1)[1])
                    check(value['uid'] == [0] * 3 and value['gid'] == [0] * 3 and value['groups'] == [0],
                          'multiplex target IDs differ')
                    check([bytes.fromhex(a).decode() for a in value['argv_hex']][1:] == ['-c', wanted],
                          'multiplex command bytes differ')
                    check(server.poll() is None, 'server exited before the owned SSH connection finished')
                closed = runtime.command([*client_options, '-O', 'exit', 'av2root@127.0.0.1'])
                require(closed.returncode == 0, 'independent multiplex close failed')
                master_status = master.wait(timeout=10)
                server_status = server.wait(timeout=10)
                verdict = runtime.trace_result(directory, want)
                output.flush()
                check((directory / 'server-output.bin').read_bytes().count(b'accepted publickey for av2root') == 1,
                      'one authentication per multiplex connection required')
                check(master_status == 0 and server_status == (0 if channels else 1),
                      'completed versus auth-only connection status differs')
                return {'channels': channels, 'server_status': server_status,
                        'master_status': master_status, 'verdict': verdict}
            finally:
                if master is not None and master.poll() is None:
                    master.kill(); master.wait()
                if server.poll() is None: os.killpg(server.pid, signal.SIGKILL); server.wait()
                output.close(); master_out.close()
        runtime.note('ssh-lifetime-' + label, multiplex, 'actual-encrypted-ssh')


def main():
    parser = argparse.ArgumentParser()
    for name in ('receipt', 'bash', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('receipt-sha256', 'bash-sha256', 'expected-uuid'): parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(sha(args.receipt) == args.receipt_sha256, 'receipt pin differs')
    receipt = json.loads(args.receipt.read_text())
    require(receipt['schema'] == 1 and receipt['kind'] == 'authority-consumer-v2-build-only' and
            receipt.get('ssh_completion_overlay', {}).get('name') == 'ssh-completion-r1' and
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
    require(sha(Path(__file__)) == receipt['files']['guest-ssh-completion.py']['sha256'], 'driver source pin differs')
    spec = importlib.util.spec_from_file_location('identity_consumers', artifacts / 'guest-consumers.py')
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    base.protected(args.bash, args.bash_sha256)
    require(args.bash.is_absolute(), 'absolute candidate required')
    args.output.mkdir(mode=0o700)
    runtime = base.Runtime(args, receipt)
    runtime.report.update(suite='ssh-completion-r1', original_topic_credit=0)
    before = runtime.command(['/usr/bin/dmesg', '--raw'])
    require(before.returncode == 0, 'kernel log unavailable')
    (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        runtime.prepare(); controls(runtime, base)
        require(len(runtime.cases) == 2 and all(row['status'] == 'PASS' for row in runtime.cases), 'control inventory incomplete')
        runtime.report.update(status='PASS', control_counts={'actual_encrypted_ssh': 2, 'existing_negative_observers_required_separately': 7})
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
        print('SSH completion preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
