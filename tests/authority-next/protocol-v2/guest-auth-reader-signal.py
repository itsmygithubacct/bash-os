#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Authentication reader signal ownership controls; attested disposable guest execution only.

Uses actual Bash read-secret and the unchanged real-terminal observer, plus
explicitly classified injected current/baseline source-mechanics checks.
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


def terminal(self, command, directory, inputs, timeout=45, extra_env=None):
    master, slave = pty.openpty(); tty = os.ttyname(slave)
    env = dict(self.environment, V2_TTY=tty, **(extra_env or {}))
    def child_setup():
        os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                               env=env, preexec_fn=child_setup, close_fds=True)
    data, sent, echo = bytearray(), 0, []
    cursor, deadline, signal_at = 0, time.monotonic() + timeout, None
    try:
        while True:
            require(time.monotonic() < deadline, 'terminal consumer timeout')
            ready, _, _ = select.select([master], [], [], .05)
            if ready:
                try: block = os.read(master, 65536)
                except OSError as failure:
                    if failure.errno == errno.EIO: block = b''
                    else: raise
                if block: data.extend(block)
            if sent < len(inputs):
                prompt, answer, secret = inputs[sent]
                offset = data.lower().find(prompt.lower(), cursor)
                if offset >= 0:
                    is_echo = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
                    echo.append({'prompt': prompt.decode(), 'secret': secret, 'echo': is_echo})
                    if secret: check(not is_echo, 'password terminal echo enabled')
                    if isinstance(answer, dict):
                        matches = re.findall(rb'LOGIN_ACTOR=([0-9]+)', data)
                        require(len(matches) == 1, 'one declared login actor required')
                        actor = int(matches[0]); actor_fd = os.pidfd_open(actor)
                        try:
                            status = dict(line.split(':', 1) for line in Path('/proc/%d/status' % actor).read_text().splitlines())
                            require(int(status['PPid']) == process.pid and
                                    list(map(int, status['Uid'].split())) == [0] * 4,
                                    'signal target must be the owned root observer child')
                            if 'queued_input' in answer:
                                require(type(answer['queued_input']) is bytes and
                                        len(answer['queued_input']) <= 256, 'bounded queued input required')
                                signal.pidfd_send_signal(actor_fd, signal.SIGSTOP)
                                try:
                                    stopped_deadline = time.monotonic() + 1
                                    while True:
                                        state = Path('/proc/%d/status' % actor).read_text()
                                        if re.search(r'^State:\s+[Tt]\b', state, re.M): break
                                        require(time.monotonic() < stopped_deadline, 'owned actor did not stop')
                                        time.sleep(.005)
                                    require(not termios.tcgetattr(slave)[3] & termios.ECHO,
                                            'queued password input must remain hidden')
                                    require(os.write(master, answer['queued_input']) == len(answer['queued_input']),
                                            'queued input write incomplete')
                                    signal.pidfd_send_signal(actor_fd, answer['signal'])
                                finally:
                                    signal.pidfd_send_signal(actor_fd, signal.SIGCONT)
                            else:
                                signal.pidfd_send_signal(actor_fd, answer['signal'])
                            signal_at = time.monotonic()
                        finally:
                            os.close(actor_fd)
                    else:
                        os.write(master, answer + b'\n')
                    cursor = len(data); sent += 1
            if process.poll() is not None:
                # Drain queued output while the slave remains open here.
                while select.select([master], [], [], .05)[0]:
                    try: block = os.read(master, 65536)
                    except OSError: break
                    if not block: break
                    data.extend(block)
                break
        restored = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
        for _, answer, secret in inputs:
            if secret and isinstance(answer, bytes): check(answer not in data, 'password was echoed or printed')
        return {'exit_code': process.returncode, 'transcript': bytes(data), 'tty': tty,
                'echo': echo, 'echo_restored': restored, 'input_complete': sent == len(inputs),
                'signal_return_seconds': time.monotonic() - signal_at if signal_at is not None else None}
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL); process.wait()
        (directory / 'transcript.bin').write_bytes(data)
        os.close(master); os.close(slave)

def controls(runtime, base):
    script = ('unset H\nauth open-v2-qualification FD || exit 91\n'
              'auth read-secret "$FD" -p "Reader password: " H\n'
              '[[ $? != 0 && -z ${H+x} ]] || exit 97\nexit 1\n')
    def no_echo_setup_fault():
        result = runtime.bash_case('auth-reader-hide-fault', script, base.expected(fault='tty-hide'),
                                   fault='tty-hide', wanted_status=1)
        check(b'Reader password: ' not in result['transcript'], 'failed suppression reached password input')
        events = [json.loads(row) for row in (runtime.output / 'auth-reader-hide-fault/trace.jsonl').read_text().splitlines()]
        check(not any(row.get('identity_operation') for row in events), 'reader setup fault reached authentication')
        return {'selected_real_terminal_fault': 1, 'password_prompt': False}
    runtime.note('auth-reader-refuses-failed-terminal-suppression', no_echo_setup_fault)
    for name, sig in [('hup', signal.SIGHUP), ('term', signal.SIGTERM), ('int', signal.SIGINT)]:
        def cancel(name=name, sig=sig):
            code = ('unset H\ncaught=0\ntrap \'caught=$((caught+1))\' HUP TERM INT\n'
                    'printf "LOGIN_ACTOR=%s\\n" "$$"\nauth open-v2-qualification FD || exit 91\n'
                    'auth read-secret "$FD" -p "Reader password: " H\n'
                    '[[ $? != 0 && -z ${H+x} && $caught == 1 ]] || exit 96\n'
                    'kill -SIGNAL_NAME "$$"\n[[ $caught == 2 ]] || exit 97\nprintf "READER_HANDLERS_RESTORED\\n"\n'.replace('SIGNAL_NAME', name.upper()))
            result = runtime.bash_case('auth-reader-cancel-' + name, code, base.expected(),
                [(b'Reader password: ', {'signal': sig}, True)])
            check(b'READER_HANDLERS_RESTORED' in result['transcript'] and
                  result['signal_return_seconds'] is not None and result['signal_return_seconds'] < 3,
                  'reader cancellation/handler restoration differs')
        runtime.note('auth-reader-cancellation-restores-' + name, cancel)
    for name, sig in [('hup', signal.SIGHUP), ('term', signal.SIGTERM), ('int', signal.SIGINT)]:
        def queued_cancel(name=name, sig=sig):
            code = ('unset H\ncaught=0\ntrap \'caught=$((caught+1))\' HUP TERM INT\n'
                    'printf "LOGIN_ACTOR=%s\\n" "$$"\nauth open-v2-qualification FD || exit 91\n'
                    'auth read-secret "$FD" -p "Reader queued password: " H\n'
                    '[[ $? != 0 && -z ${H+x} && $caught == 1 ]] || exit 96\n'
                    'TYPED=\nIFS= read -r -t 0.2 TYPED && exit 95\n'
                    '[[ -z $TYPED ]] || exit 94\n'
                    'kill -SIGNAL_NAME "$$"\n[[ $caught == 2 ]] || exit 97\n'
                    'printf "READER_QUEUE_FLUSHED\\n"\n'.replace('SIGNAL_NAME', name.upper()))
            result = runtime.bash_case('auth-reader-queued-cancel-' + name, code, base.expected(),
                [(b'Reader queued password: ', {'signal': sig, 'queued_input': b'queued-secret-must-not-reach-read\n'}, True)])
            check(b'READER_QUEUE_FLUSHED' in result['transcript'] and
                  b'queued-secret-must-not-reach-read' not in result['transcript'] and
                  result['signal_return_seconds'] is not None and result['signal_return_seconds'] < 3,
                  'queued input, cancellation, or restored trap differs')
        runtime.note('auth-reader-cancellation-flushes-queued-' + name, queued_cancel)
    for variant, count in [('current', 43), ('r1-negative', 43), ('original', 22)]:
        def mechanics(variant=variant, count=count):
            binary = 'reader-regressions-original' if variant == 'original' else 'signal-regressions-' + variant
            result = runtime.command([runtime.artifacts / binary, runtime.args.expected_uuid])
            (runtime.output / ('reader-' + variant + '.stdout')).write_bytes(result.stdout)
            (runtime.output / ('reader-' + variant + '.stderr')).write_bytes(result.stderr)
            records = [json.loads(row) for row in result.stdout.splitlines()]
            require(len(records) == count + 1 and records[-1].get('controls') == count and
                    records[-1].get('authentication_coverage') is False, 'mechanics output incomplete')
            cases = {row['id']: row for row in records[:-1]}
            require(len(cases) == count, 'mechanics ID inventory differs')
            if variant == 'current':
                check(result.returncode == 0 and records[-1]['failures'] == 0 and
                      all(row['status'] == 'PASS' for row in cases.values()), 'current source mechanics failed')
            elif variant == 'r1-negative':
                check(result.returncode == 1 and records[-1]['failures'] > 0 and
                      all(cases[name]['status'] == 'FAIL' and cases[name]['unsafe_delivery'] == 1
                          for name in ('restore1-signal', 'restore2-signal', 'restore3-signal', 'close-signal')) and
                      cases['bind-unwind']['status'] == 'FAIL',
                      'r1 source did not expose each restoration barrier and binding unwind failure')
            else:
                check(result.returncode == 1 and records[-1]['failures'] > 0 and
                      all(cases[name]['status'] == 'FAIL' for name in
                          ('lock-error', 'hide-error', 'signal2-error', 'restore-signal-error')),
                      'original source did not fail the unchanged setup/cleanup oracles')
            return {'source_mechanics_only': True, 'variant': variant, 'summary': records[-1]}
        runtime.note('auth-reader-source-mechanics-' + variant, mechanics, 'source-bound-mechanics')


def main():
    parser = argparse.ArgumentParser()
    for name in ('receipt', 'bash', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('receipt-sha256', 'bash-sha256', 'expected-uuid'): parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(sha(args.receipt) == args.receipt_sha256, 'receipt pin differs')
    receipt = json.loads(args.receipt.read_text())
    require(receipt['schema'] == 1 and receipt['kind'] == 'authority-consumer-v2-build-only' and
            receipt.get('auth_reader_overlay', {}).get('name') == 'auth-reader-signal-r1' and
            receipt.get('login_state_overlay', {}).get('name') == 'login-state-ssh-merge-r1',
            'wrong signal ownership reader receipt')
    guard(args, receipt)
    artifacts = args.receipt.resolve().parent
    require(args.output.is_absolute() and args.output.resolve().is_relative_to(HOME) and not args.output.exists(),
            'fresh private output required')
    for name, pin in receipt['files'].items():
        path = artifacts / name
        require(Path(name).name == name and path.is_file() and not path.is_symlink() and
                sha(path) == pin['sha256'] and path.stat().st_size == pin['bytes'], 'artifact pin differs')
        info = path.stat(); require(info.st_uid == 0 and not info.st_mode & 0o022, 'artifact not protected')
    require(sha(Path(__file__)) == receipt['files']['guest-auth-reader-signal.py']['sha256'], 'driver source pin differs')
    spec = importlib.util.spec_from_file_location('identity_consumers', artifacts / 'guest-consumers.py')
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    base.protected(args.bash, args.bash_sha256)
    require(args.bash.is_absolute(), 'absolute candidate required')
    args.output.mkdir(mode=0o700)
    class ReaderRuntime(base.Runtime):
        terminal = globals()['terminal']
    runtime = ReaderRuntime(args, receipt)
    runtime.report.update(suite='auth-reader-signal-r1', original_topic_credit=0)
    before = runtime.command(['/usr/bin/dmesg', '--raw'])
    require(before.returncode == 0, 'kernel log unavailable')
    (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        runtime.prepare(); controls(runtime, base)
        require(len(runtime.cases) == 10 and all(row['status'] == 'PASS' for row in runtime.cases), 'control inventory incomplete')
        runtime.report.update(status='PASS', control_counts={'actual_consumer': 7, 'source_mechanics_runs': 3, 'source_mechanics_cases': {'current': 43, 'r1-negative': 43, 'original': 22}, 'existing_negative_observers_required_separately': 7})
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
        print('Auth reader preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
