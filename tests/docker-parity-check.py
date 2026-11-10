#!/usr/bin/env python3
"""Integration checks against real Docker images, including live capture and replay."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import sys
import termios
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workspace', required=True, type=Path)
    p.add_argument('--reference', default='bash-os:parity-debian')
    p.add_argument('--candidate', default='bash-os:parity-bash-os')
    args = p.parse_args()
    work = args.workspace.resolve() / 'results' / ('validation-' + uuid.uuid4().hex[:8])
    work.mkdir(parents=True)
    runner = [sys.executable, str(ROOT / 'scripts/docker-parity.py')]
    common = ['--workspace', str(args.workspace.resolve()), '--reference', args.reference,
              '--candidate', args.candidate]
    records = []

    def check(name, script=None, extra=(), expected=0, difference=None, mode='run'):
        command = runner + [mode] + common + ['--output', str(work / name)]
        if script is not None:
            source = work / (name + '.sh')
            source.write_text(script)
            command += ['--script', str(source)]
        command += list(extra)
        result = subprocess.run(command, capture_output=True, timeout=60)
        report = json.loads((work / name / 'report.json').read_text())
        assert result.returncode == expected, (name, result.returncode, report)
        assert report['passed'] == (expected == 0), (name, report)
        if difference:
            assert any(difference in item for item in report['differences']), (name, report)
        records.append({'name': name, 'passed': True, 'report': str(work / name / 'report.json')})
        print('PASS', name, flush=True)
        return work / name

    # Archive-only storage is refused before anything is created, even through a symlink.
    archive = work / 'archive'
    archive.mkdir()
    os.symlink(archive, work / 'archive-link')
    result = subprocess.run(runner + ['run', '--workspace', str(work / 'archive-link/ws'),
                                      '--script', str(ROOT / 'tests/docker-parity/hello-world.sh')],
                            capture_output=True, timeout=60,
                            env=dict(os.environ, BASH_OS_ARCHIVE_PATHS='/nonexistent:' + str(archive)))
    assert result.returncode == 2 and b'archive-only storage' in result.stderr, result
    assert not any(archive.iterdir()), list(archive.iterdir())
    records.append({'name': 'archive-path-refused', 'passed': True})

    hello = check('hello-world', (ROOT / 'tests/docker-parity/hello-world.sh').read_text())
    for side in ('reference', 'candidate'):
        assert (hello / side / 'stdout').read_bytes() == b'Hello, world!\n'
        assert (hello / side / 'stderr').read_bytes() == b''

    fixture = work / 'initial'
    fixture.mkdir()
    (fixture / 'data').write_bytes(b'initial\0bytes\n')
    os.link(fixture / 'data', fixture / 'hard')
    os.symlink('data', fixture / 'link')
    payload = work / 'payload'
    payload.write_bytes(b'hello data\n')
    smoke = check('batch', (ROOT / 'tests/docker-parity/smoke.sh').read_text(),
                  ['--arg=two words', '--stdin', str(payload), '--fixture', str(fixture)])
    assert (fixture / 'data').read_bytes() == b'initial\0bytes\n'
    for side in ('reference', 'candidate'):
        tree = smoke / side / 'tree'
        assert (tree / 'data').stat().st_ino == (tree / 'hard').stat().st_ino
    command = json.loads((smoke / 'replay-command.json').read_text())
    command += ['--output', str(work / 'batch-reproduced')]
    subprocess.run(command, check=True, capture_output=True, timeout=60)
    records.append({'name': 'saved-input-reproduction', 'passed': True})
    check('stdout-difference', 'type -t cat\n', expected=1, difference='stdout bytes')
    check('stderr-difference', 'type -t cat >&2\n', expected=1, difference='stderr bytes')
    check('status-difference', '[[ $(type -t cat) == builtin ]]\n', expected=1, difference='exit status')
    check('filesystem-difference', 'type -t cat > result\n', expected=1,
          difference='filesystem contents')
    check('root-mode-difference', 'if [[ $(type -t cat) == builtin ]]; then chmod 700 .; else chmod 755 .; fi\n',
          expected=1, difference='filesystem contents')
    # Entries the test makes unreadable are still compared, and keep their modes.
    check('unreadable-directory-difference', 'mkdir d; type -t cat > d/f; chmod 0 d\n',
          expected=1, difference='filesystem contents')
    check('unreadable-file-difference', 'type -t cat > f; chmod 0 f\n',
          expected=1, difference='filesystem contents')
    sealed = check('unreadable-match', 'mkdir d; printf same > d/f; chmod 0 d/f d .\n')
    for side in ('reference', 'candidate'):
        tree = sealed / side / 'tree'
        assert tree.stat().st_mode & 0o777 == 0, side
        tree.chmod(0o700)
        assert (tree / 'd').stat().st_mode & 0o777 == 0, side
        (tree / 'd').chmod(0o700)
        assert (tree / 'd/f').stat().st_mode & 0o777 == 0, side
    check('reference-failure', 'exit 7\n', expected=1, difference='reference exit 7')
    check('timeout', 'while :; do :; done\n', ['--timeout', '1'], expected=1,
          difference='did not complete normally')
    payload.write_bytes(b'a\0b\n')
    check('binary-input', "IFS= read -r -d '' a; IFS= read -r b; printf '<%s><%s>\\n' \"$a\" \"$b\"; if read -r c; then exit 8; fi\n",
          ['--stdin', str(payload)])
    check('interactive', extra=['--events', str(ROOT / 'tests/docker-parity/interactive.json'),
                               '--timeout', '5'], mode='replay')
    events = work / 'eof.json'
    events.write_text(json.dumps([{'expect': 'parity> '}, {'eof': True}]))
    check('terminal-eof', extra=['--events', str(events), '--timeout', '5'], mode='replay')
    events = work / 'signal.json'
    events.write_text(json.dumps([
        {'expect': 'parity> '},
        {'send': "trap 'printf signal-received' INT\n"}, {'expect': 'parity> '},
        {'signal': 'SIGINT'}, {'expect': 'signal-received'},
        {'send': 'exit 0\n'}]))
    check('terminal-signal', extra=['--events', str(events), '--timeout', '5'], mode='replay')
    events = work / 'missing-checkpoint.json'
    events.write_text(json.dumps([{'expect': 'parity> '}, {'expect': 'never-present', 'timeout': 0.2}]))
    check('terminal-timeout', extra=['--events', str(events), '--timeout', '5'],
          expected=2, mode='replay')
    events = work / 'terminal-difference.json'
    events.write_text(json.dumps([{'expect': 'parity> '},
                                 {'send': 'type -t cat\n'}, {'expect': 'parity> '},
                                 {'send': 'exit 0\n'}]))
    check('terminal-difference', extra=['--events', str(events), '--timeout', '5'],
          expected=1, difference='terminal bytes', mode='replay')

    incomplete = work / 'incomplete-suite-source'
    (incomplete / 'scripts').mkdir(parents=True)
    (incomplete / 'tests').mkdir()
    shutil.copyfile(ROOT / 'scripts/docker-parity.py', incomplete / 'scripts/docker-parity.py')
    shutil.copyfile(ROOT / 'tests/compare-parity.py', incomplete / 'tests/compare-parity.py')
    (incomplete / 'tests/bash-gnu-parity.sh').write_text('exit 0\n')
    result = subprocess.run([sys.executable, str(incomplete / 'scripts/docker-parity.py'),
                             'suite', *common, '--output', str(work / 'incomplete-suite')],
                            capture_output=True, timeout=60)
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert not json.loads((work / 'incomplete-suite/report.json').read_text())['passed']
    records.append({'name': 'incomplete-suite', 'passed': True})

    # Exercise the human-facing recorder through an actual controlling PTY.
    master, slave = pty.openpty()
    termios.tcsetwinsize(slave, (24, 80))
    process = subprocess.Popen(runner + ['live'] + common + ['--output', str(work / 'live'),
                                                          '--timeout', '5'],
                               stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    transcript = bytearray()
    cursor = 0
    def wait_for(needle):
        nonlocal cursor
        deadline = time.monotonic() + 20
        while needle not in transcript[cursor:]:
            assert time.monotonic() < deadline, ('live timeout', transcript)
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                transcript.extend(os.read(master, 65536))
        cursor = transcript.index(needle, cursor) + len(needle)
    try:
        wait_for(b'parity> ')
        # Allow the recorder to switch its own terminal into raw mode.
        time.sleep(0.2)
        os.write(master, b"v=live; printf 'capture=%s\\n' \"$v\"\n")
        wait_for(b'capture=live\r\n')
        wait_for(b'parity> ')
        termios.tcsetwinsize(master, (32, 96))
        process.send_signal(signal.SIGWINCH)
        time.sleep(0.2)
        os.write(master, b"printf 'size=%s,%s\\n' \"$LINES\" \"$COLUMNS\"; exit 0\n")
        wait_for(b'size=32,96\r\n')
        assert process.wait(timeout=20) == 0, transcript
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        os.close(master)
    (work / 'live-controller.log').write_bytes(transcript)
    report = json.loads((work / 'live/report.json').read_text())
    assert report['passed'], report
    command = json.loads((work / 'live/replay-command.json').read_text())
    command += ['--output', str(work / 'live-replayed')]
    result = subprocess.run(command, capture_output=True, timeout=60)
    assert result.returncode == 0, (result.stdout, result.stderr)
    records.append({'name': 'live-capture-resize-replay', 'passed': True})

    master, slave = pty.openpty()
    original_terminal = termios.tcgetattr(master)
    process = subprocess.Popen(runner + ['live'] + common + ['--output', str(work / 'live-aborted'),
                                                          '--timeout', '5'],
                               stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    transcript, cursor = bytearray(), 0
    try:
        wait_for(b'parity> ')
        time.sleep(0.2)
        os.write(master, b'\x1d')
        assert process.wait(timeout=15) == 2
        assert termios.tcgetattr(master) == original_terminal
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=15)
        os.close(master)
    assert not json.loads((work / 'live-aborted/report.json').read_text())['passed']
    records.append({'name': 'live-abort-terminal-restoration', 'passed': True})

    # Closing the controlling terminal (a real hangup, not a sent signal) must
    # still stop the session, report no pass and remove both containers.
    def controlling_terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    master, slave = pty.openpty()
    termios.tcsetwinsize(slave, (24, 80))
    process = subprocess.Popen(runner + ['live'] + common + ['--output', str(work / 'live-hangup'),
                                                          '--timeout', '5'],
                               stdin=slave, stdout=slave, stderr=slave,
                               preexec_fn=controlling_terminal)
    os.close(slave)
    transcript, cursor = bytearray(), 0
    try:
        wait_for(b'parity> ')
        time.sleep(0.2)
        os.close(master)
        master = None
        assert process.wait(timeout=30) == 2, process.returncode
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=15)
        if master is not None:
            os.close(master)
    report = json.loads((work / 'live-hangup/report.json').read_text())
    assert report['status'] == 'error' and not report['passed'], report
    records.append({'name': 'live-hangup-cleanup', 'passed': True})

    # A terminal that reports no size still runs; the shells keep Docker's default.
    master, slave = pty.openpty()
    process = subprocess.Popen(runner + ['live'] + common + ['--output', str(work / 'live-unsized'),
                                                          '--timeout', '5'],
                               stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    transcript, cursor = bytearray(), 0
    try:
        wait_for(b'parity> ')
        time.sleep(0.2)
        os.write(master, b'exit 0\n')
        assert process.wait(timeout=20) == 0, transcript
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=15)
        os.close(master)
    events = json.loads((work / 'live-unsized/events.json').read_text())
    assert not any('resize' in event for event in events), events
    records.append({'name': 'live-unsized-terminal', 'passed': True})

    process = subprocess.Popen(runner + ['run'] + common + ['--output', str(work / 'terminated'),
                                '--script', str(work / 'timeout.sh'), '--timeout', '60'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            paths = [work / 'terminated' / side / 'container.json' for side in ('reference', 'candidate')]
            if all(path.exists() for path in paths):
                names = [json.loads(path.read_text())['name'] for path in paths]
                states = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.Running}}', *names], text=True)
                if states.splitlines() == ['true', 'true']:
                    break
            assert time.monotonic() < deadline, 'containers did not start before interruption test'
            time.sleep(0.05)
        process.terminate()
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 2, (stdout, stderr)
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=15)
    assert not json.loads((work / 'terminated/report.json').read_text())['passed']
    records.append({'name': 'driver-termination-cleanup', 'passed': True})
    # Names are retained in evidence; prove every container made here was removed.
    remaining = set(subprocess.check_output(['docker', 'ps', '-a', '--format', '{{.Names}}'], text=True).splitlines())
    for path in work.rglob('container.json'):
        assert json.loads(path.read_text())['name'] not in remaining, path
    (work / 'validation.json').write_text(json.dumps(records, indent=2) + '\n')
    print(f'{len(records)} integration checks passed; evidence: {work}', flush=True)


if __name__ == '__main__':
    main()
