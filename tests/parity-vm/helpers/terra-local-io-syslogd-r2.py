#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only, bounded observers for bashsyslogd's private-file and datagram contracts.

The observer starts only a shell-under-test running the builtin, owns every
socket and child, and stores raw observations beneath the case/HOME scratch
trees. FIFO config replacement synchronizes SIGHUP with an actual config open:
a writer cannot open the FIFO until the daemon has started the reload, and it
closes the FIFO before the probe datagram is sent. Thus the probe cannot be
processed by the daemon until the reload has finished. Setup checks the
observer's kernel primitives and positive/negative line matching controls.
"""
import base64
import errno
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import traceback
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
WORK = CASE / 'w'
DEADLINE = None
PFX = None
CHILDREN = []


def guard():
    global DEADLINE, PFX
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU'
    assert Path.cwd() == CASE and os.geteuid() == 2000
    DEADLINE = time.monotonic() + 45
    PFX = (rb'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) '
           rb'[ 0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] ' +
           re.escape(socket.gethostname().encode()) + rb' ')


def record(kind, **fields):
    fields['kind'] = kind
    with (HOME / 'syslogd-observations.jsonl').open('a') as f:
        f.write(json.dumps(fields, sort_keys=True) + '\n')


def raw(data):
    return base64.b64encode(data[:65536]).decode()


def wait_for(predicate, seconds=4):
    end = min(DEADLINE, time.monotonic() + seconds)
    while True:
        value = predicate()
        if value or time.monotonic() >= end:
            return value
        time.sleep(.01)


def init():
    WORK.mkdir(mode=0o700)
    os.chmod(WORK, 0o700)


def alive(p):
    return p.poll() is None


def files():
    return {n: WORK / n for n in ('messages', 'syslog', 'auth', 'kern')}


def base_args(paths):
    return ['run', '--socket', str(WORK / 'sock'), '--output', str(paths['messages']),
            '--syslog', str(paths['syslog']), '--auth', str(paths['auth']),
            '--kern', str(paths['kern']), '--queue', str(WORK / 'queue')]


def start(shell, args, label):
    out = (WORK / (label + '.stdout')).open('wb')
    err = (WORK / (label + '.stderr')).open('wb')
    try:
        p = subprocess.Popen([shell, '--noprofile', '--norc', '-c',
                              'builtin bashsyslogd "$@"', 'fixture'] + args,
                             stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                             env=dict(os.environ), start_new_session=True)
    finally:
        out.close(); err.close()
    CHILDREN.append(p)
    record('start', label=label, pid=p.pid, argv=args)
    def bound():
        try:
            return stat.S_ISSOCK((WORK / 'sock').lstat().st_mode)
        except FileNotFoundError:
            return False
    if not wait_for(lambda: bound() or not alive(p)) or not bound():
        raise RuntimeError('daemon never bound socket; exit=%s' % p.poll())
    return p


def finish(p, label, request_stop=True):
    forced = False
    if alive(p) and request_stop:
        p.send_signal(signal.SIGTERM)
    try:
        status = p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        forced = True
        p.kill()
        status = p.wait(timeout=3)
    out = (WORK / (label + '.stdout')).read_bytes()
    err = (WORK / (label + '.stderr')).read_bytes()
    record('finish', label=label, status=status, forced=forced,
           stdout_base64=raw(out), stderr_base64=raw(err),
           socket_exists=(WORK / 'sock').exists())
    return status == 0 and not forced, err


def send(sender, message):
    count = sender.sendto(message, str(WORK / 'sock'))
    record('unix-send', data_base64=raw(message), returned=count)
    if count != len(message):
        raise RuntimeError('sender short datagram')


def marker(path, token):
    try:
        return token in path.read_bytes()
    except FileNotFoundError:
        return False


def read(path):
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b''


def scrub(data):
    return bytes(32 if ((b < 32 and b != 9) or b == 127) else b for b in data)


def lines_match(data, seed, messages):
    if not data.startswith(seed):
        return False
    actual = data[len(seed):].split(b'\n')
    if len(actual) != len(messages) + 1 or actual[-1] != b'':
        return False
    return all(re.fullmatch(PFX + re.escape(scrub(message)), line) is not None
               for line, message in zip(actual[:-1], messages))


def results(paths, seeds, expected):
    ok = True
    for name, path in paths.items():
        data = read(path)
        matched = lines_match(data, seeds[name], expected[name])
        record('file', name=name, path=str(path), base64=raw(data),
               expected_messages_base64=[raw(x) for x in expected[name]], matched=matched)
        ok &= matched
    return ok


def yes(value):
    return 'yes' if value else 'no'


def routing(shell):
    init(); paths = files(); seeds = {}
    for name, path in paths.items():
        seeds[name] = ('old-' + name + '\n').encode(); path.write_bytes(seeds[name])
    p = start(shell, base_args(paths) + ['--mode', '0640'], 'routing')
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    messages = [b'<13>user-A', b'<35>auth-B', b'<86>authpriv-C', b'<3>kern-D',
                b'no-pri-E', b'<13>scrub-\x00\x01\n\r\x7f\tZ']
    try:
        for msg in messages:
            send(sender, msg)
        if not wait_for(lambda: marker(paths['syslog'], b'scrub-')):
            raise RuntimeError('final routed record missing')
        mode = stat.S_IMODE((WORK / 'sock').stat().st_mode)
        clean, err = finish(p, 'routing')
    finally:
        sender.close()
    expected = {'messages': messages, 'syslog': [messages[i] for i in (0, 4, 5)],
                'auth': [messages[i] for i in (1, 2)], 'kern': [messages[3]]}
    matched = results(paths, seeds, expected)
    print('routing exact=%s mode=%s stopped=%s socket-removed=%s stderr-empty=%s' %
          (yes(matched), oct(mode), yes(clean), yes(not (WORK / 'sock').exists()), yes(not err)))


def once_one(shell, label, first, second):
    global WORK
    root = WORK
    WORK = root / label
    WORK.mkdir(mode=0o700)
    paths = files(); seeds = {}
    for name, path in paths.items():
        seeds[name] = ('old-' + name + '\n').encode(); path.write_bytes(seeds[name])
    p = start(shell, base_args(paths) + ['--once'], label)
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        p.send_signal(signal.SIGSTOP)
        def stopped():
            try:
                return '\nState:\tT' in Path('/proc/%d/status' % p.pid).read_text()
            except FileNotFoundError:
                return False
        if not wait_for(stopped):
            raise RuntimeError('owned daemon did not stop before queueing')
        send(sender, first); send(sender, second)
        p.send_signal(signal.SIGCONT)
        clean, err = finish(p, label, request_stop=False)
    finally:
        sender.close()
    expected = {'messages': [first] if first else [], 'syslog': [first] if first else [],
                'auth': [], 'kern': []}
    matched = results(paths, seeds, expected)
    print('%s queued=2 first-only=%s stopped=%s socket-removed=%s stderr-empty=%s' %
          (label, yes(matched), yes(clean), yes(not (WORK / 'sock').exists()), yes(not err)))
    WORK = root


def once(shell):
    init()
    once_one(shell, 'nonempty', b'<13>first', b'<13>second')
    once_one(shell, 'empty', b'', b'<13>after-empty')


def lifecycle(shell):
    init(); paths = files(); seeds = {}; modes = {'messages': 0o600, 'syslog': 0o640,
                                                  'auth': 0o644, 'kern': 0o660}
    initial = {}
    for name, path in paths.items():
        seeds[name] = ('old-' + name + '\n').encode(); path.write_bytes(seeds[name]); os.chmod(path, modes[name])
        initial[name] = path.stat()
    p = start(shell, base_args(paths), 'lifecycle')
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    msgs = [b'<13>file-user', b'<35>file-auth', b'<3>file-kern']
    try:
        for msg in msgs: send(sender, msg)
        if not wait_for(lambda: marker(paths['kern'], b'file-kern')):
            raise RuntimeError('final file record missing')
        clean, err = finish(p, 'lifecycle')
    finally:
        sender.close()
    expected = {'messages': msgs, 'syslog': [msgs[0]], 'auth': [msgs[1]], 'kern': [msgs[2]]}
    matched = results(paths, seeds, expected)
    mode_ok = True
    for name, path in paths.items():
        after = path.stat()
        before = initial[name]
        wanted = modes[name]
        # Retain raw stat modes before ordinary-tool cleanup so a reviewer can
        # independently check every requested mode and the same file identity.
        record('lifecycle-mode', name=name, path=str(path), expected_mode=wanted,
               initial_st_mode=before.st_mode, final_st_mode=after.st_mode,
               initial_device=before.st_dev, initial_inode=before.st_ino,
               final_device=after.st_dev, final_inode=after.st_ino)
        mode_ok &= (stat.S_IMODE(before.st_mode) == wanted and
                    stat.S_IMODE(after.st_mode) == wanted)
    operations_ok = True
    for name, path in paths.items():
        expected_data = path.read_bytes(); copy = WORK / (name + '.copy'); moved = WORK / (name + '.moved')
        steps = [(['/usr/bin/cp', '--', str(path), str(copy)], copy),
                 (['/usr/bin/mv', '--', str(copy), str(moved)], moved),
                 (['/usr/bin/rm', '--', str(moved), str(path)], None)]
        for argv, result_path in steps:
            proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            step_ok = proc.returncode == 0 and not proc.stdout and not proc.stderr
            if result_path is not None:
                step_ok &= result_path.is_file() and result_path.read_bytes() == expected_data
            else:
                step_ok &= not moved.exists() and not path.exists()
            operations_ok &= step_ok
            record('ordinary-tool', argv=argv, status=proc.returncode, stdout_base64=raw(proc.stdout),
                   stderr_base64=raw(proc.stderr), ok=step_ok)
    print('lifecycle appended=%s modes=%s copied-moved-removed=%s stopped=%s socket-removed=%s stderr-empty=%s' %
          (yes(matched), yes(mode_ok), yes(operations_ok), yes(clean),
           yes(not (WORK / 'sock').exists()), yes(not err)))


def links(shell):
    init(); paths = files()
    paths['messages'].write_bytes(b'hard-seed\n')
    os.link(paths['messages'], paths['syslog'])
    target = WORK / 'relative-target'; target.write_bytes(b'link-seed\n')
    paths['auth'].symlink_to('relative-target'); paths['kern'].write_bytes(b'kern-seed\n')
    before = (paths['messages'].stat().st_dev, paths['messages'].stat().st_ino,
              paths['syslog'].stat().st_dev, paths['syslog'].stat().st_ino,
              paths['auth'].lstat().st_ino, os.readlink(paths['auth']))
    p = start(shell, base_args(paths), 'links')
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    msgs = [b'<13>hardlink', b'<35>symlink']
    try:
        for msg in msgs: send(sender, msg)
        if not wait_for(lambda: marker(target, b'symlink')):
            raise RuntimeError('final symlink record missing')
        clean, err = finish(p, 'links')
    finally:
        sender.close()
    hard = read(paths['messages']); hard2 = read(paths['syslog']); symlink = read(target); kern = read(paths['kern'])
    hard_ok = hard == hard2 and lines_match(hard, b'hard-seed\n', [msgs[0], msgs[0], msgs[1]])
    link_ok = lines_match(symlink, b'link-seed\n', [msgs[1]]) and kern == b'kern-seed\n'
    try:
        after = (paths['messages'].stat().st_dev, paths['messages'].stat().st_ino,
                 paths['syslog'].stat().st_dev, paths['syslog'].stat().st_ino,
                 paths['auth'].lstat().st_ino, os.readlink(paths['auth']))
        identity = before == after and before[0:2] == before[2:4] and stat.S_ISLNK(paths['auth'].lstat().st_mode)
    except OSError:
        after = None; identity = False
    record('links', before=before, after=after, hard_base64=raw(hard), alias_base64=raw(hard2),
           target_base64=raw(symlink), kern_base64=raw(kern), hard_ok=hard_ok, link_ok=link_ok)
    print('links hardlink-multiplicity=%s symlink-target=%s identities=%s stopped=%s socket-removed=%s stderr-empty=%s' %
          (yes(hard_ok), yes(link_ok), yes(identity), yes(clean),
           yes(not (WORK / 'sock').exists()), yes(not err)))


def udp_receiver(family):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0))
    s.setblocking(False)
    return s


def fifo_reload(p, content, label):
    config = WORK / 'config'
    pending = WORK / 'next-fifo'
    os.mkfifo(pending, 0o600)
    os.replace(pending, config)
    p.send_signal(signal.SIGHUP)
    fd = None
    def opened():
        nonlocal fd
        try:
            fd = os.open(config, os.O_WRONLY | os.O_NONBLOCK)
            return True
        except OSError as e:
            if e.errno == errno.ENXIO:
                return False
            raise
    if not wait_for(opened):
        raise RuntimeError('SIGHUP did not open reload FIFO: ' + label)
    try:
        n = os.write(fd, content)
        if n != len(content): raise RuntimeError('config FIFO short write')
    finally:
        os.close(fd)
    record('reload', label=label, contents_base64=raw(content), fifo_reader_seen=True)


def drain(receivers):
    result = {}
    for name, sock in receivers.items():
        packets = []
        while True:
            try:
                data, peer = sock.recvfrom(65535)
                packets.append(data)
                record('udp', receiver=name, data_base64=raw(data), peer=list(peer))
            except BlockingIOError:
                break
        result[name] = packets
    return result


def config(shell):
    init(); paths = files()
    receivers = {'A': udp_receiver(socket.AF_INET), 'B': udp_receiver(socket.AF_INET),
                 'v6': udp_receiver(socket.AF_INET6)}
    targets = {name: (('[::1]:' if name == 'v6' else '127.0.0.1:') + str(s.getsockname()[1]))
               for name, s in receivers.items()}
    conf = WORK / 'config'; conf.write_text('BASHSYSLOGD_FORWARD=%s\n' % targets['A'])
    p = start(shell, base_args(paths) + ['--config', str(conf), '--forward', targets['B']], 'config')
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    checks = []
    def probe(label, target, stop=False, child_label='config'):
        message = ('<13>phase-' + label).encode()
        send(sender, message)
        if not wait_for(lambda: marker(paths['messages'], message)):
            raise RuntimeError('local processing not observed: ' + label)
        clean = None; err = b''
        if stop:
            clean, err = finish(p, child_label)
        # On a positive probe, wait for any forwarded packet; an unexpected
        # receiver also terminates the wait and is retained as a failure.
        packets = {n: [] for n in receivers}
        end = time.monotonic() + (0.2 if stop else 1.2)
        while time.monotonic() < end:
            new = drain(receivers)
            for n in packets: packets[n].extend(new[n])
            if not stop and any(packets.values()):
                time.sleep(.1)
                new = drain(receivers)
                for n in packets: packets[n].extend(new[n])
                break
            time.sleep(.01)
        expected = {n: ([message] if n == target else []) for n in receivers}
        good = packets == expected
        record('config-phase', label=label, expected=target, actual={n: [raw(x) for x in v] for n,v in packets.items()}, ok=good)
        checks.append(good)
        print('config-%s destination=%s' % (label, yes(good)))
        return clean, err
    try:
        probe('startup', 'B')
        conf.write_text('BASHSYSLOGD_FORWARD="%s"\n' % targets['v6'])
        probe('no-hup', 'B')
        fifo_reload(p, ('  BASHSYSLOGD_FORWARD="%s" # comment\n' % targets['v6']).encode(), 'v6')
        probe('reload-v6', 'v6')
        fifo_reload(p, b'BASHSYSLOGD_FORWARD="unterminated\n', 'invalid')
        probe('invalid-retains', 'v6')
        # Numeric host avoids DNS. If shell syntax were executed, it would
        # create a sentinel in our private case directory; literal parsing
        # instead treats the characters as an invalid numeric service.
        injected = 'BASHSYSLOGD_FORWARD="127.0.0.1:$(/usr/bin/touch %s)"\n' % (WORK / 'evaluated')
        fifo_reload(p, injected.encode(), 'literal')
        probe('literal-retains', 'v6')
        literal = not (WORK / 'evaluated').exists()
        fifo_reload(p, ('BASHSYSLOGD_FORWARD=\'%s\'\n' % targets['A']).encode(), 'v4')
        probe('reload-v4', 'A')
        fifo_reload(p, b'BASHSYSLOGD_FORWARD=\n', 'empty')
        clean, err = probe('empty-disabled', None, stop=True)
        diag = b'invalid forwarding configuration' in err
        record('config-summary', literal_no_execution=literal, invalid_diagnostic=diag,
               status_clean=clean, socket_removed=not (WORK / 'sock').exists(), targets=targets)
        print('config-summary literal=%s invalid-diagnostic=%s stopped=%s socket-removed=%s' %
              (yes(literal), yes(diag), yes(clean), yes(not (WORK / 'sock').exists())))
        # Startup without a command-line target must independently honor the
        # file. Replace the FIFO only after the first daemon has exited.
        conf.unlink()
        conf.write_text('BASHSYSLOGD_FORWARD=%s\n' % targets['A'])
        p = start(shell, base_args(paths) + ['--config', str(conf)], 'config-startup')
        startup_clean, startup_err = probe('file-startup', 'A', stop=True, child_label='config-startup')
        print('config-file-startup-clean stopped=%s socket-removed=%s stderr-empty=%s' %
              (yes(startup_clean), yes(not (WORK / 'sock').exists()), yes(not startup_err)))
    finally:
        sender.close()
        for s in receivers.values(): s.close()


def setup(scenario):
    # Positive and negative controls for line identity and exact multiplicity.
    sample = b'Jan  2 03:04:05 ' + socket.gethostname().encode() + b' <13>A B\n'
    assert lines_match(b'seed\n' + sample, b'seed\n', [b'<13>A\x00B'])
    assert not lines_match(b'seed\n' + sample + sample, b'seed\n', [b'<13>A\x00B'])
    assert not lines_match(b'changed\n' + sample, b'seed\n', [b'<13>A\x00B'])
    control = HOME / 'syslogd-control'; control.mkdir(mode=0o700)
    path = control / 'dgram'; receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(str(path)); receiver.settimeout(2)
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        assert sender.sendto(b'', str(path)) == 0
        assert sender.sendto(b'next', str(path)) == 4
        assert receiver.recv(16) == b'' and receiver.recv(16) == b'next'
    finally:
        sender.close(); receiver.close(); path.unlink()
    hard = control / 'hard'; alias = control / 'alias'; symlink = control / 'sym'
    hard.write_bytes(b'old\n'); os.link(hard, alias); symlink.symlink_to('hard')
    with alias.open('ab') as f: f.write(b'new\n')
    assert symlink.read_bytes() == b'old\nnew\n' and hard.stat().st_ino == alias.stat().st_ino
    assert os.readlink(symlink) == 'hard'
    if scenario == 'config':
        recv4 = udp_receiver(socket.AF_INET); recv6 = udp_receiver(socket.AF_INET6)
        try:
            for r, target in ((recv4, '127.0.0.1'), (recv6, '::1')):
                s = socket.socket(r.family, socket.SOCK_DGRAM)
                try:
                    assert s.sendto(b'control', (target, r.getsockname()[1])) == 7
                    assert wait_for(lambda: drain({'x': r})['x'] == [b'control'], seconds=2)
                finally: s.close()
            fifo = control / 'fifo'; os.mkfifo(fifo, 0o600); seen = []
            def reader():
                with fifo.open('rb') as stream: seen.append(stream.read())
            t = threading.Thread(target=reader, daemon=True); t.start()
            fd = None
            def writer():
                nonlocal fd
                try:
                    fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK); return True
                except OSError as e:
                    if e.errno == errno.ENXIO: return False
                    raise
            assert wait_for(writer, 2)
            os.write(fd, b'control\n'); os.close(fd); t.join(2)
            assert not t.is_alive() and seen == [b'control\n']
        finally: recv4.close(); recv6.close()
    record('setup-controls', scenario=scenario, result='verified')
    print('controls=verified')


SCENARIOS = {'routing': routing, 'once': once, 'lifecycle': lifecycle, 'links': links, 'config': config}


if __name__ == '__main__':
    try:
        guard()
        if len(sys.argv) == 3 and sys.argv[1] == 'setup':
            assert sys.argv[2] in SCENARIOS
            setup(sys.argv[2])
        else:
            shell, scenario = sys.argv[1:]
            SCENARIOS[scenario](shell)
    except Exception as exc:
        try:
            record('exception', error=repr(exc), traceback=traceback.format_exc())
        except Exception:
            pass
        print('scenario-error=%s' % type(exc).__name__)
        sys.exit(1)
    finally:
        for child in CHILDREN:
            if alive(child):
                child.kill()
                child.wait(timeout=3)
                record('forced-cleanup', pid=child.pid)
