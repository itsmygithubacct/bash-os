#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only observer for the cron daemon lifecycle and the batch -> cron consumer contract.

argv[1] is the shell under test. Every scenario builds a private spool tree under
/tmp/parity-case/work/<scenario>, drives that shell's `batch` and `cron run` builtins
through the documented BASHCRON_* hooks, and leaves every table, clock file, state file,
job log, daemon stream and observation in the tree, which the harness preserves as
evidence. Readiness is always an observed fact (a marker line, a replaced state file, a
heartbeat job), never a sleep. All waits share one budget, so a failing scenario prints a
short line instead of running into the harness wall-clock limit, and every daemon is
stopped in a finally block.

Every daemon owns a session, so its pid is also the session and process-group id of
everything it starts. Teardown is verified, not assumed: after the last observation the
observer SIGKILLs whatever is still in that session, waits until none of it is alive and
only then reaps the leader, which stays unreaped until then so its pid cannot be reused.
No control or scenario starts an external helper process; the stand-in daemons used by
the setup controls wait in a shell builtin.
"""
import calendar
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path

ROOT = Path('/opt/bashos-parity')
GUARD = ROOT / 'harness/helpers/system-seccomp.py'
REFERENCE_SHELL = '/opt/bash-5.3.15/bin/bash'
WORK = Path('/tmp/parity-case')

# 2023-11-14 12:10:00 UTC. Offset k is minute 12:(10+k), so every offset used below stays in hour 12.
BASE = calendar.timegm((2023, 11, 14, 12, 10, 0))
BASE_MINUTE = BASE // 60
HOUR, FIRST_MINUTE = 12, 10
INTERVAL_TOLERANCE = 0.25
T0 = time.monotonic()
DEADLINE = T0 + 48.0
CLOCK_VARIABLES = ('BASHCRON_NOW_EPOCH', 'BASHCRON_NOW_FILE', 'BASHCRON_TEST_NOW_FILE',
                   'BASHCRON_STATE_FILE', 'BASHCRON_CATCHUP_MAX_MIN')
JOB_LINE = re.compile(r'job (\d+)\.(\d+)\.(\d{6}) scheduled for (\d+)\Z')
# Stand-ins for a daemon, run by the reference shell with $1 = marker file and $2 = a FIFO the observer created.
# Holding the FIFO open for reading and writing makes `read -t` a pure builtin wait: no child process exists
# that could outlive its parent.
CONTROL_SCRIPT = '''
exec 3<>"$2"
trap 'echo HUP >> "$1"' HUP
trap 'echo TERM >> "$1"; exit 0' TERM
echo READY >> "$1"
while :; do read -t 0.05 -u 3 junk; done
'''
STUBBORN_SCRIPT = '''
exec 3<>"$2"
trap '' TERM
echo READY >> "$1"
while :; do read -t 0.05 -u 3 junk; done
'''
DAEMONS = []


def require_guest():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    uuid.UUID(marker)
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU'
    assert Path.cwd() == WORK
    assert os.geteuid() == 2000


def record(**fields):
    fields['t'] = round(time.monotonic() - T0, 3)
    with Path('observations.jsonl').open('a') as stream:
        stream.write(json.dumps(fields, sort_keys=True) + '\n')


def say(text):
    print(text, flush=True)
    record(kind='line', text=text)


def remaining():
    return max(0.0, DEADLINE - time.monotonic())


def wait_until(predicate, timeout, step=0.02):
    """Bounded poll of an observable condition; returns its last value (falsy on timeout)."""
    limit = time.monotonic() + min(timeout, remaining())
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= limit:
            return value
        time.sleep(step)


def until(predicate, timeout, step=0.01):
    """Bounded poll for teardown, which must finish even after the case budget is spent."""
    limit = time.monotonic() + timeout
    while True:
        value = predicate()
        if value or time.monotonic() >= limit:
            return value
        time.sleep(step)


def live_session_members(group):
    """Live (not zombie) processes whose session or process group is `group`, read from /proc; never this observer."""
    me, found = os.getpid(), []
    for entry in os.listdir('/proc'):
        if not entry.isdigit() or int(entry) == me:
            continue
        try:
            data = Path('/proc/%s/stat' % entry).read_bytes()
        except OSError:
            continue
        fields = data[data.rindex(b')') + 2:].split()
        if fields[0] != b'Z' and group in (int(fields[2]), int(fields[3])):
            found.append({'pid': int(entry), 'state': fields[0].decode(),
                          'name': data[data.index(b'(') + 1:data.rindex(b')')].decode('utf-8', 'replace')})
    return found


def private_dir(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def write_private(path, text, mode=0o600):
    """Atomic replace through a dot-file, which cron's directory scans skip."""
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as stream:
        stream.write(text)
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def scenario_dir(name):
    base = WORK / 'work' / name
    for part in ('spool', 'spool/atjobs', 'spool/tabs', 'out', 'etc', 'cron.d', 'mail'):
        private_dir(base / part)
    return base


def cron_env(base, **extra):
    env = dict(os.environ)
    for name in CLOCK_VARIABLES:
        env.pop(name, None)
    env.update({'BASHCRON_SPOOL_DIR': str(base / 'spool'), 'BASHCRON_OUTPUT_DIR': str(base / 'out'),
                'BASHCRON_ETC_DIR': str(base / 'etc'), 'BASHCRON_CROND_DIR': str(base / 'cron.d'),
                'BASHCRON_MAIL_DIR': str(base / 'mail'), 'TZ': 'UTC'})
    env.update({name: str(value) for name, value in extra.items() if value is not None})
    return env


def row(offset, command):
    return '%d %d * * * %s\n' % (FIRST_MINUTE + offset, HOUR, command)


def append(log, label):
    return 'echo %s >> %s' % (label, log)


def write_table(base, rows, user='fixture'):
    write_private(base / 'spool' / 'tabs' / user, ''.join(rows))


def drop_job(base, name, command, run_at=0):
    write_private(base / 'spool' / 'atjobs' / (name + '.job'), '# run_at=%d\n%s\n' % (run_at, command))


def marks(path):
    try:
        return Path(path).read_text().split()
    except FileNotFoundError:
        return []


def queue(base):
    return sorted(path.name for path in (base / 'spool' / 'atjobs').iterdir())


def queued_jobs(base):
    return [name for name in queue(base) if name.endswith('.job')]


def read_state(path):
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return 'garbled'


def state_signature(path):
    """Changes whenever the daemon replaces the state file, i.e. when a saving poll finishes."""
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return None
    return (info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


class Heartbeat:
    """Due at-jobs that each run at the first poll scanning the spool after they are dropped."""

    def __init__(self, base, tag=''):
        self.base, self.tag, self.count = base, tag, 0
        self.log = base / ('heartbeat%s.log' % tag)

    def beat(self, timeout=15):
        self.count += 1
        label = 'HB%d' % self.count
        drop_job(self.base, 'hb%s%03d' % (self.tag, self.count), append(self.log, label))
        return bool(wait_until(lambda: label in marks(self.log), timeout))

    def sync(self, timeout=15):
        """Two beats: the poll that ran the second began after the poll that ran the first had finished."""
        return self.beat(timeout) and self.beat(timeout)


class Daemon:
    """A child that owns a session: its pid is the session and process-group id of everything it starts."""

    def __init__(self, argv, env, base, tag):
        self.tag, self.status, self.finished = tag, None, False
        self.out = open(base / (tag + '.out'), 'wb')
        self.err = open(base / (tag + '.err'), 'wb')
        self.proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=self.out, stderr=self.err,
                                     start_new_session=True, close_fds=True)
        DAEMONS.append(self)

    def exited(self):
        """True once the leader has exited. It is only peeked at (WNOWAIT), so it stays unreaped until finish()."""
        if self.finished:
            return True
        try:
            info = os.waitid(os.P_PID, self.proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return True
        if info is None:
            return False
        self.status = info.si_status if info.si_code == os.CLD_EXITED else -info.si_status
        return True

    def alive(self):
        return not self.exited()

    def signal(self, number):
        if self.finished:
            return
        try:
            os.kill(self.proc.pid, number)
        except ProcessLookupError:
            pass

    def stop(self, wait=6.0):
        """SIGTERM, a bounded wait, then SIGKILL. Returns (clean, status, seconds); finish() does the teardown."""
        began = time.monotonic()
        if self.alive():
            self.signal(signal.SIGTERM)
        clean = bool(until(self.exited, max(0.5, min(wait, remaining()))))
        if not clean:
            self.signal(signal.SIGKILL)
            until(self.exited, 5.0)
        took = time.monotonic() - began
        record(kind='daemon-stop', tag=self.tag, clean=clean, status=self.status, seconds=round(took, 3))
        return clean, self.status, took

    def finish(self):
        """Verified teardown, called after the last observation. The leader has exited but is still unreaped, so its
        pid cannot belong to anyone else: SIGKILL what is left in its session, wait until none of it is alive, then
        reap the leader. Returns (survivors that had to be killed, whether the session ended up empty)."""
        if self.finished:
            return [], True
        if not self.exited():
            self.stop(wait=1.0)
        survivors = live_session_members(self.proc.pid)
        if survivors:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        emptied = bool(until(lambda: not live_session_members(self.proc.pid), 5.0))
        status = self.proc.wait()
        if self.status is None:
            self.status = status
        self.finished = True
        for stream in (self.out, self.err):
            stream.close()
        record(kind='daemon-finish', tag=self.tag, survivors=survivors, emptied=emptied)
        return survivors, emptied


def finish_all():
    """Teardown for every daemon this process started; True when no live process is left in any of their sessions."""
    emptied = True
    for daemon in DAEMONS:
        emptied = daemon.finish()[1] and emptied
    return emptied


def candidate_daemon(shell, base, tag, interval, **extra):
    return Daemon([shell, '--noprofile', '--norc', '-c', 'cron run --interval %d' % interval],
                  cron_env(base, **extra), base, tag)


def bounded(seconds):
    """A subprocess timeout that cannot outlive the case-wide budget (at least a few seconds, so cleanup can finish)."""
    return max(5.0, min(seconds, remaining()))


def shell_run(shell, script, env, timeout=30):
    return subprocess.run([shell, '--noprofile', '--norc', '-c', script], env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=bounded(timeout))


def text(data):
    return data.decode('utf-8', 'backslashreplace')


def consume(shell, base, now, **extra):
    """One `cron run --once` poll with a fixed clock (or the real clock when now is None)."""
    result = shell_run(shell, 'cron run --once', cron_env(base, BASHCRON_NOW_EPOCH=now, **extra))
    record(kind='consume', base=str(base), now=now, status=result.returncode,
           stdout=text(result.stdout), stderr=text(result.stderr))
    return result


def spawn_submitter(shell, base, name, commands):
    """A shell that waits for one line on stdin, then runs `batch` once per command file in its own process."""
    files = []
    for index, command in enumerate(commands):
        path = base / ('%s-job%d' % (name, index))
        path.write_text(command + '\n')
        files.append(path)
    script = 'IFS= read -r _go || exit 3\n' + ''.join('batch < %s\n' % path for path in files)
    return subprocess.Popen([shell, '--noprofile', '--norc', '-c', script], env=cron_env(base), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)


def submit(proc, timeout=10):
    try:
        out, err = proc.communicate(b'go\n', timeout=bounded(timeout))
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    jobs = []
    for line in text(out).splitlines():
        match = JOB_LINE.match(line)
        if match:
            jobs.append({'id': '%s.%s.%s' % match.group(1, 2, 3), 'sec': int(match.group(1)), 'pid': int(match.group(2)),
                         'seq': int(match.group(3)), 'scheduled': int(match.group(4))})
    record(kind='submit', pid=proc.pid, status=proc.returncode, jobs=jobs, stdout=text(out), stderr=text(err))
    return jobs


def align(max_fraction=0.15, timeout=3.0):
    """Return just after a wall-clock second boundary so back-to-back submissions share one second."""
    limit = time.monotonic() + min(timeout, remaining())
    while time.monotonic() < limit:
        now = time.time()
        if now - int(now) < max_fraction:
            return True
        time.sleep(0.002)
    return False


def traced(argv, env, base, tag):
    """Run argv under the pinned seccomp observer, counting opens of the kernel load interfaces."""
    log = base / ('trace-%s.jsonl' % tag)
    wrapper = ['/usr/bin/python3', str(GUARD), '--notify', 'openat', '--reply', 'openat=continue',
               '--log-string', 'openat=1', '--notify', 'open', '--reply', 'open=continue', '--log-string', 'open=0',
               '--notify', 'sysinfo', '--reply', 'sysinfo=continue', '--log', str(log), '--']
    result = subprocess.run(wrapper + argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=bounded(40))
    rows = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    reads = [r for r in rows if r.get('syscall') in ('openat', 'open') and
             any(str(r.get(key, '')).startswith(('/proc/loadavg', '/proc/pressure')) for key in ('string0', 'string1'))]
    record(kind='trace', tag=tag, status=result.returncode, records=len(rows), loadavg_reads=len(reads),
           sysinfo_calls=sum(1 for r in rows if r.get('syscall') == 'sysinfo'), stderr=text(result.stderr))
    return result, len(reads)


# ---------------------------------------------------------------- batch -> cron consumer

def batch_once(shell):
    base = scenario_dir('batch-once')
    log = base / 'order.log'
    labels = ['L1', 'L2', 'L3']
    commands = [append(log, label) for label in labels]
    proc = spawn_submitter(shell, base, 'sub', commands)
    jobs = submit(proc)
    ids = len(jobs) == 3 and all(job['sec'] == job['scheduled'] for job in jobs)
    own_pid = ids and all(job['pid'] == proc.pid for job in jobs)
    present = modes = contents = len(jobs) == 3
    for job, command in zip(jobs, commands):
        path = base / 'spool' / 'atjobs' / (job['id'] + '.job')
        if not path.is_file():
            present = modes = contents = False
            continue
        modes = modes and stat.S_IMODE(path.stat().st_mode) == 0o600
        contents = contents and path.read_bytes() == ('# run_at=%d\n%s\n' % (job['sec'], command)).encode()
    say('produced=%d ids=%s submitter-pid=%s files=%s mode=%s bytes=%s' % (
        len(jobs), 'ok' if ids else 'bad', 'ok' if own_pid else 'bad', 'ok' if present else 'missing',
        '0600' if modes else 'other', 'ok' if contents else 'differ'))
    now = max([job['sec'] for job in jobs] or [BASE]) + 60
    first = consume(shell, base, now)
    ran = marks(log)
    left = queue(base)
    say('poll-1 status=%d executed=%d each-once=%s removed=%s leftovers=%s' % (
        first.returncode, len(ran), 'yes' if sorted(ran) == labels else 'no',
        'yes' if not [name for name in left if name.endswith('.job')] else 'no', ','.join(left) if left else 'none'))
    second = consume(shell, base, now)
    again = marks(log)
    say('poll-2 status=%d executed=%d reexecuted=%s' % (second.returncode, len(again), 'no' if again == ran else 'yes'))


def batch_boundary(shell):
    base = scenario_dir('batch-boundary')
    log = base / 'order.log'
    proc = spawn_submitter(shell, base, 'first', [append(log, 'EARLY')])
    before = int(time.time())
    jobs = submit(proc)
    after = int(time.time())
    job = jobs[0] if jobs else {'id': 'missing', 'sec': BASE, 'scheduled': 0}
    path = base / 'spool' / 'atjobs' / (job['id'] + '.job')
    header = path.read_text().splitlines()[0] if path.is_file() else ''
    submission_time = before <= job['sec'] <= after and job['scheduled'] == job['sec']
    say('run_at=%s header=%s' % ('submission-time' if submission_time else 'other',
                                 'ok' if header == '# run_at=%d' % job['sec'] else 'bad'))
    for label, now in (('run_at-1', job['sec'] - 1), ('run_at', job['sec'])):
        result = consume(shell, base, now)
        say('clock=%s status=%d executed=%d queued=%d' % (label, result.returncode, len(marks(log)), len(queued_jobs(base))))
    submit(spawn_submitter(shell, base, 'second', [append(log, 'LIVE')]))
    result = consume(shell, base, None)
    say('clock=real status=%d executed=%d queued=%d' % (result.returncode, len(marks(log)), len(queued_jobs(base))))


def batch_load(shell):
    base = scenario_dir('batch-load')
    log = base / 'order.log'
    env = cron_env(base)
    cat, cat_reads = traced(['/usr/bin/cat', '/proc/loadavg'], env, base, 'control-cat')
    true, true_reads = traced(['/usr/bin/true'], env, base, 'control-true')
    say('control: loadavg-open-detected=%s loadavg-absent-when-unread=%s' % (
        'yes' if cat.returncode == 0 and cat_reads >= 1 else 'no', 'yes' if true.returncode == 0 and true_reads == 0 else 'no'))
    job = base / 'job'
    job.write_text(append(log, 'LOADFREE') + '\n')
    produced, producer_reads = traced([shell, '--noprofile', '--norc', '-c', 'batch < %s' % job], env, base, 'producer')
    first = JOB_LINE.match((text(produced.stdout).splitlines() or [''])[0])
    run_at = int(first.group(4)) if first else BASE
    say('producer: status=%d loadavg-reads=%d' % (produced.returncode, producer_reads))
    consumed, consumer_reads = traced([shell, '--noprofile', '--norc', '-c', 'cron run --once'],
                                      cron_env(base, BASHCRON_NOW_EPOCH=run_at), base, 'consumer')
    say('consumer: status=%d executed=%d loadavg-reads=%d' % (consumed.returncode, len(marks(log)), consumer_reads))


def batch_fifo_shell(shell):
    count = 6
    expected = [str(n) for n in range(1, count + 1)]
    for attempt in range(1, 7):
        base = scenario_dir('batch-fifo-shell-%d' % attempt)
        log = base / 'order.log'
        proc = spawn_submitter(shell, base, 'sub', [append(log, label) for label in expected])
        align()
        jobs = submit(proc)
        same = len(jobs) == count and len({job['sec'] for job in jobs}) == 1
        if same or remaining() < 10:
            break
    consume(shell, base, max([job['sec'] for job in jobs] or [BASE]) + 60)
    order = marks(log)
    say('same-shell jobs=%d same-second=%s executed=%s fifo=%s' % (
        len(jobs), 'yes' if same else 'no', ''.join(order), 'yes' if order == expected else 'no'))


def cross_process(shell, first_is_higher, same_second):
    """Two shells, each submitting one job: the first spawned has the lower pid."""
    tag = ('higher' if first_is_higher else 'lower') + ('-same' if same_second else '-next')
    outcome = None
    for attempt in range(1, 7):
        base = scenario_dir('batch-fifo-cross-%s-%d' % (tag, attempt))
        log = base / 'order.log'
        low = spawn_submitter(shell, base, 'low', [append(log, 'LOW')])
        high = spawn_submitter(shell, base, 'high', [append(log, 'HIGH')])
        first, second = (high, low) if first_is_higher else (low, high)
        if same_second:
            align()
        a = submit(first)
        if not same_second and a:
            wait_until(lambda: int(time.time()) > a[0]['sec'], 3)
        b = submit(second)
        for proc in (low, high):
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        ok = bool(a) and bool(b) and low.pid < high.pid and (
            a[0]['sec'] == b[0]['sec'] if same_second else b[0]['sec'] > a[0]['sec'])
        outcome = (base, log, a, b, ok)
        if ok or remaining() < 10:
            break
    base, log, a, b, ok = outcome
    consume(shell, base, max([job['sec'] for job in a + b] or [BASE]) + 60)
    order = marks(log)
    expected = ['HIGH', 'LOW'] if first_is_higher else ['LOW', 'HIGH']
    return ok, order, order == expected


def batch_fifo_cross(shell):
    for label, higher, same in (('lower-pid-first', False, True), ('higher-pid-first', True, True),
                                ('higher-pid-first', True, False)):
        ok, order, fifo = cross_process(shell, higher, same)
        say('cross-process %s %s=%s order=%s fifo=%s' % (
            label, 'same-second' if same else 'different-second', 'yes' if ok else 'no', ','.join(order),
            'yes' if fifo else 'no'))


# ---------------------------------------------------------------- cron daemon

def cron_polls(shell):
    base = scenario_dir('polls')
    log = base / 'log'
    write_table(base, [row(k, append(log, 'P%d' % k)) for k in range(3)])
    clock = base / 'clock'
    clock.write_text('%d\n%d\n%d\n' % (BASE + 10, BASE + 60 + 25, BASE + 120 + 40))
    beats = Heartbeat(base)
    stamps = []
    daemon = candidate_daemon(shell, base, 'daemon', 2, BASHCRON_NOW_FILE=clock)
    try:
        for label in ('P0', 'P1', 'P2'):
            if wait_until(lambda label=label: label in marks(log), 15):
                stamps.append(time.monotonic())
        for _ in (1, 2):
            if beats.beat(15):
                stamps.append(time.monotonic())
    finally:
        daemon.stop()
    dispatched = [m for m in marks(log) if m.startswith('P')]
    heartbeats = [m for m in marks(beats.log) if m.startswith('HB')]
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    record(kind='gaps', gaps=[round(g, 3) for g in gaps])
    spacing = len(stamps) == 5 and min(gaps) >= 2 - INTERVAL_TOLERANCE
    say('dispatched=%s duplicates=%s heartbeat-polls=%d spacing=%s' % (
        ','.join(dispatched), 'none' if len(dispatched) == len(set(dispatched)) else 'yes', len(heartbeats),
        'ok' if spacing else 'short'))


def cron_reboot(shell):
    once = scenario_dir('reboot-once')
    once_log = once / 'log'
    write_table(once, ['@reboot %s\n' % append(once_log, 'REBOOT'), row(0, append(once_log, 'NORMAL0'))])
    result = consume(shell, once, BASE + 10)
    seen = marks(once_log)
    say('once: status=%d reboot-runs=%d normal-runs=%d' % (result.returncode, seen.count('REBOOT'), seen.count('NORMAL0')))
    base = scenario_dir('reboot-daemon')
    log = base / 'log'
    write_table(base, ['@reboot %s\n' % append(log, 'REBOOT'), row(0, append(log, 'NORMAL0')), row(1, append(log, 'NORMAL1'))])
    clock = base / 'clock'
    clock.write_text('%d\n%d\n' % (BASE + 10, BASE + 60 + 10))
    state = base / 'state'
    beats = Heartbeat(base)
    start_runs, dispatch, final = None, False, []
    daemon = candidate_daemon(shell, base, 'daemon', 1, BASHCRON_NOW_FILE=clock, BASHCRON_STATE_FILE=state)
    try:
        wait_until(lambda: 'NORMAL1' in marks(log) and read_state(state) == BASE_MINUTE + 1, 20)
        seen = marks(log)
        start_runs, dispatch = seen.count('REBOOT'), 'NORMAL0' in seen and 'NORMAL1' in seen
        before = state_signature(state)
        daemon.signal(signal.SIGHUP)
        wait_until(lambda: state_signature(state) != before, 10)
        beats.sync(15)
        final = marks(log)
        record(kind='counts', normal1_runs=final.count('NORMAL1'), reboot_runs=final.count('REBOOT'))
    finally:
        daemon.stop()
    say('daemon: reboot-runs-at-start=%s normal-dispatch=%s' % (start_runs, 'yes' if dispatch else 'no'))
    say('daemon: after-polls-and-sighup reboot-runs=%d' % final.count('REBOOT'))


def daemon_catchup(shell, tag, limit, gap):
    base = scenario_dir('catchup-' + tag)
    log = base / 'log'
    write_table(base, [row(k, append(log, 'M%d' % k)) for k in range(7)])
    clock = base / 'clock'
    clock.write_text('%d\n%d\n' % (BASE + 5, BASE + 60 * gap + 5))
    state = base / 'state'
    daemon = candidate_daemon(shell, base, 'daemon', 1, BASHCRON_NOW_FILE=clock, BASHCRON_STATE_FILE=state,
                              BASHCRON_CATCHUP_MAX_MIN=limit)
    try:
        wait_until(lambda: read_state(state) == BASE_MINUTE + gap, 20)
    finally:
        daemon.stop()
    ran = marks(log)
    daemon.finish()
    return ran


def cron_catchup_configured(shell):
    for gap in (3, 4):
        say('limit=3 gap=%d ran=%s' % (gap, ','.join(daemon_catchup(shell, 'limit3-gap%d' % gap, 3, gap))))


def cron_catchup_default(shell):
    for gap in (5, 6):
        say('limit=default gap=%d ran=%s' % (gap, ','.join(daemon_catchup(shell, 'default-gap%d' % gap, None, gap))))


MATRIX = [('1', 1), ('1', 2), ('3', 3), ('3', 4), (None, 5), (None, 6), ('1440', 9)] + [
    (value, gap) for value in ('0', '-5', '1441', 'abc', '3x', '') for gap in (5, 6)]


def cron_catchup_once(shell):
    for index, (limit, gap) in enumerate(MATRIX):
        base = scenario_dir('matrix-%02d' % index)
        log = base / 'log'
        write_table(base, [row(k, append(log, 'M%d' % k)) for k in range(10)])
        state = base / 'state'
        write_private(state, '%d\n' % BASE_MINUTE)
        result = consume(shell, base, BASE + 60 * gap + 5, BASHCRON_STATE_FILE=state, BASHCRON_CATCHUP_MAX_MIN=limit)
        say('limit=%s gap=%d status=%d ran=%s' % ('default' if limit is None else repr(limit), gap,
                                                  result.returncode, ','.join(marks(log))))


def cron_signals(shell):
    base = scenario_dir('signals')
    log = base / 'log'
    state = base / 'state'
    write_table(base, [row(0, append(log, 'A'))])
    daemon = candidate_daemon(shell, base, 'daemon', 3600, BASHCRON_NOW_EPOCH=BASE + 10, BASHCRON_STATE_FILE=state)
    try:
        wait_until(lambda: marks(log) == ['A'] and read_state(state) == BASE_MINUTE, 20)
        say('initial: ran=%s' % ','.join(marks(log)))
        signature = state_signature(state)
        write_table(base, [row(0, append(log, 'B'))])
        time.sleep(0.5)  # negative control only: with a 3600 s interval nothing can poll in this window
        ignored = marks(log) == ['A'] and state_signature(state) == signature
        say('without-signal: ran=%s table-change-ignored=%s' % (','.join(marks(log)), 'yes' if ignored else 'no'))
        for number, label in ((1, 'B'), (2, 'C')):
            if number == 2:
                write_table(base, [row(0, append(log, 'C'))])
            signature = state_signature(state)
            daemon.signal(signal.SIGHUP)
            wait_until(lambda label=label, signature=signature:
                       label in marks(log) and state_signature(state) != signature, 10)
            say('sighup-%d: ran=%s alive=%s' % (number, ','.join(marks(log)), 'yes' if daemon.alive() else 'no'))
    finally:
        clean, status, took = daemon.stop()
    leftovers = [p.name for p in (base / 'out').iterdir() if p.name.startswith('job.')] + queue(base)
    try:
        intact = read_state(state) == BASE_MINUTE and stat.S_IMODE(os.stat(state).st_mode) == 0o600
    except OSError:
        intact = False
    say('sigterm: status=%d prompt=%s leftovers=%s state-intact=%s' % (
        status, 'yes' if clean and took < 3.0 else 'no', ','.join(leftovers) or 'none', 'yes' if intact else 'no'))


def cron_restart(shell):
    base = scenario_dir('restart')
    log = base / 'log'
    state = base / 'state'
    write_table(base, ['@reboot %s\n' % append(log, 'BOOT')] + [row(k, append(log, 'R%d' % k)) for k in range(10)])
    runs = [('run-1', BASE + 7, 0), ('run-2', BASE + 3 * 60 + 9, 3), ('run-3', BASE + 9 * 60 + 9, 9),
            ('run-4', BASE + 9 * 60 + 50, 9)]
    for index, (label, now, offset) in enumerate(runs, 1):
        before = len(marks(log))
        beats = Heartbeat(base, tag='r%d' % index)
        daemon = candidate_daemon(shell, base, label, 1, BASHCRON_NOW_EPOCH=now, BASHCRON_STATE_FILE=state)
        try:
            if label == 'run-4':
                beats.sync(15)
            else:
                wait_until(lambda: read_state(state) == BASE_MINUTE + offset, 20)
        finally:
            daemon.stop()
        value = read_state(state)
        shown = 'missing' if value is None else 'garbled' if value == 'garbled' else 'm0+%d' % (value - BASE_MINUTE)
        suffix = ''
        if index == 1:
            try:
                suffix = ' mode=%s' % ('0600' if stat.S_IMODE(os.stat(state).st_mode) == 0o600 else 'other')
            except OSError:
                suffix = ' mode=missing'
        say('%s ran=%s state=%s%s' % (label, ','.join(marks(log)[before:]), shown, suffix))
        daemon.finish()


# ---------------------------------------------------------------- independent controls

def setup(scenario):
    """Controls for the observer itself, limited to what the scenario uses; the candidate is never executed."""
    assert scenario in SCENARIOS, scenario
    base = private_dir(WORK / 'controls')
    # Clock arithmetic: 1700000000 is the documented example (state minute 28333333 in the legacy state-file case).
    assert 1700000000 // 60 == 28333333
    assert BASE % 60 == 0 and BASE_MINUTE * 60 == BASE
    assert time.gmtime(BASE + 9 * 60 + 50)[3:5] == (12, 19) and time.gmtime(BASE)[3:5] == (12, 10)
    if scenario.startswith('cron-') and scenario != 'cron-catchup-once':
        # Signal, handshake and teardown driver, proven on reference-shell stand-ins that start no external process
        # (they wait in the `read -t` builtin on a FIFO they hold open): SIGHUP is observed and survived, SIGTERM
        # exits 0 and is reported clean, a process that ignores SIGTERM is NOT reported clean, and after each stop
        # the stand-in's whole session is verifiably gone and its leader reaped.
        wait_fifo = base / 'wait.fifo'
        if not wait_fifo.exists():
            os.mkfifo(wait_fifo, 0o600)
        marker = base / 'signals.log'
        control = Daemon([REFERENCE_SHELL, '--noprofile', '--norc', '-c', CONTROL_SCRIPT, 'control', str(marker),
                          str(wait_fifo)], dict(os.environ), base, 'control')
        try:
            ready = wait_until(lambda: 'READY' in marks(marker), 5)
            control.signal(signal.SIGHUP)
            hangup = wait_until(lambda: 'HUP' in marks(marker), 5)
            alive = control.alive()
        finally:
            clean, status, took = control.stop(wait=5)
        survivors, emptied = control.finish()
        assert ready and hangup and alive and clean and status == 0 and marks(marker) == ['READY', 'HUP', 'TERM'], (
            marks(marker), clean, status)
        assert not survivors and emptied and control.finished, survivors
        stubborn_log = base / 'stubborn.log'
        stubborn = Daemon([REFERENCE_SHELL, '--noprofile', '--norc', '-c', STUBBORN_SCRIPT, 'control', str(stubborn_log),
                           str(wait_fifo)], dict(os.environ), base, 'stubborn')
        try:
            assert wait_until(lambda: 'READY' in marks(stubborn_log), 5)
        finally:
            clean, status, took = stubborn.stop(wait=1.0)
        survivors, emptied = stubborn.finish()
        assert not clean and status == -signal.SIGKILL, (clean, status)
        assert not survivors and emptied and stubborn.finished, survivors
    if scenario == 'batch-load':
        # The load-interface observer must see an open of /proc/loadavg when one happens and stay silent otherwise.
        env = dict(os.environ)
        cat, cat_reads = traced(['/usr/bin/cat', '/proc/loadavg'], env, base, 'cat')
        true, true_reads = traced(['/usr/bin/true'], env, base, 'true')
        assert cat.returncode == 0 and cat_reads >= 1 and true.returncode == 0 and true_reads == 0, (cat_reads, true_reads)
    if scenario.startswith('batch-fifo'):
        # Same-second alignment and the ordering oracle: strcmp order of job ids can disagree with submission order.
        assert align(0.15, 3.0)
        assert 0.0 <= time.time() - int(time.time()) < 1.0
        first_id, second_id = '1700000000.50.000000', '1700000000.60.000000'
        assert sorted([first_id, second_id]) != [second_id, first_id]
        assert sorted(['1700000000.999.000000', '1700000000.1000.000000']) == [
            '1700000000.1000.000000', '1700000000.999.000000']
    print('controls=verified')


SCENARIOS = {'batch-once': batch_once, 'batch-boundary': batch_boundary, 'batch-load': batch_load,
             'batch-fifo-shell': batch_fifo_shell, 'batch-fifo-cross': batch_fifo_cross,
             'cron-polls': cron_polls, 'cron-reboot': cron_reboot,
             'cron-catchup-configured': cron_catchup_configured, 'cron-catchup-default': cron_catchup_default,
             'cron-catchup-once': cron_catchup_once, 'cron-signals': cron_signals, 'cron-restart': cron_restart}


if __name__ == '__main__':
    require_guest()
    if sys.argv[1:2] == ['setup']:
        try:
            setup(sys.argv[2])
        finally:
            finish_all()
    else:
        shell, scenario = sys.argv[1:]
        try:
            SCENARIOS[scenario](shell)
        except Exception as exc:  # a failing scenario must fail the comparison, not print a traceback
            record(kind='error', scenario=scenario, error=repr(exc), traceback=traceback.format_exc())
            say('scenario-error=%s' % type(exc).__name__)
        finally:
            if not finish_all():
                say('teardown-incomplete')
