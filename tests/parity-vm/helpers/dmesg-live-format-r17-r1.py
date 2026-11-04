#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Default/raw timestamp controls in a coordinator-owned disposable QEMU guest.

Two bounded ASCII writes only. No ring clear, console change, sysctl or module
operation. Run as an ordinary root fixture; the guest overlay is disposable.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path('/opt/bashos-parity')
HOME = Path('/tmp/parity-home')
CANDIDATE = ROOT / 'candidate'
BASH = Path('/opt/bash-5.3.20/bin/bash')
UTILITY = Path('/usr/bin/dmesg')
CANDIDATE_HASHES = {
    'static': '69ac1d064fa538a1d73f4936c700dc095a8962eb78bb77323f2a412aa7c0946c',
    'dynamic': '0473e17de70cc467bd96210910b1f979cf05e3889dabaee8247d1c6c9e9b77ef',
}
BASH_SHA = '25a9bcfbdb3d52798022550336c8110461d533cf7b5c90e336b117aabee559d8'
UTILITY_SHA = '605698ef166c53fc53c97338b7d0eadd95cec93daff93fac8b213932a9e8fbd0'
CAPTURE_LIMIT = 256 * 1024
REPORT_NAME = 'dmesg-live-format-r3.json'


class Incomplete(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Incomplete(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    require(path.is_file() and not path.is_symlink(), 'nonregular pinned input')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def protected(path, limit=8192):
    path = Path(path)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                not info.st_mode & 0o022, 'unprotected attestation directory')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                stat.S_IMODE(info.st_mode) == 0o444 and info.st_nlink == 1 and
                0 < info.st_size <= limit, 'unprotected attestation')
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        require(len(data) == info.st_size and
                (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size) ==
                (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size), 'attestation changed')
        return data
    finally:
        os.close(fd)


def guard():
    require(os.geteuid() == 0 and os.getcwd() == '/tmp/parity-case' and
            os.environ.get('HOME') == str(HOME), 'requires an ordinary root fixture')
    token = protected('/etc/bashos-parity-vm').decode('ascii').strip()
    require(str(uuid.UUID(token)) == token and
            protected('/run/bashos-parity-vm-identity').decode('ascii').strip() == token,
            'protected guest identity mismatch')
    require(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU' and
            Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == token,
            'requires the attested disposable QEMU guest')
    proof = json.loads(protected('/run/bashos-syslog-namespace-208.json'))
    require(proof.get('schema') == 'bashos-syslog-namespace-attestation-v1' and
            proof.get('token') == token, 'namespace identity differs')
    inner, outer = proof['namespaces'], proof['outer_namespaces']
    current = {n: os.readlink('/proc/self/ns/' + n) for n in ('pid', 'mnt', 'net')}
    require(set(inner) == set(outer) == set(current) and
            all(re.fullmatch(n + r':\[[0-9]+\]', inner[n]) and
                re.fullmatch(n + r':\[[0-9]+\]', outer[n]) and inner[n] != outer[n] for n in inner),
            'evaluator namespace boundary missing')
    require(current['pid'] == inner['pid'] and all(current[n] not in (inner[n], outer[n])
            for n in ('mnt', 'net')), 'requires the ordinary root side mount/network namespaces')
    return {'token': token, 'evaluator': proof, 'side_namespaces': current,
            'uid': os.geteuid(), 'sys_vendor': 'QEMU'}


def save(name, value):
    # Evidence is additive within the fresh per-side tmpfs; never follow links.
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    require(len(data) < 1024 * 1024, 'diagnostic would exceed harness per-file limit')
    fd = os.open(HOME / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
    return {'file': name, 'sha256': sha(data), 'bytes': len(data)}


def run(argv):
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(HOME), 'LC_ALL': 'C', 'LANG': 'C',
           'TZ': 'UTC', 'TERM': 'dumb', 'BASH_ENV': '', 'ENV': ''}
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    proc, error, status, group_clean = None, None, None, False
    start = time.monotonic()
    try:
        proc = subprocess.Popen(list(map(str, argv)), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, start_new_session=True, close_fds=True)
        with selectors.DefaultSelector() as selector:
            for stream, name in ((proc.stdout, 'stdout'), (proc.stderr, 'stderr')):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                require(time.monotonic() - start < 5, 'subprocess exceeded bounded observation')
                for key, _ in selector.select(.05):
                    data = os.read(key.fileobj.fileno(), 8192)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    room = CAPTURE_LIMIT - sum(len(b) for b in buffers.values())
                    buffers[key.data].extend(data[:room])
                    require(len(data) <= room, 'subprocess capture truncated')
        status = proc.wait(timeout=max(.01, 5 - (time.monotonic() - start)))
    except (OSError, Incomplete, subprocess.TimeoutExpired) as exc:
        error = str(exc)
    finally:
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                group_clean = True
            else:
                error = error or 'owned process group survived observation'
            proc.wait(timeout=2)
            for stream in (proc.stdout, proc.stderr):
                stream.close()
    out, err = bytes(buffers['stdout']), bytes(buffers['stderr'])
    return {'argv': list(map(str, argv)), 'status': status, 'error': error,
            'stdout_hex': out.hex(), 'stderr_hex': err.hex(), 'stdout_sha256': sha(out),
            'stderr_sha256': sha(err), 'captured_bytes': len(out) + len(err),
            'capture_complete': error is None, 'owned_process_group_empty': group_clean}


def checked_process(row):
    require(row['capture_complete'] and row['owned_process_group_empty'] and
            type(row['status']) is int and row['status'] not in (125, 126, 127),
            'incomplete process observation or unavailable executable')


def version(path, expected):
    require(digest(path) == expected, 'shell pin differs')
    row = run([path, '--noprofile', '--norc', '-c',
               'builtin printf "%s.%s.%s\\n" "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}" "${BASH_VERSINFO[2]}"'])
    checked_process(row)
    require((row['status'], row['stdout_hex'], row['stderr_hex']) == (0, b'5.3.20\n'.hex(), ''),
            'requires Bash 5.3.20')
    return dict(row, shell_sha256=expected)


def device(flags):
    fd = os.open('/dev/kmsg', flags | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (1, 11),
                'requires the real /dev/kmsg character device')
        return fd
    except BaseException:
        os.close(fd)
        raise


def drain(fd, marker):
    records, total, largest, tagged = 0, 0, 0, []
    stream = hashlib.sha256()
    deadline = time.monotonic() + 2
    while records < 16384 and total < 512 * 1024 and time.monotonic() < deadline:
        try:
            raw = os.read(fd, 65536)
        except OSError as exc:
            if exc.errno == errno.EAGAIN:
                return {'records': records, 'bytes': total, 'max_record_bytes': largest,
                        'complete_to_eagain': True, 'read_capacity': 65536,
                        'stream_sha256': stream.hexdigest(), 'tagged': tagged}
            raise Incomplete('raw drain incomplete: errno ' + str(exc.errno)) from exc
        require(bool(raw), 'unexpected /dev/kmsg EOF')
        records += 1; total += len(raw); largest = max(largest, len(raw))
        stream.update(len(raw).to_bytes(4, 'big')); stream.update(raw)
        if marker in raw.partition(b';')[2]:
            require(len(tagged) < 8, 'unexpected duplicate target records')
            tagged.append({'hex': raw.hex(), 'bytes': len(raw), 'sha256': sha(raw)})
    raise Incomplete('raw drain exceeded record/byte/time bound')


def inventory(marker):
    fd = device(os.O_RDONLY)
    try:
        os.lseek(fd, 0, os.SEEK_DATA)
        row = drain(fd, marker)
        row['start_seek'] = 'SEEK_DATA'
        # Stock util-linux 2.41.5 uses a 2048-byte array, reading 2047 bytes.
        require(row['max_record_bytes'] <= 2047, 'stock utility would encounter an oversized record')
        return row
    finally:
        os.close(fd)


def expected_lines(seed, marker):
    require(len(seed['writes']) == len(seed['drain']['tagged']) == 2 and seed['drain']['complete_to_eagain'],
            'seed records missing or duplicated')
    default, raw_output = [], []
    previous_seq = previous_us = -1
    for index, (write, observed) in enumerate(zip(seed['writes'], seed['drain']['tagged'])):
        raw, submitted = bytes.fromhex(observed['hex']), bytes.fromhex(write['input_hex'])
        header, sep, message = raw.partition(b';')
        match = re.fullmatch(rb'(14|11),([0-9]+),([0-9]+),-', header)
        require(sep and match and sha(raw) == observed['sha256'] and len(raw) == observed['bytes'] and
                sha(submitted) == write['input_sha256'] and write['written'] == len(submitted),
                'seed framing/write/hash mismatch')
        priority, sequence, usec = map(int, match.groups())
        wanted = marker + (b': first info\n' if index == 0 else b': second error\n')
        require(priority == (14 if index == 0 else 11) and message == wanted and
                submitted == b'<' + str(priority).encode() + b'>' + message and
                sequence > previous_seq and usec >= previous_us, 'seed sequence/priority/text mismatch')
        previous_seq, previous_us = sequence, usec
        stamp = ('[%5d.%06d] ' % divmod(usec, 1000000)).encode()
        default.append(stamp + message)
        raw_output.append(('<%d>' % priority).encode() + stamp + message)
    return {'default': default, 'raw': raw_output}


def stable(row, seed):
    require(row['tagged'] == seed['drain']['tagged'], 'target changed during observation')


def matches(row, marker, wanted):
    checked_process(row)
    selected = [line for line in bytes.fromhex(row['stdout_hex']).splitlines(keepends=True) if marker in line]
    return row['status'] == 0 and row['stderr_hex'] == '' and selected == wanted


def alarm(_signal, _frame):
    raise Incomplete('overall helper deadline exceeded')


def main():
    report = {'schema': 'dmesg-live-format-r3', 'result': 'ERROR', 'controls': [],
              'scope': 'actual seeded live default timestamps and valid raw priority/timestamps; stock utility oracle',
              'ring_policy': 'two ASCII writes retained until coordinator discards the guest; no clear or console changes'}
    seed_fd = write_fd = None
    signal.signal(signal.SIGALRM, alarm)
    signal.signal(signal.SIGTERM, alarm)
    signal.alarm(48)
    try:
        report['guard'] = guard()
        candidate_sha = digest(CANDIDATE)
        require(candidate_sha in CANDIDATE_HASHES.values(), 'unreviewed candidate')
        require(digest(UTILITY) == UTILITY_SHA, 'stock utility identity differs')
        report.update(candidate_sha256=candidate_sha, reference_bash_sha256=BASH_SHA,
                      reference_dmesg_sha256=UTILITY_SHA, source_sha256=digest(Path(__file__)),
                      kernel_release=os.uname().release,
                      bash_versions={'candidate': version(CANDIDATE, candidate_sha), 'reference': version(BASH, BASH_SHA)})
        report['console_before_hex'] = Path('/proc/sys/kernel/printk').read_bytes().hex()
        marker = ('dmesg-format-r3-' + uuid.uuid4().hex).encode()
        report['marker'] = marker.decode()
        report['initial_inventory'] = inventory(marker)
        require(not report['initial_inventory']['tagged'], 'marker already present')
        seed_fd = device(os.O_RDONLY); write_fd = device(os.O_WRONLY)
        os.lseek(seed_fd, 0, os.SEEK_END)
        seed = {'start_seek': 'SEEK_END', 'writes': []}; report['seed'] = seed
        for priority, suffix in ((14, b': first info\n'), (11, b': second error\n')):
            data = ('<%d>' % priority).encode() + marker + suffix
            require(len(data) < 128, 'seed size outside bounded domain')
            row = {'input_hex': data.hex(), 'input_sha256': sha(data)}; seed['writes'].append(row)
            row['written'] = os.write(write_fd, data)
            require(row['written'] == len(data), 'short /dev/kmsg write')
        seed['drain'] = drain(seed_fd, marker)
        os.close(seed_fd); seed_fd = None
        os.close(write_fd); write_fd = None
        wanted = expected_lines(seed, marker)
        for control, args in (('default', []), ('raw', ['-r'])):
            row = {'control': control, 'args': args, 'result': 'ERROR'}
            report['controls'].append(row)
            row['before'] = inventory(marker); stable(row['before'], seed)
            reference = run([UTILITY] + args)
            row['reference'] = save('dmesg-format-r3-' + control + '-reference.json', reference)
            row['reference_matches'] = matches(reference, marker, wanted[control])
            row['after_reference'] = inventory(marker); stable(row['after_reference'], seed)
            require(row['reference_matches'], 'stock utility does not match independent raw timestamp/priority oracle')
            candidate = run([CANDIDATE, '--noprofile', '--norc', '-c', 'builtin dmesg "$@"', 'qualification'] + args)
            row['candidate'] = save('dmesg-format-r3-' + control + '-candidate.json', candidate)
            row['candidate_matches'] = matches(candidate, marker, wanted[control])
            row['after_candidate'] = inventory(marker); stable(row['after_candidate'], seed)
            row['result'] = 'PASS' if row['candidate_matches'] else 'FAIL'
        report['result'] = 'PASS' if all(r['result'] == 'PASS' for r in report['controls']) else 'FAIL'
    except Exception as exc:
        report.update(result='ERROR', error=type(exc).__name__ + ': ' + str(exc))
    finally:
        signal.alarm(0)
        cleanup_errors = []
        for fd in (seed_fd, write_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as exc:
                    cleanup_errors.append('device close: ' + str(exc))
        report['device_fds_closed'] = not cleanup_errors
        report['reached_candidate_failures'] = [r['control'] for r in report['controls'] if r['result'] == 'FAIL']
        if 'console_before_hex' in report:
            try:
                report['console_after_hex'] = Path('/proc/sys/kernel/printk').read_bytes().hex()
                if report['console_after_hex'] != report['console_before_hex']:
                    cleanup_errors.append('console settings changed during observation')
            except OSError as exc:
                cleanup_errors.append('console cleanup observation: ' + str(exc))
        if cleanup_errors:
            report.update(result='ERROR', cleanup_error='; '.join(cleanup_errors))
        save(REPORT_NAME, report)
    print(report['result'])
    return {'PASS': 0, 'FAIL': 1, 'ERROR': 125}[report['result']]


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print('observer incomplete: ' + str(exc), file=sys.stderr)
        raise SystemExit(125)
