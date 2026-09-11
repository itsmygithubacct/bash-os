#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare individual builtins with BusyBox applets and installed programs.

All implementations run from the same bash-os executable. External commands
use absolute paths. Fixtures and writable destinations stay in a temporary
directory. A failed output comparison is reported without a speed ratio.
"""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
HOST_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'


def cases():
    rows = []

    def add(name, args=(), *, fixture='text', label=None, host=None,
            applet=None, host_args=None, normalizer='exact', maximum=80,
            output=None):
        rows.append(dict(id=label or name, loadable=name, args=list(args),
                         fixture=fixture, host=host or name,
                         applet=applet or host or name,
                         host_args=list(host_args) if host_args is not None else list(args),
                         normalizer=normalizer, max_passes=maximum, output=output))

    add('cat')
    add('head', ['-n', '100'])
    add('tail', ['-n', '100'])
    add('wc', ['-lwc'], label='wc-counts', normalizer='fields')
    add('wc', ['-m'], label='wc-characters')
    add('wc', ['-L'], label='wc-width')
    add('cut', ['-d', ' ', '-f', '1'])
    add('grep', ['-c', 'alpha'], label='grep-count')
    add('grep', ['alpha'], label='grep-lines')
    add('sed', ['s/alpha/OMEGA/g'])
    add('sort', ['-n'], fixture='numbers', label='sort-numeric')
    add('sort', fixture='text', label='sort-text')
    add('seq', ['100000'], fixture='empty')
    add('tr', ['a-z', 'A-Z'])
    add('uniq', fixture='duplicates')
    add('paste', ['duplicates', 'duplicates'], fixture='empty')
    add('nl', ['-ba'])
    add('rev')
    add('fold', ['-w', '40'])
    add('tac')
    add('comm', ['left', 'right'], fixture='empty')
    add('join', ['left', 'right'], fixture='empty')
    add('expand', ['-t', '8'], fixture='tabs')
    add('unexpand', ['-a'], fixture='spaces')
    add('pr', ['-t'])
    add('colrm', ['4'])
    add('column', ['-t'], fixture='tabs')
    add('strings', ['-n', '4'], fixture='bytes')
    add('od', ['-An', '-tx1'], fixture='bytes')
    add('hexdump', ['-C'], fixture='bytes')
    add('basename', ['/fixture/path/file.txt'], fixture='empty', maximum=200)
    add('dirname', ['/fixture/path/file.txt'], fixture='empty', maximum=200)
    add('readlink', ['link'], fixture='empty', maximum=200)
    add('realpath', ['link'], fixture='empty', maximum=200)
    add('stat', ['-c', '%s', 'text'], fixture='empty', maximum=200)
    add('ls', ['-1', 'tree'], fixture='empty')
    add('find', ['tree', '-type', 'f'], fixture='empty', normalizer='lines')
    add('cmp', ['text', 'copy'], fixture='empty')
    add('diff', ['text', 'copy'], fixture='empty')
    add('dd', ['if=text', 'bs=64K', 'status=none'], fixture='empty')
    add('cp', ['text', 'copied'], fixture='empty', output='copied')
    add('cksum')
    add('bashbase64', ['-w', '0'], fixture='bytes', host='base64')
    add('bashjson', ['get', '.answer'], fixture='object', host='jq', host_args=['.answer'])
    add('awk', ['{sum += $2} END {print sum}'], fixture='records')
    add('jq', ['-c', '[.[] | select(. > 50)]'], fixture='array')
    add('bc', fixture='arithmetic')
    add('expr', ['123', '*', '456'], fixture='empty', maximum=200)
    add('crypto', ['sha256', '-x'], fixture='blob', host='sha256sum',
        host_args=[], normalizer='digest')
    add('uname', fixture='empty', maximum=200)
    add('whoami', fixture='empty', maximum=200)
    add('logname', fixture='empty', maximum=200)
    add('hostname', fixture='empty', maximum=200)
    add('id', ['-u'], label='id-uid', fixture='empty', maximum=200)
    add('printenv', ['LC_ALL'], label='printenv-lcall', fixture='empty', maximum=200)
    add('touch', ['touched'], fixture='empty', output='touched', maximum=200)
    add('mkdir', ['-p', 'mdir'], fixture='empty', maximum=200)
    add('chmod', ['644', 'text'], fixture='empty', maximum=200)
    add('date', ['-u', '+%Y'], label='date-year', fixture='empty', maximum=200)
    add('getconf', ['PAGE_SIZE'], fixture='empty', maximum=200)
    add('pathchk', ['text'], fixture='empty', maximum=200)
    add('ln', ['-f', 'text', 'lnout'], fixture='empty', output='lnout', maximum=200)
    add('sync', fixture='empty', maximum=20)
    add('rm', ['-f', 'nosuch'], fixture='empty', maximum=200)
    add('chown', ['pleb', 'text'], fixture='empty', maximum=200)
    add('chgrp', ['pleb', 'text'], fixture='empty', maximum=200)
    add('sleep', ['0'], fixture='empty', maximum=200)
    add('nice', ['-n', '0', '/bin/true'], fixture='empty', maximum=200)
    add('nohup', ['/bin/true'], fixture='empty', maximum=200)
    add('setsid', ['/bin/true'], fixture='empty', maximum=200)
    add('flock', ['-n', 'lockfile', '/bin/true'], fixture='empty', maximum=200)
    add('taskset', ['-p', '1'], fixture='empty', maximum=200)
    add('ionice', ['-p', '1'], fixture='empty', maximum=200)
    add('env', ['-i', 'FOO=bar', '/usr/bin/printenv', 'FOO'], fixture='empty', maximum=200)
    add('sysctl', ['-n', 'kernel.osrelease'], fixture='empty', maximum=200)
    add('id', ['-un'], label='id-user', fixture='empty', maximum=200)
    add('id', ['-gn'], label='id-group', fixture='empty', maximum=200)
    add('hostname', ['-s'], label='hostname-s', fixture='empty', maximum=200)
    add('uname', ['-s'], label='uname-s', fixture='empty', maximum=200)
    add('date', ['-u', '+%Y-%m-%d'], label='date-ymd', fixture='empty', maximum=200)
    add('getconf', ['_NPROCESSORS_ONLN'], label='getconf-nproc', fixture='empty', maximum=200)
    # POSIX df -P on / changes used-counts between calls. /dev is a
    # stable udev pin: GNU, BusyBox and the builtin match on fields.
    add('df', ['-P', '/dev'], fixture='empty', normalizer='fields', maximum=200)
    add('free', ['-k'], fixture='empty', normalizer='fields', maximum=200)
    # Default uptime includes the wall clock and load averages. -s is boot
    # time from btime and is stable; GNU matches the builtin exactly.
    add('uptime', ['-s'], fixture='empty', normalizer='exact', maximum=200)
    # Previously unmeasured POSIX/text tools with GNU- or BusyBox-matching
    # output on these fixtures. Mutators here overwrite the same dest bytes
    # on every pass.
    add('tee')
    add('hostid', fixture='empty', maximum=200)
    add('timeout', ['1', '/bin/true'], fixture='empty', maximum=200)
    add('du', ['-b', 'tree'], fixture='empty', label='du-tree')
    add('du', ['-b', 'text'], fixture='empty', label='du-file')
    add('truncate', ['-s', '4096', 'truncout'], fixture='empty', output='truncout', maximum=200)
    add('ar', ['t', 'tiny.a'], fixture='empty', maximum=200)
    add('zstdcat', ['text.zst'], fixture='empty')
    add('zstd', ['-d', '-c', 'text.zst'], fixture='empty', label='zstd-decompress')
    add('zcat', ['text.gz'], fixture='empty')
    add('file', ['text'], fixture='empty', maximum=200)
    add('split', ['-l', '1000', 'text'], fixture='empty', output='xaa')
    add('csplit', ['text', '10', '20'], fixture='empty', output='xx00')
    add('xargs', ['-n', '10', '/bin/echo'], fixture='left')
    add('opt', ['-o', 'ab:', '--', '-a', '-b', 'x'], fixture='empty',
        host='getopt', maximum=200)
    add('uuencode', ['bytes'], fixture='bytes')
    add('uudecode', ['-o', '-'], fixture='uuencoded')
    add('strftime', ['%Y-%m-%d', '0'], fixture='empty', host='date',
        host_args=['-u', '-d', '@0', '+%Y-%m-%d'], maximum=200)
    add('strptime', ['1970-01-01 00:00:00', '%Y-%m-%d %H:%M:%S'], fixture='empty',
        host='date', host_args=['-u', '-d', '1970-01-01 00:00:00', '+%s'], maximum=200)
    add('zlib', ['-f', 'gzip', 'text.gz'], fixture='empty', host='gzip',
        host_args=['-dc', 'text.gz'])
    add('pax', ['-f', 'tiny.tar'], fixture='empty', host='tar',
        host_args=['tf', 'tiny.tar'])
    add('tput', ['cols'], fixture='empty', maximum=200)
    add('less', ['text'], fixture='empty')
    add('chrt', ['-m'], fixture='empty', maximum=200)
    add('signal', ['-n', 'TERM'], fixture='empty', host='kill',
        host_args=['-l', 'TERM'], maximum=200)
    add('cal', ['2', '2024'], fixture='empty', normalizer='fields', maximum=200)
    add('ed', ['-s', 'left'], fixture='edscript')
    add('finfo', ['-s', 'text'], fixture='empty', host='stat',
        host_args=['-c', '%s', 'text'], maximum=200)
    add('fltexpr', ['-p', '1+2*3'], fixture='empty', host='awk',
        host_args=['BEGIN{print 1+2*3}'], maximum=200)
    add('pcre', ['grep', 'alpha', 'text'], fixture='empty', host='grep',
        host_args=['-P', 'alpha', 'text'])
    add('uclampset', ['-p', '1'], fixture='empty', maximum=200)
    add('tz', ['convert', '0', '-z', 'UTC'], fixture='empty', host='date',
        host_args=['-u', '-d', '@0', '+%Y-%m-%d %H:%M:%S UTC +0000'], maximum=200)
    add('ip', ['-br', 'link', 'show', 'lo'], fixture='empty', maximum=200)
    add('tinfo', ['getnum', 'cols'], fixture='empty', host='tput',
        host_args=['cols'], maximum=200)
    return rows


def fixtures(root):
    rng = random.Random(20260908)
    words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
    text = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n'
                   for _ in range(12000)).encode()[:423000]
    data = {
        'empty': b'', 'text': text, 'copy': text,
        'numbers': ''.join(f'{rng.randrange(-1000000, 1000001)}\n'
                           for _ in range(50000)).encode(),
        'duplicates': ''.join(f'{i//3:08d} word\n' for i in range(120000)).encode(),
        'left': ''.join(f'{i:06d} left\n' for i in range(10000)).encode(),
        'right': ''.join(f'{i:06d} right\n' for i in range(0, 10000, 2)).encode(),
        'tabs': b'alpha\tbeta\tgamma\n'*20000,
        'spaces': b'alpha   beta    gamma\n'*20000,
        'bytes': bytes(range(256))*256,
        'blob': bytes(range(256))*4096,
        'records': ''.join(f'key{i%13} {i%101}\n' for i in range(20000)).encode(),
        'array': json.dumps([i%101 for i in range(10000)]).encode()+b'\n',
        'object': json.dumps({'answer':42, 'data':[i%101 for i in range(10000)]}).encode()+b'\n',
        'arithmetic': b'scale=20; sqrt(2)\n',
        'edscript': b'1,2p\nq\n',
    }
    for name, value in data.items():
        (root/name).write_bytes(value)
    (root/'link').symlink_to('text')
    (root/'tree').mkdir()
    for i in range(256):
        (root/'tree'/f'item-{i:04d}.txt').write_bytes(b'fixture\n')
    hashes = {name: {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
              for name, value in data.items()}

    def record(path: Path, key: str):
        blob = path.read_bytes()
        hashes[key] = {'bytes': len(blob), 'sha256': hashlib.sha256(blob).hexdigest()}

    (root/'mem').write_bytes(b'hello')
    record(root/'mem', 'mem')
    ar = shutil.which('ar', path=HOST_PATH)
    if ar:
        subprocess.check_call([ar, 'rcs', str(root/'tiny.a'), 'mem'], cwd=root)
        record(root/'tiny.a', 'tiny.a')
    tar = shutil.which('tar', path=HOST_PATH)
    if tar:
        subprocess.check_call([tar, '-cf', 'tiny.tar', 'mem'], cwd=root)
        record(root/'tiny.tar', 'tiny.tar')
    gzip = shutil.which('gzip', path=HOST_PATH)
    if gzip:
        with (root/'text.gz').open('wb') as out:
            subprocess.check_call([gzip, '-n', '-c', 'text'], cwd=root, stdout=out)
        record(root/'text.gz', 'text.gz')
    zstd = shutil.which('zstd', path=HOST_PATH)
    if zstd:
        with (root/'text.zst').open('wb') as out:
            subprocess.check_call([zstd, '-q', '-c', '-3', 'text'], cwd=root, stdout=out)
        record(root/'text.zst', 'text.zst')
    busybox = shutil.which('busybox', path=HOST_PATH)
    if busybox:
        encoded = subprocess.check_output(
            [busybox, 'uuencode', 'bytes'], cwd=root, input=(root/'bytes').read_bytes())
        (root/'uuencoded').write_bytes(encoded)
        record(root/'uuencoded', 'uuencoded')
    return hashes


def normalized(data, mode):
    if mode == 'fields':
        return data.split()
    if mode == 'lines':
        return sorted(data.splitlines())
    if mode == 'digest':
        # Keep every record, including malformed empty ones. A blank line
        # must fail output validation rather than abort the whole report.
        return [line.split(maxsplit=1)[0] if line.strip() else b''
                for line in data.splitlines()]
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'out/bash')
    parser.add_argument('--busybox', default=shutil.which('busybox', path=HOST_PATH))
    parser.add_argument('--runs', type=int, default=5)
    parser.add_argument('--passes', type=int, help='Fixed invocations per batch; otherwise calibrated')
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--only', help='Comma-separated loadable names or case IDs')
    parser.add_argument('--quick', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error('--runs must be positive')
    if args.passes is not None and args.passes < 1:
        parser.error('--passes must be positive')
    binary = args.binary.resolve(strict=True)
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})
    # Avoid startup files, exported functions, locale and tool-option overrides.
    environment = {'PATH':'', 'LC_ALL':'C', 'TZ':'UTC', 'TERM':'dumb'}
    applets = set()
    busybox = str(Path(args.busybox).resolve()) if args.busybox else None
    if busybox:
        applets = set(subprocess.check_output([busybox, '--list'], text=True).split())
    selected = set(args.only.split(',')) if args.only else None
    inventory = cases()
    if selected:
        unknown = selected - {x for row in inventory for x in (row['id'], row['loadable'])}
        if unknown:
            parser.error('Unknown cases: '+', '.join(sorted(unknown)))
        inventory = [row for row in inventory if selected & {row['id'],row['loadable']}]
    report = {
        'schema':1, 'date':time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'binary':binary.name, 'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'kernel':platform.release(), 'architecture':platform.machine(),
        'cpus':sorted(os.sched_getaffinity(0)), 'load_average_start':os.getloadavg(),
        'runs':1 if args.quick else args.runs,
        'method':'Same bash-os shell; builtin or absolute external command; median untraced batch wall time; stdout /dev/null; warm file cache',
        'cases':[],
    }
    for line in Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('model name'):
            report['cpu_model'] = line.split(':',1)[1].strip()
            break
    report['versions'] = {}
    for name, cmd in [('bash',[str(binary),'--version']), ('coreutils',['/usr/bin/wc','--version']),
                      ('grep',['/usr/bin/grep','--version']), ('busybox',[busybox,'--help'] if busybox else [])]:
        if cmd:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            report['versions'][name] = (p.stdout or p.stderr).splitlines()[0]
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.output.write_text(json.dumps(report, indent=2)+'\n')

    with tempfile.TemporaryDirectory(prefix='bash-os-loadable-bench-') as directory:
        root = Path(directory)
        report['fixtures'] = fixtures(root)

        def run(command, fixture, count, *, capture=False):
            script = 'input=$1; count=$2; shift 2; for ((i=0;i<count;i++)); do "$@" < "$input" || exit; done'
            argv = [str(binary),'--noprofile','--norc','-c',script,'bench',fixture,str(count),*command]
            with tempfile.TemporaryFile() as output:
                start = time.perf_counter_ns()
                try:
                    p = subprocess.run(argv, cwd=root, env=environment,
                                       stdout=output if capture else subprocess.DEVNULL,
                                       # Waiting for pipe EOF avoids wait(timeout)'s
                                       # polling intervals rounding up short timings.
                                       stderr=subprocess.PIPE, timeout=30)
                except subprocess.TimeoutExpired:
                    return {'status':'timeout'}
                elapsed = (time.perf_counter_ns()-start)/1e6
                err = p.stderr[:2048].decode(errors='replace')
                if p.returncode:
                    return {'status':'error','returncode':p.returncode,'stderr':err}
                output.seek(0)
                return {'status':'ok','ms':elapsed,'data':output.read() if capture else b'', 'stderr':err}

        for case in inventory:
            name = case['loadable']
            row = {k:v for k,v in case.items() if k not in ['max_passes']}
            row['results'] = {}
            commands = {'bashos':[name,*case['args']]}
            external = shutil.which(case['host'], path=HOST_PATH)
            if external:
                commands['external'] = [external,*case['host_args']]
            else:
                row['results']['external'] = {'status':'unavailable'}
            if busybox and case['applet'] in applets:
                commands['busybox'] = [busybox,case['applet'],*case['host_args']]
            else:
                row['results']['busybox'] = {'status':'unavailable'}
            initial = {}
            for implementation, command in commands.items():
                if case['output']:
                    (root/case['output']).unlink(missing_ok=True)
                result = run(command, case['fixture'], 1, capture=True)
                if result['status'] == 'ok' and case['output']:
                    result['data'] = (root/case['output']).read_bytes() if (root/case['output']).is_file() else b''
                initial[implementation] = result
            reference = next((label for label in ['external','busybox']
                              if label in initial and initial[label]['status']=='ok'), None)
            if reference is None:
                for label,result in initial.items():
                    row['results'][label] = {k:v for k,v in result.items() if k not in ['data','ms']}
                    if result['status'] == 'ok':
                        row['results'][label]['status'] = 'no-reference'
                report['cases'].append(row); save()
                print(case['id']+': no successful reference', flush=True)
                continue
            row['reference'] = reference
            expected = initial[reference]['data']
            accepted = []
            for label,result in initial.items():
                if result['status'] != 'ok':
                    row['results'][label] = {k:v for k,v in result.items() if k not in ['data','ms']}
                elif normalized(result['data'],case['normalizer']) != normalized(expected,case['normalizer']):
                    row['results'][label] = {'status':'output-mismatch',
                        'expected_sha256':hashlib.sha256(expected).hexdigest(),
                        'actual_sha256':hashlib.sha256(result['data']).hexdigest(),
                        'expected_sample_b64':base64.b64encode(expected[:180]).decode(),
                        'actual_sample_b64':base64.b64encode(result['data'][:180]).decode()}
                else:
                    accepted.append(label)
            probe_label = 'bashos' if 'bashos' in accepted else reference
            probe = run(commands[probe_label],case['fixture'],5)
            if probe['status'] != 'ok':
                row['results'][probe_label] = {k:v for k,v in probe.items() if k not in ['data','ms']}
                report['cases'].append(row); save(); continue
            passes = 1 if args.quick else (args.passes or max(3,min(case['max_passes'],math.ceil(75/(probe['ms']/5)))))
            row['passes'] = passes
            validation_passes = max(3, passes)
            row['validation_passes'] = validation_passes
            # Validate a complete batch too: stale stdio state can silently
            # make later invocations produce no output despite success status.
            for label in list(accepted):
                batch = run(commands[label],case['fixture'],validation_passes,capture=True)
                actual = batch.get('data',b'')
                wanted = expected*validation_passes
                if case['output']:
                    actual = (root/case['output']).read_bytes()
                    wanted = expected
                if batch['status'] != 'ok' or normalized(actual,case['normalizer']) != normalized(wanted,case['normalizer']):
                    accepted.remove(label)
                    row['results'][label] = {'status':'batch-mismatch','stderr':batch.get('stderr',''),
                        'expected_bytes':len(wanted),'actual_bytes':len(actual),
                        'expected_sha256':hashlib.sha256(wanted).hexdigest(),
                        'actual_sha256':hashlib.sha256(actual).hexdigest()}
            samples = {label:[] for label in accepted}
            # The full-batch comparison also warms the data and implementation.
            for round_number in range(report['runs']):
                order = accepted[round_number%len(accepted):]+accepted[:round_number%len(accepted)] if accepted else []
                if round_number%2:
                    order.reverse()
                for label in order:
                    timed = run(commands[label],case['fixture'],passes)
                    if timed['status'] != 'ok':
                        row['results'][label] = {k:v for k,v in timed.items() if k not in ['data','ms']}
                    else:
                        samples[label].append(timed['ms'])
            for label,values in samples.items():
                if len(values) == report['runs']:
                    row['results'][label] = {'status':'ok','median_ms':round(statistics.median(values),3),
                        'min_ms':round(min(values),3),'max_ms':round(max(values),3),
                        'runs_ms':[round(value,3) for value in values]}
            report['cases'].append(row); save()
            print(case['id']+': '+', '.join(label+'='+str(result.get('median_ms',result['status']))
                                          for label,result in row['results'].items()),flush=True)
    report['load_average_end'] = os.getloadavg()
    save()


if __name__ == '__main__':
    main()
