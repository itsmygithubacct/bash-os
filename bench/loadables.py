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
            output=None, reference=None, mode='inprocess', reset=None,
            env=None, work=None):
        # reference='self' measures a loadable that has no external or applet
        # counterpart. Pass 1 becomes its own expected output, so the repeated
        # batch is a determinism check and the reference columns stay empty.
        # A self-timed figure is comparable only with another run of the same
        # case on the same host; it is never presented as a ratio.
        rows.append(dict(id=label or name, loadable=name, args=list(args),
                         fixture=fixture, host=host or name,
                         applet=applet or host or name,
                         host_args=list(host_args) if host_args is not None else list(args),
                         normalizer=normalizer, max_passes=maximum, output=output,
                         reference=reference, mode=mode, reset=reset,
                         env=dict(env or {}), work=work))

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
    # No live `free` case: /proc/meminfo's counters move between the reference
    # call and the batch, so the comparison can only ever fail, and it was
    # omitted at publish time on every refresh. free honours BASHOS_PROC_ROOT,
    # so free-procfixture below measures it against a pinned meminfo instead,
    # and tests/free-check.sh holds the GNU parity that the ratio used to claim.
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
    add('tput', ['lines'], fixture='empty', label='tput-lines', maximum=200)
    add('signal', ['-s', '15'], fixture='empty', host='kill',
        host_args=['-l', '15'], label='signal-name', maximum=200)
    add('finfo', ['-o', 'text'], fixture='empty', host='stat',
        host_args=['-c', '%a', 'text'], label='finfo-mode', maximum=200)
    add('chrt', ['-p', '1'], fixture='empty', label='chrt-pid1', maximum=200)
    add('zlib', ['-f', 'xz', 'text.xz'], fixture='empty', host='xz',
        host_args=['-dc', 'text.xz'], label='zlib-xz')
    add('zlib', ['-f', 'bzip2', 'text.bz2'], fixture='empty', host='bzip2',
        host_args=['-dc', 'text.bz2'], label='zlib-bzip2')
    add('coreutils', ['numfmt', '--to=iec', '1024', '4096'], fixture='empty',
        host='numfmt', host_args=['--to=iec', '1024', '4096'],
        label='coreutils-numfmt', maximum=200)
    add('coreutils', ['tsort', 'chain'], fixture='empty', host='tsort',
        host_args=['chain'], label='coreutils-tsort', maximum=200)
    add('coreutils', ['factor', '1234567890', '97'], fixture='empty',
        host='factor', host_args=['1234567890', '97'],
        label='coreutils-factor', maximum=200)
    add('coreutils', ['groups'], fixture='empty', host='groups',
        host_args=[], label='coreutils-groups', maximum=200)
    add('coreutils', ['install', '-m', '644', 'text', 'installed'], fixture='empty',
        host='install', host_args=['-m', '644', 'text', 'installed'],
        output='installed', label='coreutils-install')
    add('lsblk', ['-d', '-n', '-o', 'NAME'], fixture='empty', maximum=200)
    add('binhex', fixture='bytes', host='hexdump',
        host_args=['-ve', '/1 "%02x"'])
    add('binhex', ['-d'], fixture='hexbytes', host='xxd',
        host_args=['-r', '-p'], label='binhex-decode')
    add('prlimit', ['--nofile'], fixture='empty',
        host_args=['-o', 'RESOURCE,SOFT,HARD', '--noheadings', '--nofile'],
        maximum=200)
    add('prlimit', ['--cpu'], fixture='empty',
        host_args=['-o', 'RESOURCE,SOFT,HARD', '--noheadings', '--cpu'],
        label='prlimit-cpu', maximum=200)
    add('fincore', ['-n', 'text'], fixture='empty',
        host_args=['-n', '--bytes', 'text'], normalizer='fields', maximum=200)
    add('col', ['-b'], fixture='left')
    # The large fixture is truncated to a byte count, so its last line has no
    # newline. util-linux col terminates its output; the builtin now does too,
    # which is what kept this case out of the table before.
    add('col', ['-b'], fixture='text', label='col-text',
        work='423,000 bytes filtered, unterminated final line')
    add('coreutils', ['factor', '111111111111'], fixture='empty',
        host='factor', host_args=['111111111111'],
        label='coreutils-factor-big', maximum=200)
    add('coreutils', ['fmt', '-w', '20', 'left'], fixture='empty',
        host='fmt', host_args=['-w', '20', 'left'], label='coreutils-fmt')
    add('coreutils', ['tac', 'left'], fixture='empty',
        host='tac', host_args=['left'], label='coreutils-tac')
    add('bignum', ['add', '999999999999999999', '1'], fixture='empty',
        host='expr', host_args=['999999999999999999', '+', '1'], maximum=200)
    add('bignum', ['mul', '123', '456'], fixture='empty',
        host='expr', host_args=['123', '*', '456'],
        label='bignum-mul', maximum=200)
    add('ncdu', ['-a', '-p', 'tree'], fixture='empty', host='du',
        host_args=['--apparent-size', '--block-size=1', 'tree'],
        label='ncdu-print', maximum=200)
    add('blkid', ['-s', 'TYPE', '-o', 'value', 'disk.img'], fixture='empty',
        label='blkid-type', maximum=200)
    add('blkid', ['-s', 'LABEL', '-o', 'value', 'disk.img'], fixture='empty',
        label='blkid-label', maximum=200)
    add('man', ['-w', 'ls'], fixture='empty', maximum=200)

    # Cases from the 2026-09-12 metric-coverage pass: every loadable that had no
    # number before. Each was designed against the loadable's C source,
    # adversarially verified, then validated against this harness.
    # --- block-device ---
    # Read-only on a regular-file image: bfd_list_one opens O_RDONLY and the
    # BLKSSZGET/BLKGETSIZE64 pair sits in the S_ISBLK branch, which a file
    # never takes. util-linux and BusyBox print unrelated reports, so the
    # figure is self-timed.
    add('fdisk', ['-l', 'parts.img'], fixture='empty', label='fdisk-list',
        reference='self', maximum=200,
        work='one 512-byte MBR probe, the 512-byte GPT header and the whole '
             '16 KiB 128-entry partition array in one pread, two CRC32 passes '
             '(92-byte header, 16 KiB array), 134 formatted lines / 15,587 bytes')
    # A different path from fdisk-list: bfd_table_load plus bfd_table_validate,
    # including the quadratic overlap scan. --repair, the only serializing
    # verb, is never used.
    add('fdisk', ['--verify', 'parts.img'], fixture='empty', label='fdisk-verify',
        reference='self', maximum=200,
        work='128-partition GPT table loaded and validated: header and 16 KiB '
             'entry-array CRC32 plus the pairwise overlap scan over 8,128 slot '
             'pairs, one 39-byte verdict line')
    # The harness unlinks `output` before pass 1 while both implementations
    # open the destination O_RDWR without O_CREAT, so reset has to recreate it.
    # BusyBox mkswap rejects -U, and -U is what makes the image deterministic.
    add('mkswap', ['-U', 'deadbeef-0000-4000-8000-000000000001', '-L', 'fixture',
                   'swapdest.img'], fixture='empty', output='swapdest.img',
        reset='rm -f swapdest.img; truncate -s 8388608 swapdest.img', maximum=200,
        work='one 4096-byte swap v1 header composed and pwritten at offset 0 of '
             'an 8 MiB file, then fsync; the 8,388,608-byte destination image is '
             'the compared artifact')
    # -n (no-act) on both sides: wipefs opens O_RDWR only for -a without -n.
    # util-linux -i is --noheadings and takes no argument, so both argument
    # lists must name the image exactly 32 times; 33 on one side silently
    # becomes an output mismatch.
    add('wipefs', ['-n'] + ['swapsig.img']*32, fixture='empty',
        host_args=['-n', '-O', 'OFFSET,TYPE,DEVICE', '-i'] + ['swapsig.img']*32,
        normalizer='fields', maximum=200,
        work='32 image opens x 10 fixed-offset pread signature probes each '
             '(2 swap magics, 8 filesystem magics) = 320 preads, 32 rows / '
             '736 bytes printed')
    # show_swaps() returns before the swapon(2) loop, so -s enables nothing.
    # The Used column of /proc/swaps is a live counter, so the comparison is
    # pinned to the device list, which is what swapon -s actually reports.
    add('swapon', ['-s'], fixture='empty', normalizer='digest', maximum=200,
        work="/proc/swaps read and echoed through a 1024-byte fgets loop: one "
             "header line plus one line per swap area")
    # Dry run only: bf_trim_one returns at the dry-run branch before geteuid,
    # open and the FITRIM ioctl, and -a/-A are not used, so the live mount
    # table is never consulted. The `left` fixture is already fstab-shaped and
    # its field 2 names a file in the fixture root, so every entry resolves.
    add('fstrim', ['-n', '-I', 'left'], fixture='empty', reference='self',
        work='10,000 fstab-shaped lines parsed from the left fixture, 10,000 '
             'stat() calls and 10,000 lines / 280,000 bytes printed')
    # -n clears repair_dirty, so the O_WRONLY repair reopen is unreachable and
    # the image is only read. e2fsck reports the volume label with different
    # counters and wording, and /usr/sbin/fsck would resolve the name against
    # the live mount table, so neither is a reference here.
    add('fsck', ['-n', 'disk.img'], fixture='empty', reference='self', maximum=200,
        work='the 1024-byte ext2 superblock at offset 1024 of the 8 MiB disk.img '
             'read and decoded, the sanity battery over block size, blocks and '
             'inodes per group, inode size, group-count consistency and '
             'errors-behaviour, variant classification, one 47-byte line')
    # --- process-query ---
    # The /proc and utmp readers. BASHOS_PROC_ROOT, BASHW_DEV_DIR and
    # BASHDMESG_DEV_KMSG_FILE point the walk at a fixed fixture instead of the
    # live kernel, which is what turns a moving counter into a fixed workload.
    # Where no external program can be aimed at the same fixture, the case is
    # self-referenced and the repeated batch is a determinism check.
    add('ps', ['-ef'], fixture='empty', label='ps-procfixture', reference='self',
        normalizer='lines', env={'BASHOS_PROC_ROOT': 'procfix'}, maximum=80,
        work='512 fixture PIDs walked; 1536 proc files (stat+status+cmdline) parsed; 513 rows / 45,209 bytes emitted')
    add('pgrep', ['-x', 'kthreadd'], fixture='empty', label='pgrep-kthreadd',
        maximum=200,
        work='one full live /proc walk: readdir plus a /proc/PID/comm read for every PID on the host; exactly one PID matches, 2 bytes emitted')
    add('killall5', ['-n'], fixture='empty', label='killall5-dryrun',
        reference='self', normalizer='lines', env={'BASHOS_PROC_ROOT': 'procfix'},
        maximum=80,
        work='512 fixture PIDs enumerated; a stat read (session id) and a cmdline read per PID; 512 PIDs / 2,260 bytes emitted, zero signals')
    add('pidof', ['kthreadd'], fixture='empty', label='pidof-kthreadd', maximum=200,
        work='one full live /proc walk: a comm read for every PID plus a cmdline read for every PID whose comm misses; exactly one PID matches, 2 bytes emitted')
    add('slabtop', ['-o'], fixture='empty', label='slabtop-procfixture',
        reference='self', env={'BASHOS_PROC_ROOT': 'procfix'}, maximum=200,
        work='37,616 bytes of slabinfo parsed into 512 cache rows, qsorted by object count; a 4-line summary plus 512 rows / 39,271 bytes emitted')
    add('vmstat', ['-d'], fixture='empty', label='vmstat-diskstats',
        reference='self', env={'BASHOS_PROC_ROOT': 'procfix'}, maximum=200,
        work='21,056 bytes of diskstats parsed: 256 device lines of 17 fields; 2 header lines plus 256 rows / 22,439 bytes emitted')
    add('w', ['utmpfix'], fixture='empty', label='w-utmpfixture', reference='self',
        env={'BASHW_DEV_DIR': 'tree'}, maximum=80,
        work='1,572,864 bytes of utmp read as 4096 384-byte records; 3584 USER_PROCESS rows formatted in 8 columns / 3585 lines, 211,524 bytes emitted')
    add('who', ['-q', 'utmpfix'], fixture='empty', label='who-quick', maximum=80,
        work='1,572,864 bytes of utmp read as 4096 384-byte records, filtered to 3584 USER_PROCESS entries; 3584 names plus the "# users=" tally / 32,269 bytes emitted')
    add('utmp', ['dump', 'utmpfix'], fixture='empty', label='utmp-dump',
        reference='self', maximum=80,
        work='1,572,864 bytes of utmp read as 4096 384-byte records; 3584 records scrubbed over 320 fixed-width bytes each and formatted / 3584 lines, 1,272,320 bytes emitted')
    add('free', ['-k'], fixture='empty', label='free-procfixture', reference='self',
        env={'BASHOS_PROC_ROOT': 'procfix'}, maximum=200,
        work='one 1,564-byte 50-key meminfo opened and parsed; three formatted rows / 207 bytes emitted')
    add('procstat', ['pidstat'], fixture='empty', label='procstat-pidstat',
        reference='self', env={'BASHOS_PROC_ROOT': 'procfix'}, maximum=80,
        work='scandir with versionsort over 512 fixture pid dirs, then a 52-field stat parse per PID; 513 lines / 17,985 bytes emitted')
    add('procstat', ['pmap', '100'], fixture='empty', label='procstat-pmap',
        reference='self', env={'BASHOS_PROC_ROOT': 'procfix'}, maximum=80,
        work='135,424 bytes of maps parsed: 2048 mappings (range, mode, offset, dev, inode, path) with the KiB accumulator; 2051 lines / 100,398 bytes emitted')
    add('lsof', ['-u', 'fixture-no-such-user'], fixture='empty', label='lsof-walk',
        reference='self', maximum=200,
        work='one full live /proc walk: readdir plus a /proc/PID/status read and a getpwuid() for every PID on the host; no PID matches, so only the 43-byte header is emitted')
    add('dmesg', fixture='empty', label='dmesg-kmsgfixture', reference='self',
        env={'BASHDMESG_DEV_KMSG_FILE': 'kmsgfix'}, maximum=80,
        work='524,288 bytes of /dev/kmsg records read in 8192-byte chunks; 4096 records decoded (priority/seq/us/flag plus text) and re-emitted with the monotonic timestamp column / 4096 lines, 516,443 bytes')
    # --- fs-metadata ---
    add('link', ['text', 'lnhard'], fixture='empty', output='lnhard',
        reset='rm -f lnhard', maximum=200,
        work='1 link(2) per pass creating a hard link to the 423,000-byte text '
             'fixture; the 423,000-byte destination is byte-compared')
    add('unlink', ['victim'], fixture='empty', maximum=200,
        reset='if [[ -e victim ]]; then exit 1; fi; : > victim',
        work='1 unlink(2) per pass on a freshly created empty directory entry')
    add('rmdir', ['victimdir'], fixture='empty', reset='mkdir victimdir', maximum=200,
        work='1 rmdir(2) per pass on a freshly created empty directory')
    add('mkfifo', ['fifo0'], fixture='empty', maximum=200,
        reset='[[ -p fifo0 ]] || exit 1; rm -f fifo0',
        work='1 mkfifo(2) per pass (mode a=rw & ~umask), plus the mode parse')
    add('mv', [f'mvsrc{i:02d}' for i in range(16)]+['moved'], fixture='empty', maximum=200,
        reset='if [[ -e mvsrc00 ]]; then exit 1; fi; '
              'for f in mvsrc00 mvsrc01 mvsrc02 mvsrc03 mvsrc04 mvsrc05 mvsrc06 mvsrc07 '
              'mvsrc08 mvsrc09 mvsrc10 mvsrc11 mvsrc12 mvsrc13 mvsrc14 mvsrc15; '
              'do : > "$f"; done',
        work='16 rename(2) per pass (16 sources moved into the moved/ directory), '
             "plus mv's per-operand stat and basename work")
    # A gnu-class mktemp case cannot do more than one template per pass: GNU and
    # BusyBox both refuse a second one. The digest normalizer drops the random
    # suffix, so the reset carries the assertion instead - exactly one matching
    # regular file must exist, and it is removed for the next pass.
    add('mktemp', ['-q', 'mktmp-fixture mktmp.XXXXXX'], fixture='empty',
        normalizer='digest', maximum=200,
        reset='m=(mktmp-fixture?mktmp.*); [[ ${#m[@]} -eq 1 && -f ${m[0]} ]] || exit 1; '
              'rm -f "${m[0]}"',
        work='1 template expansion + mkstemp(3) (open O_CREAT|O_EXCL + close, file '
             'kept) + 1 line printed, per pass; identical work on all three arms')
    # A regular-file stdin makes every implementation print "not a tty" and exit
    # 1. The ptmx fixture gives stdin a pty master instead, which all three
    # arms name identically.
    add('tty', fixture='ptmx', maximum=200,
        work='1 ttyname(3) on a pty-master stdin per pass (readlink /proc/self/fd/0 '
             '+ stat + isatty), 10 bytes printed')
    # The reset both asserts the previous pass set the bit and clears it again,
    # so neither arm can short-circuit the write ioctl on a later pass.
    add('chattr', ['-R', '+A', 'attrtree'], fixture='empty', maximum=60,
        reset='lsattr -d attrtree > .attrchk; read -r f _ < .attrchk; '
              '[[ $f == *A* ]] || exit 1; chattr -R -A attrtree',
        work='513 paths walked per pass (512 files + the directory): open + '
             'FS_IOC_GETFLAGS + FS_IOC_SETFLAGS + close on each, on both arms, because '
             'the reset clears the +A bit before every pass; plus a 512-entry readdir walk')
    # e2fsprogs lsattr prints a different flag field, so no normalizer aligns
    # the two honestly and BusyBox has no applet: self-timed only.
    add('lsattr', ['tree'], fixture='empty', normalizer='lines', reference='self',
        maximum=100,
        work='256 files: open + FS_IOC_GETFLAGS + close + flag-string format each, '
             '8,704 bytes of output per pass')
    # The acl package is not installed and BusyBox has no applet, so getfacl and
    # setfacl are self-timed. setfacl gets its own directory because it rewrites
    # every file it is given.
    add('getfacl', [f'acls/f{i:02d}' for i in range(32)], fixture='empty',
        reference='self', maximum=80,
        work='32 files per pass: lstat + getpwuid + getgrgid + getxattr each; 16 of '
             'them decode a 6-entry system.posix_acl_access blob and 16 synthesise '
             'base entries from the mode; 3,120 bytes of output per pass')
    add('setfacl', ['-m', 'u:1000:rwx,g:1000:r-x']+[f'aclset/f{i:02d}' for i in range(32)],
        fixture='empty', reference='self', maximum=200,
        reset='xattr read aclset/f00 system.posix_acl_access > .aclchk || exit 1; '
              'stat -c %s .aclchk > .aclsz; read -r n < .aclsz; [[ $n -eq 52 ]] || exit 1; '
              'xattr remove aclset/f00 system.posix_acl_access',
        work='32 files per pass: getxattr of the current ACL + parse of a 2-entry spec '
             '+ mask recomputation + canonical-order sort + setxattr of a 52-byte ACL '
             'each; encode_and_set() calls setxattr unconditionally, so every pass '
             'really writes all 32')
    # BusyBox getfattr renders name="value" and cannot represent the binary
    # payload at all, so neither xattr case has an alignable comparator.
    add('xattr', ['list', 'xattrs'], fixture='empty', label='xattr-list',
        reference='self', maximum=200,
        work='two-call listxattr sizing then a NUL-separated walk over 65 attribute '
             'names, 777 bytes of output per pass')
    add('xattr', ['read', 'xattrs', 'user.big'], fixture='empty', label='xattr-read',
        reference='self', maximum=200,
        work='size-probe getxattr, ERANGE-growth buffer loop, then fwrite of a '
             '32,768-byte attribute value per pass')
    # scrub is a bash-history redaction policy store with no counterpart. It
    # rewrites the file in place, hence the seed-restoring reset.
    add('scrub', ['scrub-current', 'history'], fixture='empty', reference='self',
        reset='cp scrubseed history', maximum=20,
        work='5,000 history lines / 133,000 bytes read with getline and matched '
             'against 14 POSIX EREs per pass; 4,000 lines rewritten to a temp file and '
             'renamed over the original, 1,000 dropped; the reset restores the '
             '133,000-byte seed')
    # --- net-client ---
    add('curl', ['-s', 'http://127.0.0.1:19080/fixture'], fixture='empty', label='curl-loopback-body', maximum=40, reset='if ss -tln | grep -q ":19080 "; then echo "reset: port 19080 already in use" >&2; exit 1; fi; { nc listen 19080 -s 127.0.0.1 < httpresp >/dev/null 2>&1 & }; until ss -tln | grep -q ":19080 "; do :; done', work='one loopback HTTP/1.1 GET: 423105 B response read, headers parsed, 423000 B Content-Length body written to stdout; the timed pass also includes the reset (subshell fork, one-shot bash-os nc peer serving the 423 KB, one or two ss socket-table dumps), a term common to both columns')
    add('http', ['response-body', 'httpresp', '-o', 'bodyout'], fixture='empty', label='http-response-body', reference='self', output='bodyout', work='423105 B response file slurped, header block scanned for the CRLFCRLF that ends it 105 bytes in (so the 16 KiB header cap is never reached), 423000 B body written to the destination file')
    add('nc', ['connect', '127.0.0.1', '19080', '-w', '3'], fixture='empty', label='nc-loopback-stream', host_args=['127.0.0.1', '19080'], maximum=40, reset='if ss -tln | grep -q ":19080 "; then echo "reset: port 19080 already in use" >&2; exit 1; fi; { nc listen 19080 -s 127.0.0.1 < text >/dev/null 2>&1 & }; until ss -tln | grep -q ":19080 "; do :; done', work='423000 B pulled through one loopback TCP connection and copied to stdout by the epoll multiplexer; the timed pass also includes the reset that starts the one-shot bash-os nc listen peer, so every column (builtin, GNU, BusyBox) carries the same bash-os server half and the halves overlap on loopback')
    add('dns', ['checkzone', '-o', 'fixture.test.', 'zone'], fixture='empty', label='dns-checkzone', reference='self', work='1002178 B master file tokenized and 27006 resource records validated (owner-name, label and RR-type checks plus owner tracking)')
    add('wg', ['pubkey'], fixture='wgkey', label='wg-pubkey', reference='self', maximum=200, work='one Curve25519 base-point scalar multiplication plus base64 decode of the 32-byte private key and base64 encode of the public key')
    add('wg', ['setconf', 'wg0', 'wgconf'], fixture='empty', label='wg-setconf-dryrun', reference='self', normalizer='digest', maximum=200, env={'BASHWG_DRY': '1'}, work='3852 B wg-quick config parsed (24 peers, 48 allowed-ips, 24 endpoints and keepalives) and assembled into a 3348-byte nested-nlattr SET_DEVICE message, hex-dumped as 8443 B')
    add('scp', ['--openssh', 'example.test:remote', 'copyout'], fixture='empty', label='scp-openssh-get', reference='self', maximum=40, output='copyout', env={'BASHSSH_OPENSSH_BIN': './sshpeer'}, work="one transport spawn plus 4230000 B drained through the helper's stdout pipe by run_local_helper's poll loop in 4 KB steps and written to the local destination file")
    add('sftp', ['--openssh', 'example.test'], fixture='sftpbatch', label='sftp-openssh-get', reference='self', maximum=40, output='dl', env={'BASHSSH_OPENSSH_BIN': './sshpeer'}, work='batch interpreter runs pwd, get and quit; 4230000 B fetched through the stand-in transport and written to the local destination file')
    add('ssh', ['known-hosts', 'list', 'needle.fixture.test'], fixture='empty', label='ssh-known-hosts-list', host='ssh-keygen', host_args=['-q', '-F', 'needle.fixture.test', '-f', 'knownhosts'], env={'BASHSSH_KNOWN_HOSTS': 'knownhosts'}, work='2840142 B known_hosts scanned, 20001 salted HMAC-SHA1 host-hash comparisons, the one matching entry emitted')
    add('rsync', ['-a', '-e', './rshshim', 'text', ':rdest/'], fixture='empty', label='rsync-rsh-shim', maximum=40, output='rdest/text', reset='rm -rf rdest; mkdir rdest', work='one 423000 B file transferred through the rsh shim into a freshly emptied destination directory; bash-os spawns four remote commands per pass (mkdir -p, stat, cat > dest, chmod/touch/chown) while GNU spawns one rsync --server, so both columns carry a large process-spawn term alongside the 423 KB data pipe')
    add('pcap', ['info', 'capture.pcap'], fixture='empty', label='pcap-info', reference='self', work='full record walk of a 4000024 B capture: global header decode plus 50000 x (16-byte record-header read, snaplen guard, lseek over the 64-byte payload), about 100k syscalls')
    add('pkt', ['refs', 'pktrefs'], fixture='empty', label='pkt-refs', reference='self', work='1640140 B of length-prefixed frames parsed, 24001 payloads validated (40 hex chars plus space plus refs/ or HEAD, peeled ^{} tags rejected), 20001 lines emitted (1300046 B)')
    add('pkt', ['sideband', 'pktband', '-o', 'packout'], fixture='empty', label='pkt-sideband', reference='self', output='packout', work='400277 B side-band stream demultiplexed: 51 frame headers decoded, 49 channel-1 frames (400000 B) written to the pack file, channel-2 progress routed to stderr')
    add('genl', ['ctrl', 'list'], fixture='empty', label='genl-ctrl-list', reference='self', work='one CTRL_CMD_GETFAMILY dump over NETLINK_GENERIC: every registered generic-netlink family walked with its op table, capability bitmaps and multicast groups, and the whole table formatted')
    # --- net-server ---
    add('fail2ban', ['format-status', 'ban.db', 'sshd'], fixture='empty', label='fail2ban-format-status', reference='self', work='20000 ban records (719683 B) parsed, 5000 sshd rows selected and joined into a 71341 B status block')
    add('httpd', ['part', 'multipart', '-b', 'bashos0boundary0fixture', '-o', 'partout', '-n', 'field199'], fixture='empty', output='partout', label='httpd-part', reference='self', work='1028229 B multipart body scanned, 200 part headers parsed, the 5000 B part 200 written to partout')
    add('netids', ['compile', '-S', 'netids.rules'], fixture='empty', label='netids-compile', reference='self', work='512 Suricata-subset rules (61471 B) parsed and compiled')
    add('netids', ['scan', '-r', 'netids.pcap', '-S', 'netids.rules'], fixture='empty', label='netids-scan', reference='self', work='2000 Ethernet/IPv4/TCP frames (652024 B pcap) decoded and matched against 512 content patterns, emitting 200 eve.json alerts (48312 B)')
    add('fw', ['-B', 'nft', '-n', 'batch', 'fw.batch'], fixture='empty', label='fw-batch-dryrun', reference='self', env={'BASHFW_DIR': 'fwdir'}, work='3000 batch rule lines (138147 B) parsed and translated into 3000 nft argv lines (252120 B)')
    add('cron', ['next', '--from', '1700000000', '30', '4', '29', '2', '*'], fixture='empty', label='cron-next', reference='self', work='153016 candidate minutes evaluated (localtime_r + 5-field schedule match each) to reach the next 29 Feb 04:30')
    add('crontab', ['crontab.txt'], fixture='empty', output='cronspool/tabs/bashos', label='crontab-install', reference='self', env={'BASHCRON_SPOOL_DIR': 'cronspool', 'USER': 'bashos'}, work='797916 B / 12001-line crontab installed: policy check, 4 KiB-buffered copy into <dst>.tmp.<pid>, chmod 0600, atomic rename')
    add('at', ['-l'], fixture='empty', label='at-list', reference='self', normalizer='lines', env={'BASHCRON_SPOOL_DIR': 'atspool'}, work='4096 job dirents scanned in the at spool, 4096 job ids printed (65536 B)')
    add('batch', fixture='left', label='batch-queue', reference='self', normalizer='digest', maximum=20, env={'BASHCRON_SPOOL_DIR': 'batchspool'}, reset='rm -f batchspool/atjobs/*.job', work="120000 B script ingested from stdin and written as a 120020 B spool job file (fread/fwrite loop, chmod 0600, fclose); the reset deletes the previous pass's job file")
    add('sshd', ['sessions'], fixture='empty', label='sshd-sessions', reference='self', normalizer='lines', env={'BASHSSHD_RUN_DIR': 'sshdrun'}, work='512 session files opened and parsed (2560 key=value lines), 512 status lines printed (36384 B)')
    add('dhcpd', ['respond', '010106003903f326000080000000000000000000000000000000000002000000ab0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013d070102000000ab010c07626173682d6f733c09505845436c69656e74370d0103060c0f1a1c2a33363a3b42ff', '-c', 'dhcpd.conf', '-l', 'dhcpd.leases'], fixture='empty', label='dhcpd-respond', reference='self', maximum=200, work='256-lease DB (~12 KB) parsed, one 288-byte DHCPDISCOVER decoded, one 548-byte DHCPOFFER built and hex-encoded')
    add('dhcpd6', ['respond', '01abcdef0001000a000300010200000099990008000200000003000c0000000700000000000000000006000400170018', '-c', 'dhcpd6.conf', '-l', 'dhcpd6.leases'], fixture='empty', label='dhcpd6-respond', reference='self', maximum=200, work='255-lease DB parsed, one 48-byte SOLICIT decoded, one 118-byte ADVERTISE (IA_NA/IAADDR/2 DNS) built and hex-encoded')
    add('dhcp6', ['parse', '02abcdef0002000a000300010200000000990001000a000300010200000099990003002e000000070000070800000b400005001820010db800000001000000000000010000000e1000001c20000d000200000017002020010db800000000000000000000005320010db8000000000000000000000054'], fixture='empty', label='dhcp6-parse', reference='self', maximum=200, work='one 118-byte DHCPv6 ADVERTISE decoded (CLIENTID/SERVERID/IA_NA/IAADDR/DNS/STATUS) and 12 key=value lines (208 B) printed')
    add('bashdhcp', ['parse-message', '020106003903f3260000800000000000c000020ac00002020000000002000000ab0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007078656c696e75782e3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604c0000201330400001c203a0400000e103b040000189c0104ffffff000304c00002010608c0000235c00002360f0f666978747572652e696e76616c69644214746674702e666978747572652e696e76616c6964430a7078656c696e75782e30ff'], fixture='empty', label='bashdhcp-parse-message', reference='self', maximum=200, work='one 341-byte DHCPOFFER decoded: 9 options plus the BOOTP file field walked, 12 lease fields printed')
    add('ntp', ['nts-selftest'], fixture='empty', label='ntp-nts-selftest', reference='self', maximum=200, work='one NTS-protected request built (unique-id + cookie extension fields), one response sealed with AES-SIV-CMAC, two verifies (1 accept, 1 tamper-reject)')
    # --- auth-priv ---
    # Home fields are /var/empty/... rather than /home/...: the publication
    # hygiene scan treats /home/<name> as a possible personal-path leak, and a
    # synthetic passwd fixture has no reason to look like a real developer's tree.
    # Both implementations read the same field, so the value is arbitrary.
    # Credential and policy loadables. The account database, shadow PHC, group
    # file and sudoers-shaped policy are fixture files in the bench root, so
    # nothing reads or writes a real /etc account file, and the credential
    # transition verbs (login become, su, sudo, doas) are never invoked.
    # awk over the same fixture bytes is an adapter reference, the way
    # fltexpr->awk and strftime->date already are: GNU login(1) and passwd(1)
    # cannot be pointed at a fixture account database.
    add('login', ['lookup', 'benchuser'], fixture='empty', label='login-lookup',
        host='awk', host_args=['-F:', '$1=="benchuser"{print $3":"$4":"$6":"$7":"$5}',
                               'account.passwd'],
        env={'PHCLIB_PASSWD': 'account.passwd'}, maximum=200,
        work='318,948-byte / 5,001-record passwd database scanned to its last '
             'record, one 46-byte uid:gid:home:shell:gecos line emitted')
    add('passwd', ['list', '-l'], fixture='empty', label='passwd-list',
        host='awk', host_args=['-F:', '{print $1":"$3":"$4":"$6":"$7}',
                               'account.passwd'],
        env={'PHCLIB_PASSWD': 'account.passwd'}, maximum=80,
        work='318,948 bytes / 5,001 passwd records parsed and re-emitted as '
             '230,046 bytes of name:uid:gid:home:shell. Every fixture record '
             'has all seven fields non-empty, which this case depends on: the '
             'builtin misparses a record with an empty field')
    # verify-fd reads the password from fd 0, so the fixture is the stdin one.
    # Success is the exit status: a wrong password exits 1 and an unknown
    # account 2, and both fail the case. Output is empty by design.
    add('passwd', ['verify-fd', 'benchuser', '0'], fixture='password',
        label='passwd-verify-fd', reference='self', maximum=5,
        env={'PHCLIB_PASSWD': 'account.passwd', 'PHCLIB_SHADOW': 'account.shadow',
             'PHCLIB_GROUP': 'account.group', 'BPW_LOCK_DIR': 'lockdir'},
        work='one full Argon2id verification (m=19456 KiB, t=2, p=1, 32-byte '
             'tag: passwd.c BPW_ARGON_* defaults) of a 14-byte password read '
             'from fd 0 against the fixture PHC, plus the 318,948-byte passwd '
             'scan that resolves the lockout token; the KDF dominates')
    add('userdb', ['lookup', 'benchuser', '-V', 'REC'], fixture='empty',
        label='userdb-lookup', reference='self', maximum=200,
        env={'BASHUSERDB_PASSWD': 'account.passwd', 'BASHUSERDB_CONF': 'userdb.conf'},
        work='318,948-byte / 5,001-record passwd database scanned to its last '
             'record and split into 7 colon fields per line, then the '
             'uid:gid:gecos:home:shell record bound to a shell variable')
    add('auth', ['policy-parse', 'auth.policy'], fixture='empty',
        label='auth-policy-parse', reference='self', maximum=40,
        work='129,710 bytes / 2,403 lines of sudoers-shaped policy (2 Defaults, '
             '400 aliases, 2,000 rules) tokenised, validated, normalised and '
             "SHA-256'd, emitting 234,022 bytes of defaults/alias/rule records "
             'plus the summary line')
    add('caps', ['probe'], fixture='empty', label='caps-probe',
        reference='self', maximum=200,
        work='83 capability syscalls per call (one capget of '
             '_LINUX_CAPABILITY_VERSION_3, 41 prctl PR_CAPBSET_READ, 41 prctl '
             'PR_CAP_AMBIENT IS_SET) and five mask-to-name renderings, 657 bytes out')
    add('cred', ['status'], fixture='empty', label='cred-status',
        reference='self', maximum=200,
        work='one identity snapshot per call: getuid, getgid, geteuid, getegid '
             'and getgroups(64) formatted into a uid=/gid=/euid=/egid=/groups= line')
    # A 3,003-byte LDAPv3 filter: 200 uid= equality terms under one OR.
    add('ldap', ['filter-test',
                 '(|'+''.join(f'(uid=bench{i:04d})' for i in range(200))+')'],
        fixture='empty', label='ldap-filter-test', reference='self', maximum=200,
        work='a 3,003-byte LDAPv3 filter of 200 OR-ed equality terms compiled '
             'to 3,604 BER bytes and hex-printed as 7,209 bytes')
    add('acme', ['jwk-thumbprint', '-k',
                 '5a1c1f4b9e2d8a7c3f60b5d4e9a28c1706f3b8d5e4c2a19f8b7d6e5c4a3f2b19'],
        fixture='empty', label='acme-jwk-thumbprint', reference='self', maximum=40,
        work='one P-256 base-point scalar multiplication (32-byte fixture '
             'scalar to an uncompressed public point), the RFC 7638 canonical '
             '126-byte JWK built from x and y, one SHA-256 over it and '
             'base64url of the 32-byte digest, 44 bytes out; the scalar '
             'multiplication dominates')
    add('totp', ['generate', '-k', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                 '-t', '1234567890', '-d', '8', '-a', 'sha512'],
        fixture='empty', label='totp-generate', reference='self', maximum=40,
        work='one RFC 6238 code at a fixed timestamp: RFC 4648 base32 decode of '
             'a 32-character secret, counter framing, one HMAC-SHA-512 that '
             'totp.c delegates by fork and execl of /proc/self/exe into the '
             'crypto builtin, then HOTP dynamic truncation to 8 digits; the '
             'fork and exec dominate')
    # --- editor-app ---
    # Two files, because the builtin prints the `::::::::::::::` header only
    # when more than one file is named. No applet: BusyBox more rejects -n and
    # without it emits no headers at all, so its bytes cannot be compared.
    add('more', ['-n', '100', 'text', 'copy'], fixture='empty', applet='none',
        work='846,000 bytes paged from two 423 KB files plus two per-file '
             '`::::::::::::::` headers, 846,070 bytes emitted')
    # nvim headless is the reference; BusyBox vi does not accept its options.
    add('vi', ['-c', 'w viout', '-c', 'q!', 'duplicates'], fixture='empty',
        host_args=['-u', 'NONE', '-i', 'NONE', '-n', '--headless',
                   '-c', 'w! viout', '-c', 'q!', 'duplicates'],
        applet='none', output='viout', label='vi-write',
        work='piece-table load and line index of 1,680,000 bytes / 120,000 '
             'lines, then a full save of the same 1.68 MB')
    add('vi', ['--keys', 'vikeys', 'left'], fixture='empty', reference='self',
        output='keysout', label='vi-keys', maximum=10,
        work='3,473 keystrokes dispatched through the modal key decoder = '
             '1,250 buffer edits (1,000 `x` character deletes, 200 `dd` line '
             'deletes, 50 `p` line pastes, each pushing a piece-array undo '
             'snapshot), one regex search and one 117 KB save')
    add('nano', ['selftest'], fixture='empty', reference='self',
        work='17 engine assertions on 16-, 24-, 200- and 8-byte buffers: '
             'UTF-8 grapheme cluster walks with the per-line cluster cache, '
             'screen-column arithmetic, cluster insert and backspace, forward '
             'and backward search with wraparound, hscroll and soft-wrap '
             'viewport math, then one bn_render after '
             "bn_detect_language('cache-test.sh'), which reaches "
             'bashts_compute_sgr_map and recompiles the tree-sitter bash '
             'highlight query with ts_query_new on every call')
    add('nano2', ['selftest'], fixture='empty', reference='self',
        work='23 piece-table assertions: 1,000 single-byte cursor inserts, '
             'one 64 KiB insert plus a 64 KiB flatten_range round trip, '
             '100-step undo and 100-step redo, binary-NUL insert and flatten, '
             'and three pt_save chains (write + fsync(fd) + rename + '
             'fsync(dir))')
    add('screen', ['remote-frame', 'decode'], fixture='screenframe',
        reference='self',
        work='one 423,010-byte relay frame read from stdin (10-byte header '
             'validated, 423,000-byte payload read with bs_read_exact_fd) and '
             're-emitted with a type and length preamble, 423,029 bytes out')
    # be_states[] is keyed by fd and deliberately survives between calls, so a
    # second in-process pass would match out of the retained buffer and emit
    # nothing. mode='fresh' gives each pass its own copy of that state.
    add('expect', ['expect', '0', '^004999 left$'], fixture='left',
        reference='self', mode='fresh', maximum=10,
        work='60,160 bytes consumed from a stream in 256-byte reads with a '
             'fresh regcomp and regexec over the whole accumulated buffer '
             'after every read: 235 match rounds, about 7 MB scanned, 60 KB '
             'mirrored to stdout')
    # stdin must stay empty: given a non-empty regular file on stdin,
    # util-linux scriptreplay sleeps per timing record instead of replaying.
    add('script', ['replay', 'scripttiming', 'scriptlog'], fixture='empty',
        host='scriptreplay', host_args=['-t', 'scripttiming', '-O', 'scriptlog'],
        normalizer='fields', maximum=400,
        work='104 timing records parsed and 423,001 recorded bytes re-emitted '
             'in 8 KiB chunks, every delay zero so neither side sleeps')
    add('dialog', ['--output-fd', '1', '--separate-output', '--checklist',
                   'pick', '20', '60', '10', 'alpha', 'A', 'off',
                   'beta', 'B', 'off', 'gamma', 'C', 'off', 'delta', 'D', 'off'],
        fixture='dialogtags', reference='self', maximum=10,
        work='85,000 bytes / 15,000 tag lines consumed with one read(2) per '
             'byte in bd_read_line, each line strcmp-scanned against up to '
             'four tags, and the accumulated picked set emitted once after EOF')
    # whiptail_builtin forwards to dialog_builtin; --notags drives the other
    # result-assembly branch (item text, space-joined, instead of one line per
    # tag). No external comparator: host newt cannot run without a terminal.
    add('whiptail', ['--output-fd', '1', '--notags', '--checklist',
                     'pick', '20', '60', '10', 'alpha', 'Apple', 'off',
                     'beta', 'Banana', 'off', 'gamma', 'Grape', 'off',
                     'delta', 'Damson', 'off'],
        fixture='dialogtags', reference='self', maximum=10,
        work='85,000 bytes / 15,000 tag lines consumed with one read(2) per '
             'byte, then the space-joined --notags result assembly (item text '
             'instead of tag)')
    # rot13 read stdin with stdio and left the EOF flag set, so later in-process
    # passes read nothing. Fixed at the bsdgames_builtin entry with clearerr, so
    # this runs in-process like every other filter.
    add('bsdgames', ['rot13'], fixture='duplicates', host='tr',
        host_args=['A-Za-z', 'N-ZA-Mn-za-m'], maximum=20,
        label='bsdgames-rot13',
        work='1,680,000 input bytes transformed with ROT13 and emitted as 1,680,000 bytes')
    add('bsdgames', ['primes', '1', '200000'], fixture='empty',
        reference='self', maximum=10, label='bsdgames-primes',
        work='primality test of the range 1..200,000 with 17,984 primes '
             'formatted and emitted, 114,870 bytes out')
    # BASHWALL_UTMP and BASHWALL_DEV_DIR keep the utmp source and every
    # destination inside the fixture root; NOBANNER drops the banner's clock.
    add('wall', fixture='bytes', reference='self', output='devfix/tty0',
        reset='for t in devfix/tty0 devfix/tty1 devfix/tty2 devfix/tty3; '
              'do : > "$t"; chmod 620 "$t"; done',
        env={'BASHWALL_UTMP': 'wallutmp', 'BASHWALL_DEV_DIR': 'devfix',
             'BASHWALL_NOBANNER': '1'},
        work='utmp walk and de-duplication over four USER_PROCESS records, '
             'then fputs_careful-style escaping of a 65,538-byte message '
             '(control to ^X, 0x80-0xff to \\NNN, LF to CRLF) delivered to '
             'four terminals at 171,522 bytes each, 686 KB written')
    add('write', ['tty0'], fixture='bytes', reference='self',
        output='devfix/tty0', reset=': > devfix/tty0; chmod 620 devfix/tty0',
        env={'BASHWALL_DEV_DIR': 'devfix', 'BASHWALL_NOBANNER': '1'},
        work='single-target tty resolve, stat and mesg gate, then '
             'fputs_careful-style escaping of a 65,538-byte message delivered '
             'to one terminal, 171,522 bytes written')
    # -g is the only flag that ends the loop with a zero status, so the watched
    # command appends a byte to make frame 2 differ; `reset` restores that
    # precondition. -n 0.001 keeps the one inter-iteration sleep short.
    add('watch', ['-n', '0.001', '-g', '-d', 'cat left; printf X >> wmark; cat wmark'],
        fixture='empty', reference='self', reset=': > wmark', maximum=10,
        work='two iterations: two forks, 2 x 120 KB slurped through a pipe, '
             'one full byte-for-byte diff of frame 2 against frame 1, and '
             '240 KB re-emitted by bw_write_diff at one write(2) per byte '
             'plus SGR runs, 240,012 bytes out')
    # The compared bytes are empty by design; the correctness gate is the exit
    # status, because any address-encoding or delivery failure aborts the batch.
    add('notify', ['send', 'notify.sock', 'READY=1\nSTATUS=bench fixture\nMAINPID=1'],
        fixture='empty', reference='self', maximum=5000,
        work='one AF_UNIX SOCK_DGRAM lifecycle: socket(), two fcntl for '
             'FD_CLOEXEC, address encoding, sendto() of a 38-byte sd_notify '
             'payload and close(), one datagram delivered per pass')
    # --- terminal-prim ---
    # Terminal, key-decoding and image-emitting APIs. No external program or
    # applet implements any of them on comparable terms, so every case here is
    # self-referenced: pass 1 is its own expected output and the repeated batch
    # is a determinism check.
    add('bashtermraw', ['stty-g'], fixture='ptmx', label='bashtermraw-stty-g',
        reference='self', maximum=200,
        work='one tcgetattr plus TIOCGWINSZ serialized as 4 flag words, 32 c_cc '
             'entries, 2 speeds and a winsize, 112 bytes out. '
             'btr_open_tty_quiet() opens /dev/tty first and falls back to stdin, '
             "so the state read is the bench process's controlling terminal when "
             "it has one and the ptmx fixture's fresh pty when it does not; the "
             'per-pass floor is the kernel pty allocation of that redirect rather '
             'than the two ioctls, which makes this a weak but real self metric')
    # Eight repetitions of the longest name escdelay accepts (63 characters);
    # generated rather than pasted so the call stays readable.
    add('escdelay', ['get']+[part for i in range(8)
                             for part in ('--screen', 'bench_screen_%02d_%s' % (i, 'x'*47))],
        fixture='empty', reference='self', maximum=200,
        work='8 maximum-length (63-character) screen names = 504 characters '
             'through bsd_valid_screen_name(), then one five-level ESC-delay '
             'precedence resolution on an empty per-screen table (per-screen env '
             'name built and missed, zero-entry table scan, global env missed, '
             'unset global, default 50) and one line printed')
    add('kgetch', ['decode', '1b5b'+'39'*61+'7e'], fixture='empty',
        reference='self', maximum=200, env={'BASHKGETCH_TERMINFO': 'keymap'},
        work='64 bytes parsed out of one 128-character hex word by '
             'parse_hex_args(), then one exact-match lookup over a full '
             '160-entry keymap (34 built-in ANSI entries plus 126 from the '
             'keymap fixture, which fills the table exactly). bk_exact() is a '
             'reverse scan and the 64-byte entry sits at index 34, so 126 '
             'entries are examined before it matches, and one decoded key '
             'record is printed')
    add('wgetch', ['read', '0'], fixture='keyseq', reference='self', maximum=200,
        work='one 6-byte CSI key record read off stdin through '
             'bw_read_key_fd()\'s incremental grow loop: 6 read()s, 5 poll()s '
             'and an exact/has-prefix/has-longer sweep of the 34-entry table '
             'after every byte, printing one decoded key record')
    add('wget_wch', ['decode', '65cc80cc81cc82cc83cc84cc85cc86cc87cc88cc89cc8acc8bcc8ccc8dcc8e'],
        fixture='empty', reference='self', maximum=200,
        work='31 bytes parsed from a 62-character hex word and decoded as the '
             'largest cluster the API expresses - one base scalar plus 15 '
             'combining marks, 16 codepoints through bww_decode_cluster()\'s '
             'UTF-8 decode and combiner/VS/ZWJ classification - printed as a '
             '16-field record, 125 bytes out')
    add('mouse', ['decode', '1b5b3c33353b3939393939393b3939393939394d'],
        fixture='empty', reference='self', maximum=200,
        work='one 20-byte SGR-1006 mouse record (ESC [ < 35 ; 999999 ; 999999 M) '
             'hex-parsed by bm_parse_hex() and decoded by bm_decode_sgr(), the '
             'first arm of the 1006/1015/x10 cascade and the only one this input '
             'reaches, printing one 77-byte event record')
    # vt is handle-based (new -> feed -> render) and the harness runs one
    # command per pass, so the terminal is rebuilt by the reset. `vt free 0`
    # is quiet and tolerant on the first pass, bvt_alloc_handle() returns the
    # lowest free slot so the fresh terminal is reliably handle 0, and -h binds
    # the handle to a variable instead of printing it, so the reset writes
    # nothing to stdout.
    add('vt', ['render', '0', '-A'], fixture='empty', reference='self', maximum=40,
        reset='vt free 0 >/dev/null 2>&1; vt new -h _vtb -W 200 -H 50 '
              '&& vt feed-fd 0 0 -N 1000000 < vtstream',
        work='329,711 bytes of terminal traffic (SGR basic/256-colour/truecolour, '
             'CUP/CUU/CUD/CUF/CUB, EL/ED, DECSTBM, IL/DL, DECSC/DECRC, tabs, '
             'wide CJK and combining marks) fed byte-by-byte through the VT state '
             'machine onto a 200x50 grid, then those 10,000 cells rendered with '
             'SGR run-tracking to 5,691 bytes. The rebuild runs in the per-pass '
             'reset, which is inside the timed step, so one pass is parse plus '
             'render')
    add('termpixel', ['render-demo', '-w', '400', '-H', '200'], fixture='empty',
        reference='self', maximum=40,
        work='one 400x200 RGB frame drawn (clear, outline rect, filled circle, '
             'diagonal line, 6-glyph 3x5 text over 80,000 pixels) and run-length '
             'encoded to 400x100 truecolour upper-half-block cells, 55,683 bytes '
             'out. Frame index 0 is hard-coded, so no clock or RNG is involved')
    add('termpixel_pong', ['--dump-frame'], fixture='empty', reference='self',
        maximum=200,
        work='seeded game state built and one 80x80 frame rendered (6,400 pixels: '
             'two paddles, ball, 3x5 score and hint text) then encoded to 80x40 '
             'truecolour half-block cells, 7,391 bytes out. --dump-frame returns '
             'before the input and pacing loop, so no wall clock enters it')
    add('sixel', ['-w', '200', '-H', '200', 'image.png'], fixture='empty',
        reference='self', maximum=40,
        work='a 256x256 PNG decoded through stb_image, area-average resized to '
             '200x200, 40,000 pixels quantized to the fixed 6x6x6 (216) colour '
             'cube and emitted as 34 six-row SIXEL bands (216-entry used-colour '
             'scan plus per-colour RLE row build), 10,298 bytes out')
    add('tiv', ['-w', '100', '-H', '50', '-m', 'rgb', 'image.png'], fixture='empty',
        reference='self', maximum=40,
        work='the same 256x256 PNG decoded through stb_image, area-average '
             'resized to 100x100 pixels and rendered on the half-block path as '
             '5,000 cells of 24-bit fg/bg SGR plus U+2580 glyphs, 183,334 bytes '
             'out. Explicit -w/-H keep tiv_term_size() and the fit-to-height '
             'branch out of the measurement')
    add('tiv', ['-w', '100', '-H', '50', '-m', '256', '-g', 'oct', 'image.png'],
        fixture='empty', label='tiv-oct256', reference='self', maximum=40,
        work='the same PNG resized to 200x200 pixels by the 2x4 sub-cell sampler '
             'and rendered on the other renderer body: a per-cell best-glyph '
             'search against the btv_oct table plus 256-colour cube quantization '
             'for 5,000 cells, 111,939 bytes out')
    add('kitty', ['--no-tmux', '-w', '40', '-H', '20', 'image.png'], fixture='empty',
        reference='self', maximum=40,
        work='the same 256x256 PNG decoded through stb_image and emitted as Kitty '
             'direct-RGB graphics: 196,608 payload bytes base64-encoded in '
             '3,072-byte raw chunks (BK_RAW_CHUNK) with 64 APC framings, 263,012 '
             'bytes out. A one-way emitter: --no-tmux pins the framing and the '
             'terminal is never read')
    # gpu keeps one process-scoped session, so the canvas is rebuilt by the
    # reset: `gpu start` twice in one process is an error and `gpu stop` with no
    # session still succeeds, which makes the leading stop both required and
    # safe. --headless keeps the session off every device, and the only write is
    # frame.ppm inside the harness temp directory.
    add('gpu', ['save', 'frame.ppm'], fixture='empty', reference='self',
        maximum=40, output='frame.ppm',
        reset='gpu stop >/dev/null 2>&1; gpu start 640 480 --headless '
              '&& gpu clear 102040 && gpu circle 320 240 200 ff8000 '
              '&& gpu rect 40 40 200 120 30c080 '
              '&& gpu text 16 16 ffffff BASHOS 3 '
              '&& gpu line 0 479 639 0 ffffff 2',
        work='a 640x480 headless canvas rasterized in the per-pass reset (clear, '
             'filled circle r=200, stroked rect, scaled 3x5 text, 2px diagonal '
             'line over 307,200 pixels), then those 307,200 pixels packed and '
             'written as a 921,615-byte binary PPM by the measured command')
    # --- git-object ---
    add('obj', ['hash', '--stdin'], fixture='blob', host='git', host_args=['hash-object', '--stdin'], label='obj-hash', work="1048576 bytes (1 MiB blob fixture) hashed with sha1dc over the 'blob <len>NUL' header; 41 bytes out")
    # obj.c's getline loops did not clearerr(stdin), so a second in-process
    # --batch-check emitted nothing while still exiting 0. obj.c now has the
    # clearerr that index.c:544 already had, so this runs in-process.
    add('obj', ['--batch-check', '-r', 'gitloose'], fixture='gitshalist', host='git', host_args=['-C', 'gitloose', 'cat-file', '--batch-check'], label='obj-batch-check', maximum=40, work="3000 full-40-hex loose objects looked up (existence check + open + read), zlib-inflated and header-parsed: 774997 bytes compressed on disk -> 3023974 bytes of object payload; 3000 '<sha> <type> <size>' records / 152013 bytes emitted from a 123000-byte stdin SHA list")
    add('pack', ['cat', 'packrepo/.git/objects/pack/pack-fixture.pack', 'packrepo/.git/objects/pack/pack-fixture.idx', '882badb336048d3cb6451ea86563e470d8f98f4d'], fixture='empty', host='git', host_args=['-C', 'packrepo', 'cat-file', 'blob', '882badb336048d3cb6451ea86563e470d8f98f4d'], label='pack-cat', maximum=20, work='.idx v2 fanout + binary search over 201 entries, then zlib inflate of a 613174-byte pack entry to exactly 4194304 bytes on stdout')
    # 'fields' hides exactly one difference: the builtin's documented
    # '<mode> <sha> <stage> <path>' output (index.c:22) separates the path with
    # a space where git ls-files --stage uses a TAB. All 80000 tokens are
    # equal in order, and the builtin verifies the index's SHA-1 trailer over
    # the whole 1760032-byte body just as git's verify_hdr does.
    add('index', ['read', 'indexrepo/.git/index'], fixture='empty', host='git', host_args=['-C', 'indexrepo', 'ls-files', '--stage'], label='index-read', normalizer='fields', maximum=40, work="1760032-byte git index v2 with 20000 entries parsed; 20000 '<mode> <sha> <stage> <path>' lines / 1440000 bytes / 80000 fields emitted")
    # Nothing external emits a manifest-v2 row, so this is self-timed. The
    # rows carry uid/gid/mtime/ctime, which are stable for one bench run:
    # blob, bytes and tree/ are read-only in every other case, and 'text' is
    # deliberately excluded because chmod/chown/chgrp mutate its ctime.
    add('integrity', ['emit-manifest', '--no-header', '--root', '.', '--', '/blob', '/bytes', '/tree'], fixture='empty', label='integrity-manifest', reference='self', work='fd-pinned walk of 258 files (~1.11 MB: 1 MiB blob + 64 KiB bytes + 256 x 8 B in tree/) hashed twice, SHA-256 and BLAKE2b, plus 258 fstatats; 258 manifest-v2 rows / 66805 bytes out')
    add('pkg', ['search', 'alpha', '--root', 'pkgroot'], fixture='empty', label='pkg-search', reference='self', work='4973790-byte repo INDEX slurped and split into 20000 pkg-loadable-v1 records, each strtok_r-tokenized for the record check and substring-matched; 2500 hits / 656726 bytes out')
    add('payload', ['list'], fixture='empty', label='payload-list', reference='self', env={'PAYLOAD_REPO': 'payloadrepo', 'PAYLOAD_ROOT': 'payloadroot'}, maximum=40, work='1696256-byte share INDEX streamed and 20000 blpkg-v1 records parsed with fgets+strtok_r, plus 20000 install-state stat() probes (2500 hits); 20005 lines / 1220126 bytes of table out')
    # bc_members is fopen + a 4 KiB fread/fwrite loop + fclose, so cat is the
    # canonical minimal implementation of the same job, not a false comparison.
    add('cluster', ['members'], fixture='empty', host='cat', host_args=['clusterstate/members'], label='cluster-members', env={'BASHCLUSTER_STATE_DIR': 'clusterstate'}, maximum=40, work="1768818-byte member roster streamed to stdout through bc_members' fopen + 4 KiB fread/fwrite loop (cluster.c:239-254); output is byte-identical to the roster file, so /usr/bin/cat and busybox cat do the same job")
    # BASHSV_RUNDIR is load-bearing, not documentary: sv.c:3691-3692 runs
    # bsv_mkdir_p(bsv_run_dir) unconditionally before verb dispatch, so
    # without it every read-only pass attempts mkdir('/run/sv') on the host.
    add('sv', ['log', 'fixture', '-n', '200'], fixture='empty', host='tail', host_args=['-n', '200', 'svlog/fixture'], label='sv-log', env={'BASHSV_LOGDIR': 'svlog', 'BASHSV_RUNDIR': 'svrun', 'BASHSV_DIR': 'svetc'}, work='last 200 lines / 14000 bytes emitted from a 2800000-byte / 40000-line service log')
    add('claude', ['parse-response'], fixture='sseresponse', label='claude-parse-response', reference='self', maximum=40, work='3153699-byte HTTP/1.1 chunked response de-chunked (3150431 bytes of body), ~60000 SSE lines split and strstr-scanned, 20000 text_delta JSON strings decoded; 848050 bytes of assistant text out')
    # jq -j (join output: raw, no trailing newline) is what makes both the
    # single pass and the concatenated batch byte-exact. The encode direction
    # is not measurable: concatenated quoted literals merge at the quote
    # boundary, so `claude escape` fails the batch check.
    add('claude', ['unescape'], fixture='jsonstring', host='jq', host_args=['-j', '.'], label='claude-unescape', work='649973-byte JSON string literal scanned and decoded (escaped quote/backslash/TAB/control and \\uXXXX to UTF-8) to 635986 bytes out')
    # --- data-parser ---
    # config.toml, vector.npy and bench.db are files in the fixture root read
    # by name; their stdin fixture stays empty.
    add('toml', ['emit', 'config.toml'], fixture='empty', label='toml-emit', reference='self', work='186,758 bytes of TOML parsed (605 tables, mixed string/int/float/bool/array/datetime/sub-table) and re-emitted as 186,157 bytes of canonical TOML')
    # ts and hl have no external counterpart: no tree-sitter binary and no
    # Python tree_sitter module. BusyBox's unrelated `ts` applet is a timestamp
    # prefixer, which reference=self never reaches - anyone converting these to a
    # comparison must set applet explicitly.
    add('ts', ['parse', '-L', 'json'], fixture='array', label='ts-parse', reference='self', work='39,109 bytes of JSON (10,000-element array) parsed by the vendored tree-sitter runtime and printed as a 90,019-byte root-node S-expression')
    add('ts', ['query', '-L', 'json', '-q', '(pair key: (_) @key) (number) @num (string) @str'], fixture='object', label='ts-query', reference='self', work='39,133 bytes of JSON parsed, then a 3-pattern tree-sitter query run over the tree emitting 10,005 capture records (337,936 bytes) with 1-indexed line:col and byte spans')
    add('hl', ['-L', 'json'], fixture='object', reference='self', work='39,133 bytes of JSON highlighted: parse plus curated highlight query (10,005 captures) plus inline SGR rendering to 129,160 bytes')
    add('utf8', ['normalize', 'NFD', 'Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 '], fixture='empty', label='utf8-normalize-nfd', reference='self', maximum=200, work='1,824 bytes / 1,080 codepoints canonically decomposed to 2,400 bytes per pass (Latin precomposed accents, precomposed Hangul syllables via algorithmic decomposition, CJK, compatibility characters, U+00C5/U+00C6/U+00D8, astral emoji)')
    add('utf8', ['length', 'Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 Café naïve Étoile ñandú 각깎밝 你好世界 ﬁ⁵½ ÅÆØ œ 😀 ', '-T', 'grapheme'], fixture='empty', label='utf8-length-grapheme', reference='self', maximum=200, work="1,824 bytes / 1,080 codepoints walked by libgrapheme's cluster-break machine, yielding 1,080 grapheme clusters")
    # A prepared statement is consumed by its own step: in-process, pass 2 gets
    # SQLITE_DONE and fails, so this is the case mode=fresh exists for.
    add('sqlite', ['step', 'T0g2'], fixture='empty', label='sqlite-step-aggregate', reference='self', mode='fresh', reset='[[ -v D ]] || { sqlite open bench.db -h D && sqlite prepare "$D" "SELECT count(*), sum(v), max(k) FROM items" -h S; }', work='one sqlite3_step of a prepared full-table aggregate over 100,000 rows / 2,252,800 bytes (SELECT count(*), sum(v), max(k) FROM items), printing one tab-separated row')
    add('vec', ['sum', '0'], fixture='empty', label='vec-sum', reference='self', reset='[[ -v V ]] || vec import-npy vector.npy -h V', work='one reduction over 1,000,000 int64 elements (8,000,000 bytes scanned) printing the exact sum; the guarded one-time import-npy is charged once per timed batch')
    add('vec', ['dot', '0', '0'], fixture='empty', label='vec-dot', reference='self', reset='[[ -v V ]] || vec import-npy vector.npy -h V', work='one multiply-accumulate over 1,000,000 int64 element pairs (self dot product) printing the exact result')
    # asort writes no bytes, so the check is the reset printing index samples;
    # `-i DEST SOURCE` leaves SOURCE intact, so every pass sorts the same array.
    add('asort', ['-n', '-i', 'I', 'A'], fixture='empty', label='asort-index-numeric', reference='self', reset='[[ -v I ]] || { mapfile -t A < numbers; asort -n -i I A; }; printf "%s\\n" "${I[*]:0:8}" "${I[*]:24996:8}" "${I[*]: -8}"', work='a 50,000-element numeric sort of a bash array (the existing numbers fixture, 369,296 bytes) plus 50,000 index writes into the destination array')
    # buf load replaces the whole buffer, so it restores its own precondition.
    add('buf', ['load', '0', 'text'], fixture='empty', label='buf-load', reference='self', reset='[[ -v B ]] || { buf new -h B >/dev/null; buf load "$B" text; }; buf lines 0; buf len 0 8061; buf line 0 0', work='423,000 bytes mmapped and newline-scanned per pass (8,062 lines counted) to rebuild the sparse checkpoint index, one offset every BB_CKPT_STRIDE=1024 lines, with the previous mapping munmapped each pass')
    add('buf', ['text', '0'], fixture='empty', label='buf-text', host='cat', host_args=['text'], reset='[[ -v B ]] || { buf new -h B >/dev/null; buf load "$B" text; }', work='8,062 in-memory buffer lines joined and written as 423,000 bytes to stdout per pass')
    # One composite group of 2,000 records; the reset's redo re-arms it, and
    # pass 1's redo fails harmlessly because the trailing buf lines sets status.
    add('undo', ['undo', '0'], fixture='empty', label='undo-composite-group', reference='self', reset='[[ -v U ]] || { buf new -h B >/dev/null; buf load "$B" text; undo new -h U -B "$B" -d 4; undo begin-group "$U"; for ((k=0;k<2000;k++)); do undo record "$U" D "$k" "deleted line $k"; done; undo end-group "$U"; }; undo redo 0 2>/dev/null; undo depth 0; buf lines 0', work="2,000 grouped inverse line-inserts applied to a 423,000-byte / 8,062-line buffer per pass, plus the 2,000 line-deletes the reset's redo re-applies")
    # The exactly-inverse insert-line/delete-line round trip forces bb_realize, so
    # the one-time copy-range is not a large additive constant on both sides.
    add('clip', ['text', '0'], fixture='empty', label='clip-text', host='head', host_args=['-n', '4000', 'text'], reset='[[ -v C ]] || { buf new -h B >/dev/null; buf load "$B" text; buf insert-line "$B" 8062 x; buf delete-line "$B" 8062; clip new -h C >/dev/null; clip copy-range "$C" "$B" 0 4000; }', work='4,000 yank-ring lines (209,906 bytes) written to stdout per pass; the guarded one-time reset (buf load, realize, copy-range) is charged once per timed batch to both sides')
    # Not a GNU comparison: /usr/bin/locale prints LANG=/LANGUAGE= lines this
    # verb omits, quotes every value and puts LC_ALL last, and no normalizer
    # reconciles that. `locale current` is a different documented verb.
    add('locale', ['current'], fixture='empty', label='locale-current', reference='self', maximum=200, work='13 LC_* category resolutions (each walking LC_ALL -> LC_<cat> -> LANG through getenv plus find_variable) printed as 13 lines / 170 bytes')
    # v1/v4/v6/v7 are clock- or CSPRNG-based. The name-based versions are pure
    # hashes, and -C repeats them inside one invocation.
    add('uuidgen', ['-s', '-n', '@dns', '-N', 'example.com', '-C', '20000'], fixture='empty', label='uuidgen-v5-sha1', reference='self', work='20,000 name-based UUIDv5 generations per pass (20,000 SHA-1 digests over a 16-byte namespace plus an 11-byte name, formatted to 740,000 bytes of output)')
    add('uuidgen', ['-m', '-n', '@dns', '-N', 'example.com', '-C', '20000'], fixture='empty', label='uuidgen-v3-md5', reference='self', work='20,000 name-based UUIDv3 generations per pass (20,000 MD5 digests over a 16-byte namespace plus an 11-byte name, formatted to 740,000 bytes of output)')
    # --- syscall-ipc ---
    add('bashio', ['pread', '0', '423000', '0'], fixture='text', host='dd',
        host_args=['bs=423000', 'count=1', 'status=none'], label='bashio-pread',
        work='423,000 bytes read from a regular file with one pread(2) at '
             'offset 0 plus one write(2) to stdout')
    add('bashio', ['pread', '-x', '0', '65536', '0'], fixture='bytes', host='xxd',
        host_args=['-p', '-c', '65536'], label='bashio-pread-hex',
        work='65,536 bytes read with one pread(2) and hex-encoded to 131,072 '
             "hex digits through bio_print_hex's 4 KB-chunked per-byte loop")
    # epoll refuses regular files, so fds 0 and 1 (the fixture and the capture
    # file) cannot be registered. The reset dup2's the harness's own stderr
    # pipe, which is always EPOLLOUT-ready, onto eight distinct descriptors.
    add('bashpoll', ['wait', '-t', '0', '2:write', '9:write', '8:write',
                     '7:write', '6:write', '5:write', '4:write', '3:write'],
        fixture='empty', reference='self', maximum=200, label='bashpoll-wait',
        reset='exec 9>&2 8>&2 7>&2 6>&2 5>&2 4>&2 3>&2',
        work='one epoll instance per pass: epoll_create1 + 8 level-triggered '
             'EPOLL_CTL_ADD registrations + one non-blocking epoll_wait + 8 '
             'formatted event lines + close')
    # Re-adding the same path returns the same watch descriptor, and a mask of
    # attrib alone ignores the one-time IN_CREATE, so every pass queues exactly
    # 32 IN_ATTRIB events. Omitting -n drains the whole queue.
    add('bashinotify', ['wait', '-t', '0'], fixture='empty', reference='self',
        maximum=200, label='bashinotify-drain',
        reset='if [[ ! -e iw/f1 ]]; then mkdir -p iw; touch iw/f{1..32}; fi; '
              'bashinotify add iw attrib WD; touch iw/f{1..32}',
        work='32 queued inotify events drained in one read(2) of the global '
             "inotify fd and formatted as 32 'WD attrib NAME' lines (407 bytes)")
    add('fdflags', ['-v'], fixture='empty', reference='self', maximum=20,
        label='fdflags-scan',
        work='one full descriptor-table scan per pass: getmaxfd() probes '
             'fcntl(fd,F_GETFD) downward from RLIMIT_NOFILE (524,288 on this '
             'host, so ~524,284 failing fcntls) then prints a verbose flag '
             'line for every fd below the highest open one')
    # Closing the three descriptors first makes socketpair return 3 and 4 and
    # the received descriptor 5 on every pass, whatever stdin the reset inherits.
    add('scm', ['recv-fd', '4', '--token', 'tok', '--fd-socket'], fixture='empty',
        reference='self', maximum=200, label='scm-recv-fd',
        reset='exec 3>&- 4>&- 5>&-; scm pair -h A -h B; scm send-fd 3 4 tok',
        work='one complete SCM_RIGHTS round trip per pass: '
             'socketpair(AF_UNIX,SOCK_DGRAM) + sendmsg carrying one descriptor '
             '+ recvmsg(MSG_CMSG_CLOEXEC) + cmsg walk + token compare + fstat '
             'descriptor-type check')
    add('mlock', ['try-lock', '1048576'], fixture='empty', reference='self',
        maximum=200, label='mlock-trylock',
        work="1 MiB (256 pages) mmapped anonymous, mlock'd (faulted in and "
             "pinned), munlock'd and munmapped per pass")
    # Both sides create the namespace, exec /bin/true and wait, so the ratio is
    # not one unshare(2) against a whole extra program load.
    add('ns', ['spawn', 'user', '/bin/true'], fixture='empty', host='unshare',
        host_args=['--user', '/bin/true'], label='ns-spawn-user',
        work='one user namespace created and one program exec\'d per pass: '
             'builtin clone(CLONE_NEWUSER) + child execvp(/bin/true) + '
             'waitpid; reference fork + exec of unshare(1), which unshares '
             'and execs /bin/true')
    add('ns', ['list-ns'], fixture='empty', reference='self', normalizer='lines',
        maximum=200, label='ns-list',
        work='enumerate /proc/self/ns: one opendir plus a readlink and an '
             'ns-id parse per entry (10 entries on this kernel), formatted '
             "into 10 'TYPE: <inode>' lines (192 bytes)")
    # Reap before closing the master: the child opens its slave after spawn
    # returns, so closing first can kill it before it gets there.
    add('pty', ['spawn', 'F', 'P', 'true'], fixture='empty', reference='self',
        label='pty-spawn',
        reset='if [[ -n "${F:-}" ]]; then pty waitpid "$P"; pty close "$F"; fi',
        work='one full pty session per pass: posix_openpt + grantpt + '
             'unlockpt + ptsname_r + pipe2 + socketpair gate + double fork, '
             'child setsid + open(slave) + TIOCSCTTY + 3x dup2 + run the '
             '`true` builtin, then reap and close the master (in the reset)')
    # The per-call mode prints the tracee pid and raw pointers, which ASLR
    # moves every run. The -c summary is counts only.
    add('strace', ['-c', '-o', 'strace.out', '--', '/bin/true'], fixture='empty',
        reference='self', maximum=20, output='strace.out', label='strace-summary',
        work='fork + PTRACE_TRACEME exec of /bin/true and ~31 traced syscalls '
             'per pass, i.e. ~62 ptrace stop/continue round trips decoded and '
             'accumulated into a 17-row summary table (666 bytes)')
    # The clock-reading verbs print a live timestamp no normalizer can pin.
    # A zero sleep measures the parse plus the syscall, not the kernel timer.
    add('bashclock', ['sleep', '0.000000000'], fixture='empty', host='sleep',
        host_args=['0.000000000'], maximum=200, label='bashclock-sleep',
        work='one 20-character SECS.NANOS parse through bc_parse_ts (full '
             '9-digit fraction path) plus one '
             'clock_nanosleep(CLOCK_MONOTONIC, 0, {0,0}) per pass')
    # --- repeat-input ---
    # The group proposed mode='fresh' for xargs and uuencode, having concluded
    # that both leave stdin at EOF so pass 2 of an in-process batch reads
    # nothing. That was the defect fixed in fff2bb1, which is in the binary
    # these were validated against; both now pass an in-process batch, so the
    # existing in-process cases stand and keep their ids. In-process is also the
    # honest shape: mode='fresh' adds a fork per pass to every implementation and
    # would make these two rows incomparable with the rest of the table.
    # -m selects a different encoder in the source (enc_b64, the RFC 4648
    # alphabet and a '====' trailer) rather than enc_classic.
    add('uuencode', ['-m', 'bytes'], fixture='bytes', label='uuencode-base64',
        work='65536 B read from stdin and encoded as base64 (enc_b64): 1457 '
             '60-char lines plus the ==== trailer, 88869 B out')
    # bashkmod aliases: libkmod reads only depmod's binary indexes, which cannot
    # be generated for a synthetic tree, so modprobe --resolve-alias cannot be
    # pointed at this fixture and there is no honest reference.
    add('bashkmod', ['aliases', 'pci:v00008086d00001000sv00000000sd00000000bc0Csc03i30'],
        fixture='empty', label='bashkmod-aliases', reference='self',
        env={'BASHKMOD_MODULES_DIR': 'modules'},
        work='454227 B / 8601 modules.alias lines read, 8600 fnmatch(3) calls '
             'against the query modalias, 200 matches deduped and printed in '
             'file order (1800 B out)')
    # The builtin prints the eight fields tab-separated and findmnt --raw prints
    # them space-separated; normalizer='fields' compares the 16000 tokens in
    # order. No mount(2)/umount2(2): the mountinfo path is an operand.
    add('bashmount', ['--findmnt-table', 'mountinfo'], fixture='empty',
        label='bashmount-findmnt', host='findmnt',
        host_args=['--tab-file', 'mountinfo', '--raw', '--noheadings', '-o',
                   'ID,PARENT,MAJ:MIN,FSROOT,TARGET,VFS-OPTIONS,FSTYPE,SOURCE'],
        normalizer='fields',
        work='2000 mountinfo records (199510 B) tokenized, dash-scanned for '
             'type/source and re-emitted as 2000 eight-field rows '
             '(137198 B, 16000 fields)')
    # audit decode-text: the only verb that touches neither NETLINK_AUDIT nor
    # the kernel rule ABI. '-o -' writes to stdout instead of appending to
    # $AUDIT_RECORDS_FILE. The epoch and serial come from the payload's own
    # audit(...) stamp, so nothing in the compared bytes moves between passes.
    audit_message = (
        'audit(1757600000.123:4242): arch=c000003e syscall=59 success=yes exit=0 '
        'a0=7ffd0a1b2c30 a1=7ffd0a1b2d40 a2=7ffd0a1b2e50 a3=7f2b1c0d8e60 items=2 '
        'ppid=1024 pid=2048 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 '
        'fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="bash" '
        'exe="/usr/local/bin/bash-os" subj=unconfined key="exec-watch" '
        'cwd="/home/pleb/projects/bash-os" '
        + ' '.join(f'a{i}="/home/pleb/projects/bash-os/loadables/part{i:02d}.c"'
                   for i in range(48))
        + ' name="loadables/audit.c" inode=917531 dev=fe:01 mode=0100644'
          ' ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0'
          ' cap_fe=0 cap_fver=0 cap_frootid=0')
    add('audit', ['decode-text', '1300', audit_message, '-o', '-'], fixture='empty',
        label='audit-decode-text', reference='self', maximum=200,
        work='one 3069-byte kernel audit message body (89 tokens, a0..a47 execve '
             'vector) scanned twice - five lifted columns via ba_field, then the '
             'kv tail - and re-emitted as a 3044-byte 9-field TSV record, '
             'character at a time through fputc')
    # mail newaliases: both paths are options inside the fixture root, and
    # bm_write_path_atomic writes '<db>.tmp.<pid>' then renames, so the db is
    # exactly what output= compares. sendmail/newaliases/postalias are absent
    # and the db format is bash-os's own.
    add('mail', ['newaliases', '--aliases', 'aliases.txt', '--db', 'aliasdb'],
        fixture='empty', label='mail-newaliases', reference='self', output='aliasdb',
        work='5001 aliases-file lines (160441 B) read in shuffled key order, '
             "comment-stripped and trimmed, 5000 entries qsort'ed and written "
             'atomically as a 160036-byte db')
    # lpr list is the only observational verb: opendir, suffix-filter, print.
    # find over the same spool is the same directory-enumeration task and agrees
    # byte for byte; normalizer='lines' guards against readdir order.
    add('lpr', ['list'], fixture='empty', label='lpr-list', host='find',
        host_args=['lprspool', '-name', '*.lpr'], normalizer='lines',
        env={'BASHLPR_SPOOL': 'lprspool'},
        work='4001 spool directory entries enumerated and suffix-filtered, 4000 '
             "'<spool>/<name>.lpr' lines emitted (120000 B)")
    # apropos/whatis: MANPATH keeps both implementations inside the fixture
    # index, and BASHMAN_STALE_QUIET silences the one-shot staleness warning.
    # PATH is restored because man-db execs grep for a plain-text index and dies
    # under the harness's empty PATH; bash still resolves the builtin first.
    add('apropos', ['alpha'], fixture='empty',
        env={'MANPATH': 'manfix', 'BASHMAN_STALE_QUIET': '1', 'PATH': '/usr/bin:/bin'},
        work='1283890 B / 20000 whatis-index lines scanned with a substring '
             'match, 2500 matching lines printed (161110 B)')
    # whatis opens the index once and rewinds per NAME, so eight names cost
    # eight full scans - the rescan loop is what this case measures.
    add('whatis', ['tool00001', 'tool02500', 'tool05000', 'tool07500', 'tool10000',
                   'tool12500', 'tool15000', 'tool19999'], fixture='empty',
        env={'MANPATH': 'manfix', 'BASHMAN_STALE_QUIET': '1', 'PATH': '/usr/bin:/bin'},
        work='8 rewind+scan passes over the 1283890 B whatis index (10.3 MB read, '
             '160000 lines head-matched), 8 records emitted (518 B)')
    return rows


def fixtures(root, needed=None):
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
        'chain': b'a b\nb c\nc d\n',
        'hexbytes': (bytes(range(256))*256).hex().encode(),
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
    xz = shutil.which('xz', path=HOST_PATH)
    if xz:
        with (root/'text.xz').open('wb') as out:
            subprocess.check_call([xz, '-c', 'text'], cwd=root, stdout=out)
        record(root/'text.xz', 'text.xz')
    bzip2 = shutil.which('bzip2', path=HOST_PATH)
    if bzip2:
        with (root/'text.bz2').open('wb') as out:
            subprocess.check_call([bzip2, '-c', 'text'], cwd=root, stdout=out)
        record(root/'text.bz2', 'text.bz2')
    busybox = shutil.which('busybox', path=HOST_PATH)
    if busybox:
        encoded = subprocess.check_output(
            [busybox, 'uuencode', 'bytes'], cwd=root, input=(root/'bytes').read_bytes())
        (root/'uuencoded').write_bytes(encoded)
        record(root/'uuencoded', 'uuencoded')
    mkfs = shutil.which('mkfs.ext2', path=HOST_PATH)
    if mkfs:
        (root/'disk.img').write_bytes(b'\0' * (8 * 1024 * 1024))
        subprocess.check_call(
            [mkfs, '-F', '-q', '-L', 'fixture', str(root/'disk.img')])
        record(root/'disk.img', 'disk.img')

    # Fixtures for the 2026-09-12 metric-coverage cases. Each artifact is built
    # once, guarded on its host tool and on already existing, so a host missing
    # a tool still runs the rest of the suite.
    # --- block-device ---
    # A 12 MiB GPT image with 128 partitions. The label id, every partition
    # GUID, name and offset are pinned, so the image is byte-identical on
    # every build; fdisk reads it as a regular file and never opens a device.
    sfdisk = shutil.which('sfdisk', path=HOST_PATH)
    if sfdisk and not (root/'parts.img').exists():
        layout = ['label: gpt',
                  'label-id: 6F1D0E90-1111-4222-8333-444455556666',
                  'unit: sectors',
                  'first-lba: 2048']
        for index in range(128):
            layout.append('start=%d, size=128, '
                          'type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, '
                          'uuid=%08X-0000-4000-8000-%012X, name="part-%03d"'
                          % (2048 + index*128, 0xA0000000 + index, index, index))
        (root/'parts.img').write_bytes(b'\0' * (12*1024*1024))
        subprocess.run([sfdisk, '--no-tell-kernel', '-q', str(root/'parts.img')],
                       input=('\n'.join(layout)+'\n').encode(), check=True,
                       stdout=subprocess.DEVNULL)
        record(root/'parts.img', 'parts.img')
    # An 8 MiB file carrying a swap signature with a pinned UUID and label.
    # Swap is the one magic whose type string the builtin and util-linux spell
    # identically ('swap'); on an ext2 image the builtin says 'ext' and
    # util-linux 'ext4'. Writing it with mkswap puts the signature at the
    # host's own pagesize-10 offset, which is where wipefs.c looks.
    mkswap = shutil.which('mkswap', path=HOST_PATH)
    if mkswap and not (root/'swapsig.img').exists():
        (root/'swapsig.img').write_bytes(b'\0' * (8*1024*1024))
        subprocess.check_call([mkswap, '-U', '6f1d0e90-1111-4222-8333-444455556666',
                               '-L', 'fixture', str(root/'swapsig.img')],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        record(root/'swapsig.img', 'swapsig.img')
    # --- process-query ---
    # A synthetic procfs tree, a binary utmp file and a /dev/kmsg record log.
    # Every artifact is index-derived, so building it twice gives the same
    # bytes. procfix/ and utmpfix are shared with other groups, so each block
    # is guarded and a second copy of it is a no-op.
    if not (root/'procfix').exists():
        # 512 pid directories plus the kernel-level files free/vmstat/slabtop
        # and the /proc readers in ps, killall5 and procstat parse.
        proc = root/'procfix'
        proc.mkdir()
        (proc/'uptime').write_text('987654.32 7891011.50\n')
        (proc/'loadavg').write_text('0.42 0.37 0.31 2/765 424242\n')
        stat_lines = ['cpu  '+' '.join(str(1000000+i*37) for i in range(10))]
        for cpu in range(8):
            stat_lines.append(f'cpu{cpu} '+' '.join(str(120000+cpu*11+i*7) for i in range(10)))
        stat_lines += ['intr 123456789 '+' '.join(str(i) for i in range(64)),
                       'ctxt 987654321', 'btime 1700000000', 'processes 543210',
                       'procs_running 3', 'procs_blocked 1',
                       'softirq 55555555 '+' '.join(str(1000+i) for i in range(10))]
        (proc/'stat').write_text('\n'.join(stat_lines)+'\n')
        meminfo = [('MemTotal', 16777216), ('MemFree', 2097152), ('MemAvailable', 8388608),
                   ('Buffers', 131072), ('Cached', 4194304), ('SwapCached', 1024),
                   ('Active', 5242880), ('Inactive', 3145728), ('Active(anon)', 2097152),
                   ('Inactive(anon)', 524288), ('Active(file)', 3145728),
                   ('Inactive(file)', 2621440), ('Unevictable', 4096), ('Mlocked', 4096),
                   ('SwapTotal', 4194304), ('SwapFree', 4063232), ('Dirty', 512),
                   ('Writeback', 0), ('AnonPages', 2621440), ('Mapped', 1048576),
                   ('Shmem', 262144), ('KReclaimable', 393216), ('Slab', 524288),
                   ('SReclaimable', 393216), ('SUnreclaim', 131072), ('KernelStack', 16384),
                   ('PageTables', 32768), ('NFS_Unstable', 0), ('Bounce', 0),
                   ('WritebackTmp', 0), ('CommitLimit', 12582912), ('Committed_AS', 6291456),
                   ('VmallocTotal', 34359738367), ('VmallocUsed', 65536),
                   ('VmallocChunk', 0), ('Percpu', 8192), ('AnonHugePages', 0),
                   ('ShmemHugePages', 0), ('ShmemPmdMapped', 0), ('FileHugePages', 0),
                   ('FilePmdMapped', 0), ('HugePages_Total', 0), ('HugePages_Free', 0),
                   ('HugePages_Rsvd', 0), ('HugePages_Surp', 0), ('Hugepagesize', 2048),
                   ('Hugetlb', 0), ('DirectMap4k', 262144), ('DirectMap2M', 8388608),
                   ('DirectMap1G', 8388608)]
        (proc/'meminfo').write_text(''.join(f'{k}:{v:>16} kB\n' for k, v in meminfo))
        record(proc/'meminfo', 'procfix/meminfo')
        counters = ['nr_free_pages', 'nr_zone_inactive_anon', 'nr_zone_active_anon',
                    'nr_zone_inactive_file', 'nr_zone_active_file', 'nr_mlock',
                    'nr_bounce', 'nr_zspages', 'nr_free_cma', 'numa_hit', 'numa_miss',
                    'pgpgin', 'pgpgout', 'pswpin', 'pswpout', 'pgalloc_dma',
                    'pgalloc_normal', 'pgfree', 'pgactivate', 'pgdeactivate',
                    'pgfault', 'pgmajfault', 'pgscan_kswapd', 'pgsteal_kswapd',
                    'kswapd_inodesteal', 'pageoutrun', 'pgrotated', 'drop_pagecache',
                    'drop_slab', 'oom_kill', 'numa_pte_updates', 'nr_dirtied',
                    'nr_written', 'thp_fault_alloc', 'thp_collapse_alloc',
                    'compact_stall', 'compact_fail', 'compact_success',
                    'unevictable_pgs_culled', 'unevictable_pgs_rescued',
                    'balloon_inflate', 'swap_ra', 'swap_ra_hit', 'nr_unstable']
        (proc/'vmstat').write_text(''.join(f'{n} {1000+i*997}\n'
                                           for i, n in enumerate(counters)))
        disks = []
        for i in range(256):
            fields = [100000+i*7, 200+i, 800000+i*31, 5000+i, 60000+i*5, 100+i,
                      400000+i*17, 3000+i, i % 4, 90000+i*13, 120000+i*19,
                      0, 0, 0, 0, 0, 0]
            disks.append(f'{8+i//16} {i%16} fx{i//26:d}{chr(97+i%26)} '
                         + ' '.join(str(x) for x in fields))
        (proc/'diskstats').write_text('\n'.join(disks)+'\n')
        record(proc/'diskstats', 'procfix/diskstats')
        slab = ['slabinfo - version: 2.1',
                '# name            <active_objs> <num_objs> <objsize> <objperslab> '
                '<pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : '
                'slabdata <active_slabs> <num_slabs> <sharedavail>']
        for i in range(512):
            active, total = 100+i*3, 200+i*5
            size = 32 << (i % 6)
            per = max(1, 4096//size)
            slab.append(f'fixture_cache_{i:04d} {active} {total} {size} {per} '
                        f'{1 << (i % 3)} : tunables 0 0 0 : slabdata '
                        f'{active//per+1} {total//per+1} 0')
        (proc/'slabinfo').write_text('\n'.join(slab)+'\n')
        record(proc/'slabinfo', 'procfix/slabinfo')
        for n in range(512):
            pid = 100 + n*3
            entry = proc/str(pid)
            entry.mkdir()
            comm = f'fixture{n%37:02d}'
            state = 'SRDZT'[n % 5]
            ppid = 1 if n == 0 else 100+(n//8)*3
            # Session and pid values above pid_max (4194304) so a live
            # getsid(0) or a /proc lookup on the real tree can never match.
            fields = [str(pid), f'({comm})', state, str(ppid), str(pid),
                      str(4200000+(n % 16)), '0', '-1', '4194560', str(1000+n), '0',
                      str(200+n), '0', str(1500+n*7), str(700+n*3), '0', '0', '20',
                      '0', str(1+n % 9), '0', str(500000+n*1000),
                      str(10485760+n*4096), str(1024+n*8)]
            fields += ['0']*(52-len(fields))
            (entry/'stat').write_text(' '.join(fields)+'\n')
            (entry/'comm').write_text(comm+'\n')
            (entry/'status').write_text(
                f'Name:\t{comm}\nUmask:\t0022\nState:\t{state} (sleeping)\n'
                f'Tgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nTracerPid:\t0\n'
                'Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t64\nGroups:\t0 \n'
                f'VmPeak:\t{10240+n*4:>8} kB\nVmSize:\t{10240+n*4:>8} kB\n'
                'VmLck:\t       0 kB\n'
                f'VmRSS:\t{4096+n*4:>8} kB\nThreads:\t{1+n%9}\n')
            (entry/'cmdline').write_bytes(
                f'/usr/lib/fixture/{comm}\0--config\0/etc/fixture/{n%13}.conf\0'.encode())
        maps = []
        for i in range(2048):
            start = 0x400000 + i*0x3000
            mode = ['r-xp', 'r--p', 'rw-p', '---p'][i % 4]
            path = (f'/usr/lib/fixture/libfix{i%64:02d}.so.1' if i % 4 != 2
                    else ('[heap]' if i % 8 == 2 else ''))
            maps.append(f'{start:x}-{start+0x2000:x} {mode} {i*0x1000:08x} '
                        f'08:01 {100000+i} {path}'.rstrip())
        (proc/'100'/'maps').write_text('\n'.join(maps)+'\n')
        record(proc/'100'/'maps', 'procfix/100/maps')
    if not (root/'utmpfix').exists():
        # 4096 x86-64 struct utmp records: 3584 USER_PROCESS, 256 BOOT_TIME,
        # 256 DEAD_PROCESS. ut_pid is above pid_max so w's session-leader
        # lookup can never collide with a live process.
        import struct
        layout = '<h2xi32s4s32s256shhiii16s20s'
        assert struct.calcsize(layout) == 384, struct.calcsize(layout)
        records = bytearray()
        for i in range(4096):
            kind = 7 if i % 8 else (2 if i % 16 == 0 else 8)
            records += struct.pack(layout, kind, 4200000+i, f'fxpts/{i%64}'.encode(),
                                   f'f{i%10:03d}'.encode(), f'fxuser{i%53:02d}'.encode(),
                                   f'fixture-{i%29:02d}.invalid'.encode(), 0, 0,
                                   4200000+i, 1700000000+i*17, i*7, b'\0'*16, b'\0'*20)
        (root/'utmpfix').write_bytes(bytes(records))
        record(root/'utmpfix', 'utmpfix')
    if not (root/'kmsgfix').exists():
        # 4096 /dev/kmsg-format records, every line exactly 128 bytes. dmesg's
        # fixture reader splits 8192-byte chunks on newlines, and 128 divides
        # 8192, so no chunk boundary ever falls inside a record.
        facilities = [0, 0, 0, 1, 3, 4]
        subsystems = ['usb', 'ata1.00', 'eth0', 'nvme0n1', 'cgroup', 'audit', 'acpi']
        kmsg = []
        for i in range(4096):
            line = (f'{facilities[i%6]*8+(i%8)},{i},{1000*i+(i*7919)%1000},-;'
                    f'{subsystems[i%7]}: fixture record {i} '
                    f'status=0x{i*2654435761 % 0xffffffff:08x} ')
            line = line + 'y'*(127-len(line)) if len(line) < 127 else line[:127]
            assert len(line) == 127, len(line)
            kmsg.append(line)
        (root/'kmsgfix').write_text('\n'.join(kmsg)+'\n')
        record(root/'kmsgfix', 'kmsgfix')
    # --- fs-metadata ---
    # mkfifo: the case's reset asserts the previous pass left a FIFO before
    # removing it, so the fixture seeds one for pass 1.
    if not (root/'fifo0').exists():
        os.mkfifo(root/'fifo0', 0o600)
    # mv: the 16 sources are recreated by the case's reset before every pass;
    # this is only the destination directory they are renamed into.
    if not (root/'moved').exists():
        (root/'moved').mkdir()
    # mktemp: the case's reset asserts the previous pass left exactly one
    # 'mktmp-fixture mktmp.XXXXXX' entry, so the fixture seeds one. The space in
    # the template is deliberate: it puts the constant part in the first
    # whitespace field, the only field the digest normalizer keeps.
    if not (root/'mktmp-fixture mktmp.seed').exists():
        (root/'mktmp-fixture mktmp.seed').write_bytes(b'')
    # tty: stdin has to be a terminal, so the stdin fixture is a symlink to the
    # pty multiplexer. Each pass opens it read-only and closes it, allocating
    # and immediately freeing one pty pair. No byte is ever read from it, so the
    # recorded size is zero rather than a read of the device.
    if not (root/'ptmx').is_symlink():
        (root/'ptmx').symlink_to('/dev/ptmx')
    hashes['ptmx'] = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
    # chattr: a private tree, so the FS_IOC_SETFLAGS pass cannot perturb the
    # shared tree/ fixture that ls, find, du, ncdu and lsattr measure. 512 files
    # so the ioctl walk dominates the reference's fork and exec. The directory
    # is seeded with FS_NOATIME_FL because the case's reset asserts the previous
    # pass left the bit set, and pass 1 has no previous pass.
    if not (root/'attrtree').exists():
        import fcntl
        import struct
        FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_NOATIME_FL = 0x80086601, 0x40086602, 0x80
        (root/'attrtree').mkdir()
        for i in range(512):
            (root/'attrtree'/f'item-{i:04d}.txt').write_bytes(b'fixture\n')
        fd = os.open(root/'attrtree', os.O_RDONLY | os.O_NONBLOCK)
        try:
            current = struct.unpack('l', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('l', 0)))[0]
            fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('l', current | FS_NOATIME_FL))
        finally:
            os.close(fd)

    # getfacl and setfacl: POSIX.1e access ACLs are written straight into
    # system.posix_acl_access. Entries stay in canonical order (user_obj, user,
    # group_obj, group, mask, other) because the kernel validates the order.
    def posix_acl(entries):
        blob = bytearray((2).to_bytes(4, 'little'))
        for tag, perm, ident in entries:
            blob += tag.to_bytes(2, 'little') + perm.to_bytes(2, 'little') \
                    + (ident & 0xffffffff).to_bytes(4, 'little')
        return bytes(blob)

    ACL_UO, ACL_U, ACL_GO, ACL_G, ACL_M, ACL_O = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
    ACL_UNDEFINED = 0xffffffff
    seeded_acl = posix_acl([(ACL_UO, 6, ACL_UNDEFINED), (ACL_U, 7, os.getuid()),
                            (ACL_GO, 4, ACL_UNDEFINED), (ACL_G, 5, os.getgid()),
                            (ACL_M, 7, ACL_UNDEFINED), (ACL_O, 4, ACL_UNDEFINED)])
    # getfacl reads 32 files, half of them carrying an extended access ACL so
    # the binary-decode path runs as well as the mode-derived base entries. The
    # kernel syncs the mode to the ACL, so the odd-numbered files settle at
    # 0o674 whatever the chmod asked for; that is deterministic.
    if not (root/'acls').exists():
        (root/'acls').mkdir()
        for i in range(32):
            path = root/'acls'/f'f{i:02d}'
            path.write_bytes(b'acl fixture\n')
            path.chmod(0o644 if i % 2 == 0 else 0o600)
            if i % 2:
                os.setxattr(path, 'system.posix_acl_access', seeded_acl)
    # setfacl rewrites every file it is given, so it gets its own directory and
    # leaves getfacl's acls/ pristine. f00 is the sentinel the case's reset
    # reads back, size-checks and removes, so it is seeded with the same
    # 6-entry ACL the case writes; pass 1 has no previous pass to have left it.
    if not (root/'aclset').exists():
        (root/'aclset').mkdir()
        for i in range(32):
            path = root/'aclset'/f'f{i:02d}'
            path.write_bytes(b'acl fixture\n')
            path.chmod(0o644)
        os.setxattr(root/'aclset'/'f00', 'system.posix_acl_access', seeded_acl)
    # xattr: 64 small attributes plus one 32 KiB value, shared by the
    # xattr-list name walk and the xattr-read ERANGE growth loop.
    # Only xattr cases need filesystem support for large extended attributes.
    # Other selected cases retain all of their existing fixture setup.
    if needed is None or 'xattrs' in needed:
        if not (root/'xattrs').exists():
            (root/'xattrs').write_bytes(b'xattr fixture\n')
            for i in range(64):
                os.setxattr(root/'xattrs', f'user.attr{i:02d}', b'value-%03d' % i)
            os.setxattr(root/'xattrs', 'user.big', bytes(range(256))*128)
        record(root/'xattrs', 'xattrs')
    # scrub: 5,000 history lines, every fifth one a secret form that the
    # baked-in denylist drops (4,000 kept, 1,000 dropped). scrub-current
    # rewrites the file in place, so scrubseed is the pristine copy the case's
    # reset restores from before every pass.
    if not (root/'scrubseed').exists():
        verbs = ['ls -la /srv', 'grep -rn alpha src', 'make -j8 all',
                 'git status --short', 'cat /etc/hostname']
        secrets = ['mysql --password=hunter2 -u app',
                   'curl -H x -d --token=abc123 host',
                   'PGPASSWORD=swordfish psql -h db', 'export API_KEY=zzz',
                   'aws --secret=shh s3 ls']
        history = [secrets[i % 5] if i % 5 == 0 else f'{verbs[i % 5]} # {i:05d}'
                   for i in range(5000)]
        blob = ('\n'.join(history)+'\n').encode()
        (root/'scrubseed').write_bytes(blob)
        (root/'history').write_bytes(blob)
    record(root/'scrubseed', 'scrubseed')
    record(root/'history', 'history')
    # --- net-client ---
    # 'httpresp' is shared with other groups. Every artifact below is guarded by
    # an exists() check so a duplicate block from another group is a no-op.
    if not (root/'httpresp').exists():
        # Canned HTTP/1.1 response whose body is the `text` fixture: 423105 B.
        body = data['text']
        resp = (b'HTTP/1.1 200 OK\r\nServer: fixture\r\nContent-Type: text/plain\r\n'
                b'Content-Length: %d\r\nConnection: close\r\n\r\n' % len(body)) + body
        (root/'httpresp').write_bytes(resp)
        record(root/'httpresp', 'httpresp')
    if not (root/'zone').exists():
        # RFC 1035 master file: 1002178 B, 27006 resource records.
        zone = ['$TTL 3600',
                '@\t3600\tIN\tSOA\tns1.fixture.test. hostmaster.fixture.test.'
                ' ( 2026091201 7200 3600 1209600 3600 )',
                '@\t3600\tIN\tNS\tns1.fixture.test.',
                '@\t3600\tIN\tNS\tns2.fixture.test.',
                'ns1\t3600\tIN\tA\t192.0.2.1',
                'ns2\t3600\tIN\tA\t192.0.2.2',
                '@\t3600\tIN\tMX\t10 mail.fixture.test.']
        for i in range(20000):
            zone.append('host%05d\t3600\tIN\tA\t198.51.%d.%d'
                        % (i, (i//254) % 254, i % 254 + 1))
            if i % 4 == 0:
                zone.append('alias%05d\t3600\tIN\tCNAME\thost%05d.fixture.test.' % (i, i))
            if i % 10 == 0:
                zone.append('txt%05d\t3600\tIN\tTXT\t"fixture record %05d"' % (i, i))
        (root/'zone').write_bytes(('\n'.join(zone)+'\n').encode())
        record(root/'zone', 'zone')
    if not (root/'wgkey').exists():
        # stdin fixture: one base64 Curve25519 private key, 45 B.
        (root/'wgkey').write_bytes(
            base64.b64encode(hashlib.sha256(b'bash-os wg fixture key 2026-09-12').digest())
            + b'\n')
        record(root/'wgkey', 'wgkey')
    if not (root/'wgconf').exists():
        # wg-quick-shaped config, 3852 B, 24 peers x 2 allowed-ips. 24 peers is
        # deliberate: BW_MAX_PEERS is 64 (wg.c:123) and BW_BUFSZ overflows earlier
        # still, so 120 peers gives 'too many peers' and 64 peers x 3 aips gives
        # 'message too large'; 24 x 2 assembles a 3348-byte SET_DEVICE message.
        wgconf = ['[Interface]', 'ListenPort = 51820',
                  'PrivateKey = '
                  + base64.b64encode(hashlib.sha256(b'iface').digest()).decode()]
        for i in range(24):
            wgconf += ['', '[Peer]',
                       'PublicKey = '
                       + base64.b64encode(hashlib.sha256(b'peer%d' % i).digest()).decode(),
                       'AllowedIPs = 10.%d.0.0/16, 10.%d.1.0/24' % (i % 250, i % 250),
                       'Endpoint = 192.0.2.%d:%d' % (i % 250 + 1, 51820 + i),
                       'PersistentKeepalive = 25']
        (root/'wgconf').write_bytes(('\n'.join(wgconf)+'\n').encode())
        record(root/'wgconf', 'wgconf')
    if not (root/'sshpayload').exists():
        # Transfer payload for the scp and sftp cases: text x10 = 4230000 B.
        (root/'sshpayload').write_bytes(data['text']*10)
        record(root/'sshpayload', 'sshpayload')
    if not (root/'sftpbatch').exists():
        # stdin fixture: the sftp verb stream (sftp.c:864 reads stdin without -b).
        (root/'sftpbatch').write_bytes(b'get remote dl\nquit\n')
        record(root/'sftpbatch', 'sftpbatch')
    sh = shutil.which('sh', path=HOST_PATH)
    cat = shutil.which('cat', path=HOST_PATH)
    if sh and cat and not (root/'sshpeer').exists():
        # Offline stand-in for the ssh transport (BASHSSH_OPENSSH_BIN), so no
        # connection and no name resolution happens. It must answer the `pwd`
        # probe with a path (sftp_pwd runs before the first verb, sftp.c:874) and
        # every other command with the payload. execvp reaches it through a
        # slash-containing relative path, so no PATH lookup is needed.
        (root/'sshpeer').write_text(
            '#!%s\n'
            'for a in "$@"; do last="$a"; done\n'
            'case "$last" in\n'
            '  *pwd*) printf \'/\\n\' ;;\n'
            '  *)     exec %s %s ;;\n'
            'esac\n' % (sh, cat, root/'sshpayload'))
        (root/'sshpeer').chmod(0o755)
    if sh and not (root/'rshshim').exists():
        # One rsh shim serving both implementations. rsync.c:50-60 documents
        # `-e RSH` -> argv = rsh_argv + [host?] + [cmd] with an empty host dropped,
        # so DEST=':rdest/' makes the 'remote' local. bash-os rsync issues
        # mkdir/stat/cat-shaped remote commands and GNU rsync issues
        # `rsync --server`; the shim gives both the same peer-side PATH, and the
        # command under test still runs with an empty PATH.
        (root/'rshshim').write_text(
            '#!%s\n'
            'exec %s -c "PATH=/usr/bin:/bin; $*"\n' % (sh, sh))
        (root/'rshshim').chmod(0o755)
    if not (root/'knownhosts').exists():
        # 2840142 B, 20001 hashed (|1|salt|hash) ed25519 entries; the needle is
        # the last one, so both implementations HMAC-SHA1 every entry.
        import hmac
        kh_rng = random.Random(20260912)

        def kh_entry(host):
            salt = bytes(kh_rng.randrange(256) for _ in range(20))
            tag = hmac.new(salt, host.lower().encode(), hashlib.sha1).digest()
            key = base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 '
                                   + bytes(kh_rng.randrange(256) for _ in range(32)))
            return '|1|%s|%s ssh-ed25519 %s' % (base64.b64encode(salt).decode(),
                                                base64.b64encode(tag).decode(),
                                                key.decode())

        kh = [kh_entry('host%05d.fixture.test' % i) for i in range(20000)]
        kh.append(kh_entry('needle.fixture.test'))
        (root/'knownhosts').write_bytes(('\n'.join(kh)+'\n').encode())
        record(root/'knownhosts', 'knownhosts')
    if not (root/'capture.pcap').exists():
        # Classic little-endian pcap, LINKTYPE_ETHERNET, 50000 records x 64 B
        # payload = 4000024 B.
        import struct
        pcap = bytearray()
        pcap += struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        for i in range(50000):
            pcap += struct.pack('<IIII', 1600000000 + i, (i*37) % 1000000, 64, 64)
            pcap += bytes((i + j) & 0xff for j in range(64))
        (root/'capture.pcap').write_bytes(bytes(pcap))
        record(root/'capture.pcap', 'capture.pcap')

    def pkt_line(payload):
        return b'%04x' % (len(payload) + 4) + payload

    if not (root/'pktrefs').exists():
        # git pkt-line ref advertisement: 1640140 B, 24001 pkt-lines plus flush.
        pkt_rng = random.Random(20260912)
        adv = bytearray()
        adv += pkt_line(pkt_rng.randbytes(20).hex().encode()
                        + b' HEAD\x00multi_ack thin-pack side-band side-band-64k'
                          b' ofs-delta shallow no-progress include-tag\n')
        for i in range(20000):
            adv += pkt_line(pkt_rng.randbytes(20).hex().encode()
                            + b' refs/heads/branch-%05d\n' % i)
            if i % 5 == 0:                  # peeled tags: must be filtered out
                adv += pkt_line(pkt_rng.randbytes(20).hex().encode()
                                + b' refs/tags/v%05d^{}\n' % i)
        adv += b'0000'
        (root/'pktrefs').write_bytes(bytes(adv))
        record(root/'pktrefs', 'pktrefs')
    if not (root/'pktband').exists():
        # side-band-64k stream, 400277 B: a 400000 B pack across 49 channel-1
        # frames plus NAK, one channel-2 progress frame and a flush.
        band = bytearray()
        band += pkt_line(b'NAK\n')
        pack = bytes((i*7 + 13) & 0xff for i in range(400000))
        for off in range(0, len(pack), 8192):
            band += pkt_line(b'\x01' + pack[off:off+8192])
        band += pkt_line(b'\x02' + b'progress: done\n')
        band += b'0000'
        (root/'pktband').write_bytes(bytes(band))
        record(root/'pktband', 'pktband')
    # --- net-server ---
    # fail2ban format-status: 20000 TAB-separated ban records over four jails,
    # 5000 of them in sshd. 719683 B,
    # sha256 2cbb8b2988affd9f395717c2a189b507bd3b91bdab158fb02f7b075c5002661b.
    if not (root/'ban.db').exists():
        ban_rng = random.Random(20260912)
        ban_jails = ['sshd', 'nginx-http-auth', 'postfix-sasl', 'recidive']
        (root/'ban.db').write_bytes(''.join(
            '%d.%d.%d.%d\t%s\t%d\n' % (ban_rng.randrange(1, 224), ban_rng.randrange(256),
                                       ban_rng.randrange(256), ban_rng.randrange(1, 255),
                                       ban_jails[i % 4], 1700000000 + i)
            for i in range(20000)).encode())
        record(root/'ban.db', 'ban.db')
    # httpd part: a 200-part multipart/form-data body with 5000 B per part.
    # 1028229 B, sha256 649fd8759de4da0d901189db90d6bcd750b94cb08ae6db86117188b4303b71a1.
    if not (root/'multipart').exists():
        part_rng = random.Random(20260912)
        boundary = b'bashos0boundary0fixture'
        part_rows = []
        for i in range(200):
            body = bytes(part_rng.randrange(32, 127) for _ in range(5000))
            part_rows.append(
                b'--' + boundary
                + b'\r\nContent-Disposition: form-data; name="field%03d"; '
                  b'filename="f%03d.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'
                  % (i, i)
                + body + b'\r\n')
        (root/'multipart').write_bytes(
            b''.join(part_rows) + b'--' + boundary + b'--\r\n')
        record(root/'multipart', 'multipart')
    # netids: 512 Suricata-subset content rules, shared by compile and scan.
    # 61471 B, sha256 102692505214f0ade09a45b0fc3372b3e4816f801b1da058765178b7dd471cf2.
    if not (root/'netids.rules').exists():
        (root/'netids.rules').write_bytes(b'# bash-os netids fixture rules\n' + b''.join(
            b'alert tcp any any -> any any (msg:"fixture rule %03d"; content:"token%03d"; '
            b'sid:%d; rev:1; classtype:misc-activity;)\n' % (i, i, 1000000 + i)
            for i in range(512)))
        record(root/'netids.rules', 'netids.rules')
    # netids scan: 2000 Ethernet/IPv4/TCP frames in a classic pcap savefile, every
    # tenth payload carrying one rule token. Record timestamps come from the file,
    # not the clock. Headers are packed with int.to_bytes because fixtures() has no
    # struct import. 652024 B,
    # sha256 3093a71ce1943bc4016ea3dd4851bd40a891ebb3b3e48fe69c09941a29a0e835.
    if not (root/'netids.pcap').exists():
        pcap_rng = random.Random(20260912)
        pcap_records = []
        for n in range(2000):
            payload = bytearray(bytes(pcap_rng.randrange(97, 123) for _ in range(256)))
            if n % 10 == 0:
                token = ('token%03d' % (n // 10 % 512)).encode()
                payload[100:100+len(token)] = token
            tcp = ((1024 + (n % 40000)).to_bytes(2, 'big') + (80).to_bytes(2, 'big')
                   + n.to_bytes(4, 'big') + bytes(4) + b'\x50\x18'
                   + (8192).to_bytes(2, 'big') + bytes(4))
            ip = (b'\x45\x00' + (20 + 20 + 256).to_bytes(2, 'big')
                  + (n & 0xffff).to_bytes(2, 'big') + bytes(2) + b'\x40\x06' + bytes(2)
                  + bytes((10, 0, (n >> 8) & 0xff, n & 0xff)) + bytes((192, 0, 2, 10)))
            checksum = sum(int.from_bytes(ip[i:i+2], 'big') for i in range(0, 20, 2))
            while checksum >> 16:
                checksum = (checksum & 0xffff) + (checksum >> 16)
            ip = ip[:10] + (~checksum & 0xffff).to_bytes(2, 'big') + ip[12:]
            frame = (bytes((2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2)) + b'\x08\x00'
                     + ip + tcp + bytes(payload))
            pcap_records.append((1700000000 + n // 100).to_bytes(4, 'little')
                                + ((n % 100) * 10000).to_bytes(4, 'little')
                                + len(frame).to_bytes(4, 'little') * 2 + frame)
        (root/'netids.pcap').write_bytes(
            b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00' + bytes(8)
            + (65535).to_bytes(4, 'little') + (1).to_bytes(4, 'little')
            + b''.join(pcap_records))
        record(root/'netids.pcap', 'netids.pcap')
    # fw batch: 3000 rule lines in the three shapes the translator handles.
    # 138147 B, sha256 0a75056c26d6e1c573182d51670ccdddd5cdf8febe750a41639e1f35a0a60078.
    if not (root/'fw.batch').exists():
        batch_rows = ['# bash-os fw batch fixture\n']
        for i in range(3000):
            a, b, c = (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff
            if i % 3 == 0:
                batch_rows.append('allow 10.%d.%d.%d -p tcp -d %d\n'
                                  % (a, b, c, 1024 + (i % 60000)))
            elif i % 3 == 1:
                batch_rows.append('deny 172.16.%d.%d -p udp -d %d --ct-state new\n'
                                  % (b, c, 1024 + (i % 60000)))
            else:
                batch_rows.append('allow 192.168.%d.%d -p tcp --multiport 80,443,8080'
                                  ' -i eth0\n' % (b, c))
        (root/'fw.batch').write_bytes(''.join(batch_rows).encode())
        record(root/'fw.batch', 'fw.batch')
    # crontab install: a 12001-line user crontab. 797916 B,
    # sha256 292cf7833707cedc107d64c912ef959071328b4e1e7165dc2945815e116836bd.
    if not (root/'crontab.txt').exists():
        tab_rows = ['# bash-os crontab fixture\n']
        for i in range(12000):
            tab_rows.append('%d %d * * %d /usr/bin/fixture-job-%05d --flag=%d'
                            ' >/dev/null 2>&1\n' % (i % 60, i % 24, i % 7, i, i))
        (root/'crontab.txt').write_bytes(''.join(tab_rows).encode())
        record(root/'crontab.txt', 'crontab.txt')
    # at -l: 4096 queued jobs in a private spool. pid is not recorded in the name
    # the builtin prints, and nothing here is ever run or removed.
    if not (root/'atspool').exists():
        at_dir = root/'atspool'/'atjobs'
        at_dir.mkdir(parents=True)
        for i in range(4096):
            (at_dir/('%d.%d.job' % (1700000000 + i, 1000 + i))).write_bytes(
                b'# run_at=%d\necho fixture job %d\n' % (1700000000 + i, i))
    # sshd sessions: 512 session state files. pid=1 is deliberate - sessions_cmd
    # prunes a session only when kill(pid, 0) fails with ESRCH, and kill(1, 0)
    # returns EPERM unprivileged or 0 as root, so the fixture is never modified.
    if not (root/'sshdrun').exists():
        sshd_dir = root/'sshdrun'/'sessions'
        sshd_dir.mkdir(parents=True)
        for i in range(512):
            (sshd_dir/('sess-%04d' % i)).write_text(
                'id=sess-%04d\npid=1\nkind=%s\npeer=198.51.100.%d:%d\nstarted=1700000000\n'
                % (i, 'shell' if i % 2 else 'exec', i % 254 + 1, 40000 + i))
    # dhcpd respond: a static pool config and a full 256-row lease DB
    # (BDHCPD_MAX_LEASES). The first row is keyed to the request's MAC; every
    # lease expires in 2096 so the pool pick cannot move between passes.
    if not (root/'dhcpd.conf').exists():
        (root/'dhcpd.conf').write_text(
            'pool 192.0.2.10 192.0.2.250\nnetmask 255.255.255.0\ngateway 192.0.2.1\n'
            'dns 192.0.2.53,192.0.2.54\ndomain fixture.invalid\nserver_id 192.0.2.1\n'
            'lease 7200\nnext-server 192.0.2.2\ntftp-server tftp.fixture.invalid\n'
            'bootfile pxelinux.0\n')
        record(root/'dhcpd.conf', 'dhcpd.conf')
    if not (root/'dhcpd.leases').exists():
        lease_rows = ['02:00:00:00:ab:01 192.0.2.10 4000000000 client000\n']
        for i in range(1, 256):
            lease_rows.append('02:00:00:00:%02x:%02x 192.0.2.%d 4000000000 client%03d\n'
                              % ((i >> 8) & 0xff, i & 0xff, 100 + (i % 150), i))
        (root/'dhcpd.leases').write_text(''.join(lease_rows))
        record(root/'dhcpd.leases', 'dhcpd.leases')
    # dhcpd6 respond: server config plus a 255-row lease DB (cap is D6D_MAX_LEASES
    # 256), again all expiring in 2096.
    if not (root/'dhcpd6.conf').exists():
        (root/'dhcpd6.conf').write_text(
            'server-duid 00030001020000000099\npool-start 2001:db8:0:1::100\n'
            'pool-size 4096\ndns 2001:db8::53\ndns 2001:db8::54\nlease-pref 3600\n'
            'lease-valid 7200\nt1 1800\nt2 2880\n')
        record(root/'dhcpd6.conf', 'dhcpd6.conf')
    if not (root/'dhcpd6.leases').exists():
        lease6_rows = []
        for i in range(255):
            lease6_rows.append('00030001%012x 1 20010db80000000100000000%08x 4000000000 0\n'
                               % (0x020000000100 + i, 0x1000 + i))
        (root/'dhcpd6.leases').write_text(''.join(lease6_rows))
        record(root/'dhcpd6.leases', 'dhcpd6.leases')
    # --- auth-priv ---
    # Account database for the credential loadables, shared with any other
    # group that needs one: 5,000 filler accounts plus the benchmark subject as
    # the LAST record, so a name lookup has to scan the whole file. 318,948
    # bytes, 5,001 records. Do not add a record with an empty field (an empty
    # GECOS, say): `passwd list -l` splits records with strtok_r, which
    # collapses consecutive colons, so such a record is misparsed and the awk
    # comparison stops matching.
    if not (root/'account.passwd').exists():
        accounts = ''.join(
            f'bench{i:04d}:x:{5000+i}:{5000+i}:Bench User {i}:'
            f'/var/empty/bench{i:04d}:/bin/bash\n' for i in range(5000))
        accounts += 'benchuser:x:4242:4242:benchuser:/var/empty/benchuser:/bin/bash\n'
        (root/'account.passwd').write_bytes(accounts.encode())
    # Argon2id PHC for the bytes in root/'password', produced once by the
    # builtin itself (passwd add-fd) and frozen here. The salt is fixed, and a
    # last-change day of 20000 with max_days 99999 keeps the aging fields valid.
    if not (root/'account.shadow').exists():
        (root/'account.shadow').write_bytes(
            b'benchuser:$argon2id$v=19$m=19456,t=2,p=1'
            b'$1c0abbb2d0f91f1794d2b5d9a46357bb'
            b'$c742c0a1ebcd0b8cada06235fe60b3f272333064eee009bc738fd80ae8c084c0'
            b':20000:0:99999:7:::\n')
    if not (root/'account.group').exists():
        (root/'account.group').write_bytes(b'benchuser:x:4242:\n')
    # The 14-byte KDF input, redirected onto stdin for `passwd verify-fd`.
    if not (root/'password').exists():
        (root/'password').write_bytes(b'bench-password')
    # BPW_LOCK_DIR: passwd unlinks fail.<uid> here on a successful verify.
    if not (root/'lockdir').exists():
        (root/'lockdir').mkdir()
    # BASHUSERDB_CONF with no providers, so userdb forks nothing.
    if not (root/'userdb.conf').exists():
        (root/'userdb.conf').write_bytes(b'')
    # sudoers-shaped policy for `auth policy-parse`: 2 Defaults, 400 aliases
    # and 2,000 rules, 2,403 lines / 129,710 bytes.
    if not (root/'auth.policy').exists():
        policy = ['# bash-os auth policy fixture',
                  'Defaults requiretty = true',
                  'Defaults secure_path = /usr/sbin:/usr/bin:/sbin:/bin']
        for i in range(200):
            policy.append(f'User_Alias BENCHERS{i:03d} = bench{i:04d}, '
                          f'bench{i+1:04d}, bench{i+2:04d}')
            policy.append(f'Cmnd_Alias BENCHCMD{i:03d} = /usr/bin/tool{i:03d}, '
                          f'/usr/sbin/tool{i:03d}')
        for i in range(2000):
            policy.append(f'bench{i:04d} ALL = (ALL:ALL) NOPASSWD: /usr/bin/tool{i%97:03d}')
        (root/'auth.policy').write_bytes(('\n'.join(policy)+'\n').encode())
    # Recorded outside the guards, so a shared artifact another group built
    # first is still reported with the bytes and hash actually on disk.
    for name in ('account.passwd', 'account.shadow', 'account.group', 'password',
                 'auth.policy', 'userdb.conf'):
        record(root/name, name)
    # --- editor-app ---
    # vi scripted-keystroke stream, read through argv (`--keys vikeys`):
    # 1,000 `x` character deletes, one regex search, 200 `dd` line deletes,
    # 50 `p` line pastes, then a save and quit. Deliberately no `G` before the
    # dd run: once a dd removes the last line the builtin leaves the cursor
    # past the end of the buffer and every later edit is a silent no-op.
    if not (root/'vikeys').exists():
        (root/'vikeys').write_bytes(b'jjx'*1000 + b'/left\r' + b'dd'*200
                                    + b'yy' + b'p'*50 + b':w keysout\r:q!\r')
        record(root/'vikeys', 'vikeys')
    # screen remote-relay frame: 'BSCR' magic, version 1, FRAME_PTY, a 32-bit
    # big-endian payload length, then the `text` fixture as the payload.
    if not (root/'screenframe').exists():
        (root/'screenframe').write_bytes(
            b'BSCR' + bytes([1, 1]) + len(text).to_bytes(4, 'big') + text)
        record(root/'screenframe', 'screenframe')
    # script/scriptreplay pair, both named on argv. The leading empty line is
    # the banner slot: util-linux scriptreplay always skips the typescript's
    # first line, and bash-os `script record` writes no banner.
    if not (root/'scriptlog').exists():
        (root/'scriptlog').write_bytes(b'\n' + text)
        record(root/'scriptlog', 'scriptlog')
    if not (root/'scripttiming').exists():
        remaining, rows = len(text) + 1, []
        while remaining > 0:
            chunk = min(4096, remaining)
            rows.append(f'0.000000 {chunk}\n')
            remaining -= chunk
        (root/'scripttiming').write_text(''.join(rows))
        record(root/'scripttiming', 'scripttiming')
    # dialog/whiptail non-interactive checklist input: 15,000 tag lines.
    if not (root/'dialogtags').exists():
        (root/'dialogtags').write_bytes(b'alpha\nbeta\ngamma\n'*5000)
        record(root/'dialogtags', 'dialogtags')
    # Synthetic utmp for wall: four USER_PROCESS records naming tty0..tty3.
    # A private utmp for wall: the shared `utmpfix` is 4096 records across 64
    # fxpts/N terminals, which are not the terminals devfix provides and not the
    # four-record walk wall's work= describes. Sharing it would have made wall
    # write to devfix/fxpts/N, which does not exist.
    if not (root/'wallutmp').exists():
        import struct
        utmp = b''
        for index in range(4):
            entry = bytearray(384)           # sizeof(struct utmp), glibc x86-64
            struct.pack_into('<h', entry, 0, 7)            # ut_type USER_PROCESS
            struct.pack_into('<i', entry, 4, 1000 + index)  # ut_pid
            entry[8:8+len(f'tty{index}')] = f'tty{index}'.encode()  # ut_line @8
            entry[40:42] = f't{index}'.encode()            # ut_id[4]     @40
            entry[44:51] = b'fixture'                      # ut_user[32]  @44
            entry[76:87] = b'fixturehost'                  # ut_host[256] @76
            utmp += bytes(entry)             # ut_session @336, ut_tv @340 zero
        (root/'wallutmp').write_bytes(utmp)
        record(root/'wallutmp', 'wallutmp')
    # Fake terminal targets for wall and write. Mode 0620 is what makes the
    # mesg gate pass for a non-root caller; both cases re-apply it in `reset`
    # because the harness unlinks the compared destination before pass 1.
    if not (root/'devfix').exists():
        (root/'devfix').mkdir()
        for index in range(4):
            target = root/'devfix'/f'tty{index}'
            target.write_bytes(b'')
            os.chmod(target, 0o620)
    # A live AF_UNIX datagram receiver for the notify case, held open for the
    # whole run: without it sendto() gets ECONNREFUSED, the builtin returns
    # failure and the batch aborts. The draining thread is not optional -
    # thousands of datagrams overrun the receive buffer and a full queue makes
    # the builtin's blocking sendto() hang.
    if not (root/'notify.sock').exists():
        import socket
        import threading
        receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        address = str(root/'notify.sock')
        if len(address.encode()) < 100:      # sun_path is 108 bytes
            receiver.bind(address)
        else:                                # long TMPDIR: bind relative to root
            here = os.getcwd()
            os.chdir(root)
            receiver.bind('notify.sock')
            os.chdir(here)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)

        def drain(handle):
            while True:
                try:
                    handle.recv(65536)
                except OSError:
                    return
        threading.Thread(target=drain, args=(receiver,), daemon=True).start()
        # Keep a reference on the function object so the socket outlives this
        # call and stays bound for every pass of the batch.
        fixtures.receivers = getattr(fixtures, 'receivers', [])
        fixtures.receivers.append(receiver)
        hashes['notify.sock'] = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
    # --- terminal-prim ---
    # Imported here rather than inside the PNG block below so the names stay
    # bound whichever group's copy of that shared recipe actually runs.
    import struct
    import zlib
    # Private pty master. Each open() of this symlink allocates a fresh pts
    # pair that the kernel frees on close, so a redirect from it hands the
    # builtin a brand-new terminal. There is no readable content, so the
    # metadata is registered directly.
    if not (root/'ptmx').is_symlink():
        (root/'ptmx').symlink_to('/dev/ptmx')
        hashes['ptmx'] = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
    # kgetch/tinfo-style keymap. 126 key_* definitions layered over kgetch's
    # 34 built-in ANSI entries fill its 160-entry table exactly. The first
    # line is a 64-byte sequence - the largest bk_add() accepts - so
    # `kgetch decode` exercises the whole hex parser and a 126-entry scan.
    # Read by name through BASHKGETCH_TERMINFO, not from stdin.
    if not (root/'keymap').exists():
        keynames = ['key_f5', 'key_f6', 'key_f7', 'key_f8', 'key_f9', 'key_f10',
                    'key_f11', 'key_f12', 'key_s_up', 'key_s_down', 'key_s_left',
                    'key_s_right', 'key_ppage', 'key_npage', 'key_ic', 'key_dc',
                    'key_home', 'key_end', 'key_up', 'key_down', 'key_left',
                    'key_right']
        keylines = ['key_f5=\\E['+'9'*61+'~']
        keylines += ['%s=\\E[%d;%d~' % (keynames[i % len(keynames)], 300+i, i % 8)
                     for i in range(125)]
        (root/'keymap').write_bytes(('\n'.join(keylines)+'\n').encode())
        record(root/'keymap', 'keymap')
    # 2048 shift-Up CSI records for the fd-driven key decoders.
    if not (root/'keyseq').exists():
        (root/'keyseq').write_bytes(b'\x1b[1;2A'*2048)
        record(root/'keyseq', 'keyseq')
    # Deterministic VT traffic for the vt parser - SGR (basic, 256-colour,
    # truecolour), CUP/CUU/CUD/CUF/CUB, EL/ED, DECSTBM scroll regions, IL/DL,
    # DECSC/DECRC, tabs, wide CJK and combining-mark UTF-8, and words. Uses
    # its OWN Random instance: drawing from the module-level rng would shift
    # every later fixture's bytes. No OSC/DSR/DA, so nothing accumulates in
    # the response buffer.
    if not (root/'vtstream').exists():
        vrng = random.Random(20260912)
        vwords = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
        vwide = ['世界', 'こん', 'ę́', 'é']
        out = bytearray()
        for i in range(6000):
            r = i % 12
            if r == 0:    out += b'\x1b[%d;%dm' % (30+i % 8, 40+(i//8) % 8)
            elif r == 1:  out += b'\x1b[38;5;%dm' % (i % 256)
            elif r == 2:  out += b'\x1b[38;2;%d;%d;%dm' % (i % 256, (i*7) % 256, (i*13) % 256)
            elif r == 3:  out += b'\x1b[%d;%dH' % (1+i % 50, 1+i % 200)
            elif r == 4:  out += b'\x1b[%dC\x1b[%dD\x1b[%dA\x1b[%dB' % (1+i % 5, 1+i % 3, 1+i % 4, 1+i % 2)
            elif r == 5:  out += b'\x1b[K' if i % 2 else b'\x1b[2K'
            elif r == 6:  out += b'\x1b[%d;%dr' % (1+i % 10, 20+i % 30)
            elif r == 7:  out += b'\x1b7'+' '.join(vrng.choice(vwords) for _ in range(6)).encode()+b'\x1b8'
            elif r == 8:  out += vwide[i % len(vwide)].encode()*3
            elif r == 9:  out += b'\t\x1b[4m'+vrng.choice(vwords).encode()+b'\x1b[0m'
            elif r == 10: out += b'\x1b[%dL\x1b[%dM' % (1+i % 3, 1+i % 3)
            else:         out += b'\x1b[m'
            out += ' '.join(vrng.choice(vwords) for _ in range(8)).encode()
            out += b'\r\n' if i % 3 else b'\n'
        (root/'vtstream').write_bytes(bytes(out))
        record(root/'vtstream', 'vtstream')
    # Deterministic 256x256 RGB PNG for the image encoders (sixel, tiv,
    # kitty). Smooth gradient plus two flat shapes so the RLE and
    # run-detection paths both do real work. Written with zlib/struct so no
    # image library is needed. The commands open it by name from this root
    # rather than reading stdin; record() keeps it in the published list.
    if not (root/'image.png').exists():
        pw = ph = 256
        px = bytearray()
        for y in range(ph):
            for x in range(pw):
                r, g, b = x*255//(pw-1), y*255//(ph-1), (x+y)*255//(pw+ph-2)
                if 60 <= x < 100 and 60 <= y < 160: r, g, b = 240, 30, 30
                if (x-180)**2 + (y-80)**2 < 1600: r, g, b = 20, 200, 120
                px += bytes((r, g, b))
        raw = b''.join(b'\x00'+bytes(px[y*pw*3:(y+1)*pw*3]) for y in range(ph))

        def png_chunk(tag, payload):
            body = tag+payload
            return (struct.pack('>I', len(payload))+body
                    + struct.pack('>I', zlib.crc32(body) & 0xffffffff))
        (root/'image.png').write_bytes(
            b'\x89PNG\r\n\x1a\n'
            + png_chunk(b'IHDR', struct.pack('>IIBBBBB', pw, ph, 8, 2, 0, 0, 0))
            + png_chunk(b'IDAT', zlib.compress(raw, 6))
            + png_chunk(b'IEND', b''))
        record(root/'image.png', 'image.png')
    # --- git-object ---
    # Loose-object store for `obj --batch-check` / `git cat-file --batch-check`,
    # plus the 40-hex SHA list both read from stdin. Built from pure Python
    # (sha1 + zlib), so no git is needed to create it, and no pack directory is
    # written, so git reads the same loose objects the builtin does.
    def build_gitloose(root, count=3000):
        import zlib
        g = root/'gitloose'/'.git'
        (g/'objects').mkdir(parents=True, exist_ok=True)
        (g/'refs'/'heads').mkdir(parents=True, exist_ok=True)
        (g/'HEAD').write_text('ref: refs/heads/main\n')
        local = random.Random(20260912)
        shas = []
        for _ in range(count):
            body = ''.join(' '.join(local.choice(words) for _ in range(12))+'\n'
                           for _ in range(16)).encode()
            raw = b'blob '+str(len(body)).encode()+b'\0'+body
            sha = hashlib.sha1(raw).hexdigest()
            directory = g/'objects'/sha[:2]
            directory.mkdir(parents=True, exist_ok=True)
            (directory/sha[2:]).write_bytes(zlib.compress(raw, 6))
            shas.append(sha)
        (root/'gitshalist').write_bytes(
            ''.join(sha+'\n' for sha in sorted(set(shas))).encode())

    if not (root/'gitloose').exists():
        build_gitloose(root)
    record(root/'gitshalist', 'gitshalist')

    # A v2 pack plus its .idx, read by `pack cat` and by `git cat-file blob`.
    # 201 non-delta entries; the first is a 4 MiB blob whose sha1 must stay
    # 882badb336048d3cb6451ea86563e470d8f98f4d, which pack-cat names.
    # packrepo/.git/objects holds only 'pack', so git cannot fall back to a
    # loose copy. Validated with `git verify-pack -v`.
    def build_packrepo(root):
        import struct
        import zlib
        local = random.Random(20260912)

        def body(lines):
            return ''.join(' '.join(local.choice(words) for _ in range(10))+'\n'
                           for _ in range(lines)).encode()
        blobs = [body(90000)[:4*1024*1024]] + [body(16)[:1024] for _ in range(200)]
        entries, chunks, offset = [], [], 12
        for payload in blobs:
            raw = b'blob '+str(len(payload)).encode()+b'\0'+payload
            sha = hashlib.sha1(raw).digest()
            size, first = len(payload), (3 << 4) | (len(payload) & 0x0f)
            head, size = bytearray(), size >> 4
            head.append(first | (0x80 if size else 0))
            while size:
                head.append((size & 0x7f) | (0x80 if size >> 7 else 0))
                size >>= 7
            data = bytes(head)+zlib.compress(payload, 6)
            entries.append((sha, offset, zlib.crc32(data) & 0xffffffff))
            chunks.append(data)
            offset += len(data)
        pack = b'PACK'+struct.pack('>II', 2, len(blobs))+b''.join(chunks)
        pack += hashlib.sha1(pack).digest()
        entries.sort(key=lambda entry: entry[0])
        counts = [0]*256
        for sha, _, _ in entries:
            counts[sha[0]] += 1
        total, cumulative = 0, []
        for count in counts:
            total += count
            cumulative.append(total)
        idx = b'\377tOc'+struct.pack('>I', 2)
        idx += b''.join(struct.pack('>I', count) for count in cumulative)
        idx += b''.join(sha for sha, _, _ in entries)
        idx += b''.join(struct.pack('>I', crc) for _, _, crc in entries)
        idx += b''.join(struct.pack('>I', off) for _, off, _ in entries)
        idx += pack[-20:]
        idx += hashlib.sha1(idx).digest()
        directory = root/'packrepo'/'.git'/'objects'/'pack'
        directory.mkdir(parents=True, exist_ok=True)
        (root/'packrepo'/'.git'/'refs'/'heads').mkdir(parents=True, exist_ok=True)
        (root/'packrepo'/'.git'/'HEAD').write_text('ref: refs/heads/main\n')
        (directory/'pack-fixture.pack').write_bytes(pack)
        (directory/'pack-fixture.idx').write_bytes(idx)

    if not (root/'packrepo').exists():
        build_packrepo(root)
    record(root/'packrepo'/'.git'/'objects'/'pack'/'pack-fixture.pack',
           'pack-fixture.pack')
    record(root/'packrepo'/'.git'/'objects'/'pack'/'pack-fixture.idx',
           'pack-fixture.idx')

    # A git index v2 with 20000 entries, read by `index read` and by
    # `git ls-files --stage`. Every stat field is zeroed, so the fixture
    # carries no ctime/mtime/dev/ino and is byte-reproducible.
    def build_indexrepo(root, count=20000):
        import struct
        body = b'DIRC'+struct.pack('>II', 2, count)
        for i in range(count):
            path = ('dir%03d/file-%05d.txt' % (i % 256, i)).encode()
            sha = hashlib.sha1(b'entry %d' % i).digest()
            entry = struct.pack('>10I', 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, 0)
            entry += sha+struct.pack('>H', len(path))+path+b'\0'
            while len(entry) % 8:
                entry += b'\0'
            body += entry
        body += hashlib.sha1(body).digest()
        directory = root/'indexrepo'/'.git'
        (directory/'objects').mkdir(parents=True, exist_ok=True)
        (directory/'refs'/'heads').mkdir(parents=True, exist_ok=True)
        (directory/'HEAD').write_text('ref: refs/heads/main\n')
        (directory/'index').write_bytes(body)

    if not (root/'indexrepo').exists():
        build_indexrepo(root)
    record(root/'indexrepo'/'.git'/'index', 'indexrepo.index')

    # A pkg repo INDEX that `pkg search --root pkgroot` scans. Only the repos
    # directory exists, so pkg's installed/ and cache/ opendirs miss cleanly.
    def build_pkgroot(root, count=20000):
        names = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta']
        lines = []
        for i in range(count):
            name = 'mod-%05d-%s' % (i, names[i % 8])
            sha = hashlib.sha256(('pkg %d' % i).encode()).hexdigest()
            lines.append('pkg-loadable-v1 name=%s version=1.%d.0 builtin=%s abi=bash-5.3 '
                         'arch=x86_64 sha256=%s package=%s-1.%d.0.pkg sig=%s-1.%d.0.pkg.sig deps=-'
                         % (name, i % 97, name, sha, name, i % 97, name, i % 97))
        directory = root/'pkgroot'/'var'/'lib'/'pkg'/'repos'/'fixture'
        directory.mkdir(parents=True, exist_ok=True)
        (directory/'INDEX').write_bytes(('\n'.join(lines)+'\n').encode())

    if not (root/'pkgroot').exists():
        build_pkgroot(root)
    record(root/'pkgroot'/'var'/'lib'/'pkg'/'repos'/'fixture'/'INDEX', 'pkgroot.INDEX')

    # The staged share INDEX and the bl-pkg install state that `payload list`
    # reads through PAYLOAD_REPO / PAYLOAD_ROOT.
    def build_payload(root, count=20000):
        repo = root/'payloadrepo'
        repo.mkdir(exist_ok=True)
        state = root/'payloadroot'/'var'/'lib'/'bl-pkg'/'installed'
        state.mkdir(parents=True, exist_ok=True)
        lines = ['# bashy.box payload index (fixture)']
        for i in range(count):
            name = 'pl-%05d' % i
            lines.append('blpkg-v1 name=%s version=1.%d.0 arch=x86_64 type=payload provides=bin/%s'
                         % (name, i % 53, name))
            if i % 8 == 0:
                (state/name).write_text('txn=txn-%05d\nversion=1.%d.0\n' % (i, i % 53))
        (repo/'INDEX').write_bytes(('\n'.join(lines)+'\n').encode())

    if not (root/'payloadrepo').exists():
        build_payload(root)
    record(root/'payloadrepo'/'INDEX', 'payloadrepo.INDEX')

    # The cluster state directory BASHCLUSTER_STATE_DIR points at. `cluster
    # members` streams the roster verbatim, which is why cat is the reference.
    # listener_pid is inert: there is no kill() anywhere in cluster.c.
    def build_clusterstate(root, count=20000):
        directory = root/'clusterstate'
        directory.mkdir(exist_ok=True)
        (directory/'cluster_id').write_text('cluster-fixture-0001\n')
        (directory/'node_id').write_text('node-fixture-0001\n')
        (directory/'port').write_text('5450\n')
        (directory/'listener_pid').write_text('1\n')
        rows = ['node-%05d-0000-4000-8000-000000000000 10.%d.%d.%d:5450 '
                '/etc/cluster/keys/node-%05d.key'
                % (i, i//65536 % 256, i//256 % 256, i % 256, i) for i in range(count)]
        (directory/'members').write_bytes(('\n'.join(rows)+'\n').encode())

    if not (root/'clusterstate').exists():
        build_clusterstate(root)
    record(root/'clusterstate'/'members', 'clusterstate.members')

    # The service log BASHSV_LOGDIR makes `sv log fixture` read; bsv_log's path
    # is <BASHSV_LOGDIR>/<name>, with no suffix. svrun/ and svetc/ exist only
    # so that sv.c:3691's unconditional bsv_mkdir_p(bsv_run_dir) -- which every
    # sv verb runs before dispatch, read-only verbs included -- is an EEXIST
    # no-op inside the fixture root instead of an attempted mkdir('/run/sv')
    # against the real host on every pass. Rows stay inside sv.c's line[512].
    def build_svlog(root, count=40000):
        directory = root/'svlog'
        directory.mkdir(exist_ok=True)
        (root/'svrun').mkdir(exist_ok=True)
        (root/'svetc').mkdir(exist_ok=True)
        rows = ['2026-01-01T00:00:%02d fixture[%05d] service log record %05d status=ok'
                % (i % 60, i, i) for i in range(count)]
        (directory/'fixture').write_bytes(('\n'.join(rows)+'\n').encode())

    if not (root/'svlog').exists():
        build_svlog(root)
    record(root/'svlog'/'fixture', 'svlog.fixture')

    # stdin fixture: a complete HTTP/1.1 200 streaming response (headers,
    # Transfer-Encoding: chunked, terminal zero-chunk) with 20004 SSE events.
    # Every 50th delta carries an escaped newline, quote, backslash and TAB so
    # the JSON string decoder is exercised, not just the line splitter. No
    # timestamps, ids, pids or random values reach the compared bytes.
    def build_sseresponse(root, count=20000):
        local = random.Random(20260912)
        events = ['event: message_start\ndata: {"type":"message_start","message":'
                  '{"id":"msg_fixture","model":"claude-fixture","role":"assistant","content":[]}}\n\n',
                  'event: content_block_start\ndata: {"type":"content_block_start","index":0,'
                  '"content_block":{"type":"text","text":""}}\n\n']
        for i in range(count):
            piece = ' '.join(local.choice(words) for _ in range(8))
            if i % 50 == 0:
                piece += '\n"quoted\\slash" \ttab'
            events.append('event: content_block_delta\ndata: '+json.dumps(
                {'type': 'content_block_delta', 'index': 0,
                 'delta': {'type': 'text_delta', 'text': piece+' '}},
                separators=(',', ':'))+'\n\n')
        events.append('event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n')
        events.append('event: message_stop\ndata: {"type":"message_stop"}\n\n')
        body = ''.join(events).encode()
        chunks = [('%x\r\n' % len(body[at:at+8000])).encode()+body[at:at+8000]+b'\r\n'
                  for at in range(0, len(body), 8000)]
        chunks.append(b'0\r\n\r\n')
        head = (b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n'
                b'Transfer-Encoding: chunked\r\nanthropic-version: 2023-06-01\r\n\r\n')
        (root/'sseresponse').write_bytes(head+b''.join(chunks))

    if not (root/'sseresponse').exists():
        build_sseresponse(root)
    record(root/'sseresponse', 'sseresponse')

    # stdin fixture: one JSON string literal whose decoded form is 635986
    # bytes. Every 97th line carries an escaped quote, an escaped backslash, a
    # TAB, a control character and two non-ASCII code points, so ensure_ascii
    # puts \u escapes in the literal and the UTF-8 emit path is covered.
    def build_jsonstring(root, count=12000):
        local = random.Random(20260912)
        parts = []
        for i in range(count):
            line = ' '.join(local.choice(words) for _ in range(10))
            if i % 97 == 0:
                line += ' "quoted" back\\slash tab\there ctrl\x01 unicodeé中'
            parts.append(line)
        text = '\n'.join(parts)+'\n'
        (root/'jsonstring').write_bytes(json.dumps(text, ensure_ascii=True).encode()+b'\n')

    if not (root/'jsonstring').exists():
        build_jsonstring(root)
    record(root/'jsonstring', 'jsonstring')
    # --- data-parser ---
    # These three are named files read from argv or from a case's reset, not
    # stdin fixtures, so their cases keep fixture='empty'. Each is guarded so a
    # duplicate block from another group is a no-op.
    # config.toml: 605 tables / 186,758 bytes. Its own Random(20260912) keeps
    # the shared rng stream - and so every fixture drawn from it - unchanged.
    if not (root/'config.toml').exists():
        toml_rng = random.Random(20260912)
        toml_words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta']
        toml_lines = ['title = "bash-os toml fixture"\n', 'revision = 17\n',
                      'ratio = 0.5\n', 'enabled = true\n',
                      'stamp = 1979-05-27T07:32:00Z\n\n']
        for i in range(600):
            toml_lines += [
                f'[section{i:04d}]\n',
                f'name = "{toml_words[i%8]}-{i:04d}"\n',
                f'index = {i}\n',
                f'weight = {i/8:.4f}\n',
                f'active = {"true" if i%2 == 0 else "false"}\n',
                'tags = ['+', '.join(f'"{toml_words[(i+j)%8]}"' for j in range(6))+']\n',
                f'numbers = [{", ".join(str((i*j)%1000) for j in range(8))}]\n',
                f'text = "{" ".join(toml_rng.choice(toml_words) for _ in range(12))}"\n',
                f'[section{i:04d}.nested]\n',
                'depth = 2\n',
                f'label = "{toml_words[(i+3)%8]}"\n\n']
        (root/'config.toml').write_bytes(''.join(toml_lines).encode())
        record(root/'config.toml', 'config.toml')
    # vector.npy: 1,000,000 little-endian int64 values / 8,000,128 bytes. int64
    # rather than float keeps `vec sum` and `vec dot` exact, so their check is an
    # integer comparison instead of an FP-associativity argument.
    if not (root/'vector.npy').exists():
        import struct
        vec_count = 1000000
        vec_header = "{'descr': '<i8', 'fortran_order': False, 'shape': (%d,), }" % vec_count
        vec_prefix = b'\x93NUMPY\x01\x00'
        vec_pad = (64 - (len(vec_prefix)+2+len(vec_header)+1) % 64) % 64
        vec_header = vec_header+' '*vec_pad+'\n'
        (root/'vector.npy').write_bytes(
            vec_prefix+struct.pack('<H', len(vec_header))+vec_header.encode()
            + struct.pack('<%dq' % vec_count, *[(i*7919) % 100003 for i in range(vec_count)]))
        record(root/'vector.npy', 'vector.npy')
    # bench.db: 100,000 rows / 2,252,800 bytes, built with the sqlite3 module,
    # not a host program. VACUUM leaves one file with no journal beside it.
    if not (root/'bench.db').exists():
        import sqlite3
        db_words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta']
        connection = sqlite3.connect(root/'bench.db')
        connection.execute('PRAGMA journal_mode=OFF')
        connection.execute('CREATE TABLE items (id INTEGER PRIMARY KEY, k TEXT NOT NULL, v INTEGER NOT NULL)')
        connection.executemany('INSERT INTO items (id,k,v) VALUES (?,?,?)',
                               [(i, f'{db_words[i%8]}-{i%997:04d}', (i*7919) % 100003)
                                for i in range(100000)])
        connection.commit()
        connection.execute('VACUUM')
        connection.commit()
        connection.close()
        record(root/'bench.db', 'bench.db')
    # --- syscall-ipc ---
    # No new fixture artifacts. Every syscall-ipc case either reads an existing
    # fixture from stdin (bashio-pread uses `text`, bashio-pread-hex uses
    # `bytes`) or takes no stdin at all (`empty`) and builds whatever state it
    # needs in its own `reset`, using builtins only:
    #   bashpoll-wait     dup2's the harness's stderr pipe onto fds 3-9
    #   bashinotify-drain creates iw/ and iw/f1..f32 with the mkdir and touch
    #                     builtins on the first pass, then re-touches them
    #   scm-recv-fd       makes its socketpair and sends the descriptor
    #   pty-spawn         reaps and closes the previous pass's pty session
    #   strace-summary    writes only its own output='strace.out' destination
    # No host tool is needed, so this group adds no shutil.which guard and
    # defines no shared artifact.
    # --- repeat-input ---
    # bashkmod: a synthetic /lib/modules/<version> tree, reached with
    # BASHKMOD_MODULES_DIR=modules. depmod's two generated manifests are what
    # `bashkmod aliases` and `bashkmod deps` parse; the host's real module tree
    # is never opened. (Auxiliary artifacts; the case's stdin fixture is 'empty'.)
    if not (root/'modules').exists():
        names = [f'mod{i:05d}' for i in range(4000)]
        (root/'modules').mkdir()
        dep = []
        for i, name in enumerate(names):
            deps = [f'kernel/drivers/base/{names[(i*7+k) % len(names)]}.ko'
                    for k in range(1, 1+(i % 4))]
            dep.append(f'kernel/drivers/net/{name}.ko: '+' '.join(deps))
        (root/'modules'/'modules.dep').write_text('\n'.join(dep)+'\n')
        alias = ['# depmod-generated fixture']
        for i, name in enumerate(names):
            vendor, device = 0x8086+(i % 64), 0x1000+i
            alias.append(f'alias pci:v0000{vendor:04X}d0000{device:04X}sv*sd*bc*sc*i* {name}')
            alias.append(f'alias usb:v{vendor:04X}p{device:04X}d*dc*dsc*dp*ic*isc*ip*in* {name}')
            if i % 10 == 0:
                alias.append(f'alias pci:v0000{vendor:04X}d*sv*sd*bc*sc*i* {name}')
            if i % 20 == 0:
                # one shared device-class family, the way several drivers claim
                # the same xHCI class: a class query matches every one of them.
                alias.append(f'alias pci:v*d*sv*sd*bc0Csc03i30 {name}')
        (root/'modules'/'modules.alias').write_text('\n'.join(alias)+'\n')
        record(root/'modules'/'modules.dep', 'modules.dep')
        record(root/'modules'/'modules.alias', 'modules.alias')
    # bashmount --findmnt-table: a synthetic /proc/self/mountinfo. Unescaped
    # paths and fsroot "/" on purpose, so util-linux findmnt --raw prints the
    # same eight field values (an escaped path prints \x20 there, and a
    # non-"/" fsroot makes findmnt append "[<fsroot>]" to SOURCE).
    # (Auxiliary artifact; the case's stdin fixture is 'empty'.)
    if not (root/'mountinfo').exists():
        mounts = []
        for i in range(2000):
            mount_id, parent = 20+i, (1 if i % 8 else 20)
            if i % 10 == 3:                   # no optional fields before the dash
                mounts.append(f'{mount_id} {parent} 0:{24+i % 40} / /mnt/tmp{i:04d} '
                              f'rw,nosuid,nodev - tmpfs tmpfs rw,size=65536k')
            else:
                mounts.append(f'{mount_id} {parent} 254:{i % 250} / /mnt/point{i:04d} '
                              f'rw,relatime shared:{i % 37} - ext4 '
                              f'/dev/mapper/vg-lv{i:04d} rw,errors=remount-ro')
        (root/'mountinfo').write_text('\n'.join(mounts)+'\n')
        record(root/'mountinfo', 'mountinfo')
    # mail newaliases: an /etc/aliases-shaped manifest, read with --aliases and
    # compiled to --db. Its own Random so the shared rng stream (and therefore
    # every other fixture's bytes) is untouched. Keys are emitted in shuffled
    # order so the qsort is real work, and a comment line, inline comments and
    # padded fields exercise the strip/trim path.
    # (Auxiliary artifact; the case's stdin fixture is 'empty'.)
    if not (root/'aliases.txt').exists():
        alias_rng = random.Random(20260912)
        order = list(range(5000))
        alias_rng.shuffle(order)
        entries = ['# fixture aliases (depmod-style manifest for newaliases)']
        for n, i in enumerate(order):
            entry = f'alias{i:05d}: user{i%997:04d}@ex.invalid'
            if n % 500 == 0:
                entry += '   # operator note'
            elif n % 97 == 0:
                entry = '  '+entry+'  '
            entries.append(entry)
        (root/'aliases.txt').write_text('\n'.join(entries)+'\n')
        record(root/'aliases.txt', 'aliases.txt')
    # lpr list: a prefilled print spool, reached with BASHLPR_SPOOL=lprspool.
    # The one non-.lpr entry checks the suffix filter.
    # (Auxiliary artifact; the case's stdin fixture is 'empty'.)
    if not (root/'lprspool').exists():
        (root/'lprspool').mkdir()
        for i in range(4000):
            (root/'lprspool'/f'{i:016x}.lpr').write_bytes(b'job\n')
        (root/'lprspool'/'operator-notes.txt').write_bytes(b'not a job\n')
    # apropos + whatis: a plain-text whatis index under a fixture MANPATH.
    # man-db reads the same file (it greps it when no index.db exists), so GNU
    # apropos/whatis are byte-exact references on it.
    # (Auxiliary artifact; the cases' stdin fixture is 'empty'.)
    if not (root/'manfix').exists():
        topics = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta']
        (root/'manfix').mkdir()
        (root/'manfix'/'whatis').write_text('\n'.join(
            f'tool{i:05d}({1+i % 8}) - {topics[i % len(topics)]} utility number {i} '
            f'for the fixture corpus' for i in range(20000))+'\n')
        record(root/'manfix'/'whatis', 'whatis')
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
        needed = None
        if selected:
            needed = {case['fixture'] for case in inventory}
            # xattr reads the xattrs operand with empty stdin.
            if any(case['loadable'] == 'xattr' for case in inventory):
                needed.add('xattrs')
        report['fixtures'] = fixtures(root, needed)

        def run(command, case, count, *, capture=False):
            # mode='fresh' runs each pass in a subshell. The fork gives the pass
            # a private copy of the process, so a command that keeps stdio or
            # other state across calls starts clean every time, the way it would
            # in a pipeline. It costs one fork per pass on both sides, so a
            # fresh-mode timing is only comparable with another fresh-mode one.
            body = '( "$@" < "$input" )' if case['mode'] == 'fresh' else '"$@" < "$input"'
            # reset restores a mutator's precondition before every pass; it runs
            # with the same empty PATH, so it must use builtins only.
            step = f'{{ {case["reset"]}; }} || exit; {body} || exit' if case['reset'] else f'{body} || exit'
            script = f'input=$1; count=$2; shift 2; for ((i=0;i<count;i++)); do {step}; done'
            argv = [str(binary),'--noprofile','--norc','-c',script,'bench',case['fixture'],str(count),*command]
            environ = {**environment, **case['env']}
            with tempfile.TemporaryFile() as output:
                start = time.perf_counter_ns()
                try:
                    p = subprocess.run(argv, cwd=root, env=environ,
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
            # row['reference'] below becomes the label whose output was the
            # expected bytes, so the declared intent has to be recorded
            # separately or a self-timed case is indistinguishable from a
            # compared one and the catalog would show it as carrying a ratio.
            row['self_timed'] = case['reference'] == 'self'
            row['results'] = {}
            commands = {'bashos':[name,*case['args']]}
            if case['reference'] == 'self':
                # No counterpart exists to compare against, so neither column
                # is a missing tool: record that no comparison applies and
                # measure the builtin on its own.
                row['results']['external'] = {'status':'not-applicable'}
                row['results']['busybox'] = {'status':'not-applicable'}
            else:
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
                result = run(command, case, 1, capture=True)
                if result['status'] == 'ok' and case['output']:
                    result['data'] = (root/case['output']).read_bytes() if (root/case['output']).is_file() else b''
                initial[implementation] = result
            # A self-referenced case validates the builtin against its own first
            # pass, which makes the repeated batch below a determinism check.
            # A first pass that failed is not an expected output.
            if case['reference'] == 'self':
                reference = 'bashos' if initial['bashos']['status'] == 'ok' else None
            else:
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
            probe = run(commands[probe_label],case,5)
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
                batch = run(commands[label],case,validation_passes,capture=True)
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
                    timed = run(commands[label],case,passes)
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
