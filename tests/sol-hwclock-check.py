#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Safe production hwclock fixtures. Compilation is a separate gated step."""
import argparse
import calendar
import datetime as dt
import json
import os
from pathlib import Path
import random
import re
import shlex
import subprocess
import tempfile
from zoneinfo import ZoneInfo

UTC = dt.timezone.utc
ROOT = Path(__file__).resolve().parents[1]

def iso(values):
    y, m, d, h, mi, s = values
    return f'{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}'

def epoch(values, zone=UTC):
    return int(dt.datetime(*values, tzinfo=zone).timestamp())

def fields(t, zone=UTC):
    d = dt.datetime.fromtimestamp(t, zone)
    return (d.year, d.month, d.day, d.hour, d.minute, d.second)

class Driver:
    def __init__(self, binary, module, host=None):
        self.binary, self.module, self.host = map(lambda x: str(Path(x).resolve()) if x else None,
                                                 (binary, module, host))
    def run(self, commands, tz='UTC0', extra=''):
        env = dict(os.environ, TZ=tz, LC_ALL='C', ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        if self.host:
            assert not extra
            script = ''.join('\t'.join(map(str, c))+'\n' for c in commands)
            p = subprocess.run([self.host], input=script, text=True, capture_output=True, env=env)
        else:
            setup = (f'enable -f {shlex.quote(self.module)} hwclock || exit 90\n'
                     f'enable -f {shlex.quote(self.module)} hwclock_fixture || exit 91\nPATH=\n')
            script = setup + ''.join(shlex.join(['hwclock_fixture' if c[0] == 'fixture' else c[0],
                                               *map(str, c[1:])])+"; printf 'STATUS=%s\\n' \"$?\"\n"
                                     for c in commands) + extra
            p = subprocess.run([self.binary, '--noprofile', '--norc'], input=script, text=True,
                               capture_output=True, env=env)
        assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
        assert not re.search(r'AddressSanitizer|runtime error:|LeakSanitizer', p.stderr), p.stderr
        statuses = [int(s) for s in re.findall(r'^STATUS=(\d+)$', p.stdout, re.M)]
        assert len(statuses) == len(commands), (statuses, p.stdout, p.stderr)
        output = re.sub(r'^STATUS=\d+\n', '', p.stdout, flags=re.M)
        return statuses, output, p.stderr
    def case(self, args, rtc=(2024, 2, 29, 12, 34, 56), now=1709210096, fail='', tz='UTC0',
             adj=None, noadj=True, trace=False):
        commands = [('fixture','reset'), ('fixture','rtc',*rtc), ('fixture','now',now)]
        if fail: commands.append(('fixture','fail',fail))
        command = ['hwclock', '--rtc', '/fixture/rtc']
        if noadj: command.append('--noadjfile')
        if adj is not None: command += ['--adjfile', str(adj)]
        command += args
        commands += [command, ('fixture','stats')]
        if trace: commands += [('fixture','trace')]
        statuses, out, err = self.run(commands, tz)
        assert all(s == 0 for i,s in enumerate(statuses) if i != len(commands)-(3 if trace else 2)), statuses
        statline = next(l for l in out.splitlines() if l.startswith('open='))
        stats = dict(v.split('=',1) for v in statline.split())
        for key in stats:
            if key != 'rtc': stats[key] = int(stats[key])
        assert stats['live'] == stats['bad'] == 0, stats
        return statuses[-3 if trace else -2], out.replace(statline+'\n',''), stats, err

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', default='out/bash-sol-hwclock')
    ap.add_argument('--module', required=True)
    ap.add_argument('--host')
    ap.add_argument('--report', required=True)
    ap.add_argument('--regressions', action='store_true', help='Only targeted regression cases (also for baseline)')
    args = ap.parse_args()
    driver = Driver(args.binary, args.module, args.host)
    results = []
    def check(name, f):
        try:
            f(); results.append(dict(name=name,status='pass')); print('PASS', name, flush=True)
        except Exception as e:
            results.append(dict(name=name,status='fail',error=repr(e))); print('FAIL', name, repr(e), flush=True)
    def expect(rc, expected, out=None, exact=None):
        assert rc == expected, (rc, expected, out)
        if exact is not None: assert out == exact, (out,exact)
    with tempfile.TemporaryDirectory(prefix='sol-hwclock-', dir=Path(args.report).resolve().parent) as tmp:
        d = Path(tmp); adj = d/'adjtime'
        def put(text): adj.write_bytes(text.encode() if isinstance(text,str) else text); return adj
        def invalid_calendar():
            rc, out, stats, err = driver.case(['--hctosys'], rtc=(2023,2,29,0,0,0))
            expect(rc,1,out); assert stats['set'] == 0 and 'calendar' in err
        check('regression-invalid-calendar', invalid_calendar)
        def malformed_nan():
            put('nan 1 0\n1\nUTC\n')
            rc,out,stats,err=driver.case(['--show'], adj=adj)
            expect(rc,1,out); assert stats['open'] == 0
        check('regression-nonfinite-adjtime', malformed_nan)
        def trailing():
            put('0 1 0 junk\n1\nUTC\n')
            rc,out,stats,err=driver.case(['--show'], adj=adj)
            expect(rc,1,out); assert stats['open'] == 0
        check('regression-adjtime-trailing-token', trailing)
        def dst_gap():
            rc,out,stats,err=driver.case(['-s','-l'],rtc=(2024,3,10,2,30,0),tz='America/New_York')
            expect(rc,1,out); assert stats['set'] == 0 and 'nonexistent' in err
        check('regression-dst-gap', dst_gap)
        def fractional():
            vals=(2024,3,1,0,0,1); t=epoch(vals)
            put(f'2.5 {t-86400} 0.25\n123\nUTC\n')
            adj.chmod(0o640)
            rc,out,stats,err=driver.case(['-a'],rtc=vals,adj=adj)
            expect(rc,0,out); assert stats['rtc'] == iso(fields(t-2)), stats
            assert adj.read_text() == f'2.500000 {t-2} 0.750000\n123\nUTC\n', adj.read_text()
            assert adj.stat().st_mode & 0o777 == 0o640
            assert list(d.iterdir()) == [adj]
        check('regression-adjust-retains-fraction-and-mode', fractional)
        def systohc_metadata():
            t=epoch((2024,2,29,12,34,56))
            put('2.5 1000 0.75\n500\nLOCAL\n')
            rc,out,stats,err=driver.case(['-w','-u'],adj=adj,now=t)
            expect(rc,0,out)
            assert adj.read_text()==f'2.500000 {t} 0.000000\n{t}\nUTC\n',adj.read_text()
        check('regression-systohc-resets-adjtime-timestamps',systohc_metadata)
        def local_minus_one():
            rc,out,stats,err=driver.case(['-s','-l'],rtc=(1969,12,31,23,59,59),tz='UTC0')
            expect(rc,0,out); assert stats['sys']==-1
        check('regression-local-valid-minus-one-is-not-an-error',local_minus_one)
        if not args.host:
            def output_failure():
                script = '''hwclock_fixture reset
hwclock_fixture rtc 2024 2 29 12 34 56
hwclock --noadjfile --rtc /fixture/rtc >/dev/full; rc=$?
printf 'FULL=%s\\n' "$rc"
hwclock --help >/dev/full; rc=$?
printf 'HELPFULL=%s\\n' "$rc"
hwclock --version >/dev/full; rc=$?
printf 'VERSIONFULL=%s\\n' "$rc"
hwclock --noadjfile --rtc /fixture/rtc; rc=$?
printf 'RECOVER=%s\\n' "$rc"
'''
                statuses,out,err=driver.run([],extra=script)
                assert 'FULL=1\n' in out and 'HELPFULL=1\n' in out and 'VERSIONFULL=1\n' in out and 'RECOVER=0\n' in out and '2024-02-29T12:34:56\n' in out, (out,err)
            check('regression-output-failure-and-recovery', output_failure)
        if not args.regressions:
            rng=random.Random(20261019)
            dates=[(1900,1,1,0,0,0),(1900,2,28,23,59,59),(1969,12,31,23,59,59),
                   (1970,1,1,0,0,0),(1999,12,31,23,59,59),(2000,2,29,0,0,0),
                   (2038,1,19,3,14,8),(2100,3,1,0,0,0),(2400,2,29,0,0,0),
                   (9999,12,31,23,59,59)]
            for _ in range(64):
                y=rng.randrange(1900,10000); m=rng.randrange(1,13)
                dates.append((y,m,rng.randrange(1,calendar.monthrange(y,m)[1]+1),rng.randrange(24),rng.randrange(60),rng.randrange(60)))
            for vals in dates:
                def conversions(vals=vals):
                    t=epoch(vals)
                    rc,out,stats,err=driver.case(['-r','-u'],rtc=vals)
                    expect(rc,0,out,iso(vals)+'\n'); assert stats['read']==stats['close']==1 and stats['cloexec']==1
                    rc,out,stats,err=driver.case(['-s','-u'],rtc=vals)
                    expect(rc,0,out,''); assert stats['sys']==t and stats['nsec']==0,stats
                    rc,out,stats,err=driver.case(['-w','-u'],now=t)
                    expect(rc,0,out,''); assert stats['rtc']==iso(vals) and stats['get']==stats['write']==stats['close']==1,stats
                    expected=dt.datetime(*vals)
                    assert stats['wday']==(expected.weekday()+1)%7 and stats['yday']==expected.timetuple().tm_yday-1 and stats['isdst']==0,stats
                check('utc-oracle-'+iso(vals),conversions)
            local_vals=[(2024,3,10,1,59,59),(2024,3,10,3,0,0),(2024,11,3,0,59,59),
                        (2024,11,3,2,0,0),(2024,1,1,0,0,0),(2024,7,1,0,0,0)]
            for vals in local_vals:
                def local(vals=vals):
                    t=epoch(vals,ZoneInfo('America/New_York'))
                    put('0 0 0\n0\nLOCAL\n')
                    rc,out,stats,err=driver.case(['--hctosys'],rtc=vals,adj=adj,tz='America/New_York')
                    expect(rc,0,out); assert stats['sys']==t,stats
                    rc,out,stats,err=driver.case(['--systohc','--localtime'],now=t,tz='America/New_York')
                    expect(rc,0,out); assert stats['rtc']==iso(vals),stats
                    rc,out,stats,err=driver.case(['-s','-u'],rtc=vals,adj=adj,tz='America/New_York')
                    expect(rc,0,out); assert stats['sys']==epoch(vals),stats
                check('local-oracle-'+iso(vals),local)
            for zone_name,vals in [('Asia/Kathmandu',(2024,1,1,0,0,0)),
                                   ('Pacific/Kiritimati',(2024,1,1,0,0,0)),
                                   ('Australia/Lord_Howe',(2024,10,6,1,59,59)),
                                   ('Australia/Lord_Howe',(2024,10,6,2,30,0))]:
                def nonhour(zone_name=zone_name,vals=vals):
                    t=epoch(vals,ZoneInfo(zone_name))
                    rc,out,stats,err=driver.case(['-s','-l'],rtc=vals,tz=zone_name)
                    expect(rc,0,out); assert stats['sys']==t,stats
                    rc,out,stats,err=driver.case(['-w','-l'],now=t,tz=zone_name)
                    expect(rc,0,out); assert stats['rtc']==iso(vals),stats
                check('local-zone-'+zone_name+'-'+iso(vals),nonhour)
            def half_hour_gap():
                rc,out,stats,err=driver.case(['-s','-l'],rtc=(2024,10,6,2,15,0),tz='Australia/Lord_Howe')
                expect(rc,1,out); assert stats['set']==0
            check('half-hour-dst-gap-is-rejected',half_hour_gap)
            def fold():
                vals=(2024,11,3,1,30,0); zone=ZoneInfo('America/New_York')
                allowed={int(dt.datetime(*vals,tzinfo=zone,fold=f).timestamp()) for f in (0,1)}
                rc,out,stats,err=driver.case(['-s','-l'],rtc=vals,tz='America/New_York')
                expect(rc,0,out); assert stats['sys'] in allowed,stats
                for t in allowed:
                    rc,out,stats,err=driver.case(['-w','-l'],now=t,tz='America/New_York')
                    expect(rc,0,out); assert stats['rtc']==iso(vals),stats
            check('dst-fold-libc-choice-and-both-epoch-oracles',fold)

            invalid=[(1900,2,29,0,0,0),(2100,2,29,0,0,0),(2024,0,1,0,0,0),(2024,13,1,0,0,0),
                     (2024,1,0,0,0,0),(2024,4,31,0,0,0),(2024,1,1,24,0,0),(2024,1,1,0,60,0),
                     (2024,1,1,0,0,60),(2024,1,1,-1,0,0),(1899,12,31,23,59,59),(10000,1,1,0,0,0)]
            for vals in invalid:
                def bad_calendar(vals=vals):
                    for action in ('--show','--hctosys','--adjust'):
                        put('1 1 0\n1\nUTC\n')
                        rc,out,stats,err=driver.case([action],rtc=vals,adj=adj)
                        expect(rc,1,out); assert stats['set']==stats['write']==0,stats
                check('invalid-calendar-'+iso(vals),bad_calendar)
            malformed=['','0 0 0\n0\n','oops\n0\nUTC\n','0 1\n0\nUTC\n',
                       '0 1 0\n0 garbage\nUTC\n','0 1 0\n0\nlocal\n','0 1 0\n0\nUTC\nX',
                       'inf 1 0\n0\nUTC\n','0 1 -inf\n0\nUTC\n','1e999 1 0\n0\nUTC\n',
                       '0 999999999999999999999999 0\n0\nUTC\n','0 1 0\n999999999999999999999999\nUTC\n',
                       '0 1 0\x00junk\n0\nUTC\n','0 1 0'+' '*200+'\n0\nUTC\n',
                       '0 1 0\n0 '+' '*200+'\nUTC\n','0 1 0\n0\nUTC'+' '*200+'\n',
                       '0x 1 0\n0\nUTC\n','0 1x 0\n0\nUTC\n','0 1 0junk\n0\nUTC\n']
            for i,text in enumerate(malformed):
                def bad_adj(text=text):
                    put(text)
                    for action in ('--show','--hctosys','--systohc','--adjust'):
                        rc,out,stats,err=driver.case([action],adj=adj)
                        expect(rc,1,out); assert stats['open']==stats['get']==stats['set']==0,stats
                check(f'malformed-adjtime-{i}',bad_adj)
            def valid_adj():
                for text in [' 0.0\t0 0.0 \r\n0 \r\nUTC\r\n\n','0 0 0\n0\nUTC']:
                    put(text); rc,out,stats,err=driver.case(['-s'],adj=adj)
                    expect(rc,0,out); assert stats['sys']==epoch((2024,2,29,12,34,56))
                rc,out,stats,err=driver.case(['-s'],adj=d/'missing')
                expect(rc,0,out); assert stats['sys']==epoch((2024,2,29,12,34,56))
                rc,out,stats,err=driver.case(['--show'],adj=d)
                expect(rc,1,out); assert stats['open']==0
            check('valid-whitespace-crlf-missing-and-unreadable-adjtime',valid_adj)
            def unreadable_adj():
                put('0 1 0\n1\nUTC\n'); adj.chmod(0)
                try:
                    rc,out,stats,err=driver.case(['-s'],adj=adj)
                    expect(rc,1,out); assert stats['open']==stats['set']==0
                finally: adj.chmod(0o600)
            check('permission-denied-adjtime-before-device-access',unreadable_adj)

            def adjfile_symlink_and_create():
                t=epoch((2024,2,29,12,34,56)); put('0 1 0\n1\nUTC\n')
                owner=(adj.stat().st_uid,adj.stat().st_gid)
                link=d/'adjlink'; link.symlink_to('adjtime')
                try:
                    rc,out,stats,err=driver.case(['-w','-l'],adj=link,now=t,tz='America/New_York')
                    expect(rc,0,out); assert link.is_symlink()
                    assert adj.read_text()==f'0.000000 {t} 0.000000\n{t}\nLOCAL\n'
                    assert (adj.stat().st_uid,adj.stat().st_gid)==owner
                    assert sorted(p.name for p in d.iterdir())==['adjlink','adjtime']
                finally: link.unlink()
                new=d/'new-adjtime'
                try:
                    rc,out,stats,err=driver.case(['-w','-u'],adj=new,now=t)
                    expect(rc,0,out); assert new.read_text()==f'0.000000 {t} 0.000000\n{t}\nUTC\n'
                    assert new.stat().st_mode & 0o777 == 0o600
                finally:
                    if new.exists(): new.unlink()
                original=adj.read_text()
                rc,out,stats,err=driver.case(['-w','-u','--noadjfile'],adj=adj,now=t)
                expect(rc,0,out); assert adj.read_text()==original
            check('systohc-preserves-symlink-owner-creates-private-adjfile-noadj-bypasses-write',adjfile_symlink_and_create)

            def drift():
                vals=(2024,3,1,0,0,1); t=epoch(vals)
                for factor,rem,whole,remainder in [(2.5,.25,2,.75),(-2.5,-.25,-2,-.75),(.1,.2,0,.3)]:
                    original=f'{factor} {t-86400} {rem}\n123\nUTC\n'
                    put(original)
                    rc,out,stats,err=driver.case(['-s'],rtc=vals,adj=adj)
                    expect(rc,0,out); assert stats['sys']==t-whole
                    rc,out,stats,err=driver.case(['-a'],rtc=vals,adj=adj)
                    expect(rc,0,out)
                    if whole:
                        assert stats['rtc']==iso(fields(t-whole)),stats
                        assert adj.read_text()==f'{factor:.6f} {t-whole} {remainder:.6f}\n123\nUTC\n'
                    else:
                        assert stats['write']==0 and adj.read_text()==original
                put('0 0 0\n0\nUTC\n')
                rc,out,stats,err=driver.case(['-a'],adj=adj); expect(rc,1,out); assert stats['open']==0
                for action in ('-s','-a'):
                    put('1e300 1 0\n1\nUTC\n')
                    rc,out,stats,err=driver.case([action],adj=adj)
                    expect(rc,1,out); assert stats['write']==stats['set']==0
            check('positive-negative-small-zero-overflow-drift',drift)
            def adjustment_then_readback():
                vals=(2024,3,1,0,0,1); t=epoch(vals)
                put(f'2.5 {t-86400} 0.25\n123\nUTC\n')
                rc,out,stats,err=driver.case(['-a'],rtc=vals,adj=adj)
                expect(rc,0,out); updated=adj.read_text()
                # Feed the observed setter calendar back as the next RTC read.
                rc,out,stats,err=driver.case(['-a'],rtc=fields(t-2),adj=adj)
                expect(rc,0,out); assert stats['read']==1 and stats['write']==0 and adj.read_text()==updated
                rc,out,stats,err=driver.case(['-s'],rtc=fields(t-2),adj=adj)
                expect(rc,0,out); assert stats['sys']==t-2
            check('adjust-readback-does-not-apply-whole-correction-twice',adjustment_then_readback)

            def local_adjust():
                vals=(2024,3,10,3,0,1); t=epoch(vals,ZoneInfo('America/New_York'))
                put(f'2 {t-86400} 0\n123\nLOCAL\n')
                rc,out,stats,err=driver.case(['-a'],rtc=vals,adj=adj,tz='America/New_York')
                expect(rc,0,out); assert stats['rtc']=='2024-03-10T01:59:59',stats
                assert adj.read_text()==f'2.000000 {t-2} 0.000000\n123\nLOCAL\n'
            check('adjust-local-across-dst-gap',local_adjust)
            def adjust_write_directory_denied():
                # The RTC write is intercepted; the real private directory
                # cannot accept the temporary adjfile. No privileged path used.
                if os.geteuid()==0:
                    raise AssertionError('directory permission fixture requires an unprivileged test user')
                t=epoch((2024,2,29,12,34,56)); original=f'2 {t-86400} 0\n1\nUTC\n'; put(original)
                d.chmod(0o500)
                try:
                    rc,out,stats,err=driver.case(['-a'],adj=adj)
                    expect(rc,1,out); assert stats['write']==1 and adj.read_text()==original
                finally: d.chmod(0o700)
                assert list(d.iterdir())==[adj]
            check('adjfile-temporary-create-denied',adjust_write_directory_denied)
            def out_of_range_system():
                for t in (-2208988801,253402300800,9223372036854775807):
                    rc,out,stats,err=driver.case(['-w','-u'],now=t)
                    expect(rc,1,out); assert stats['open']==stats['write']==0
            check('out-of-range-system-calendar-does-not-write-RTC',out_of_range_system)
            for failure,action,trace in [('open','-s','OPEN r\n'),('read','-s','OPEN r\nREAD\nCLOSE\n'),
                                        ('set','-s','OPEN r\nREAD\nCLOSE\nSET\n'),('get','-w','GET\n'),
                                        ('write','-w','GET\nOPEN w\nWRITE\nCLOSE\n'),
                                        ('close','-w','GET\nOPEN w\nWRITE\nCLOSE\n'),
                                        ('close','-s','OPEN r\nREAD\nCLOSE\n')]:
                def failure_case(failure=failure,action=action,trace=trace):
                    rc,out,stats,err=driver.case([action],fail=failure,trace=True)
                    expect(rc,1,out,trace); assert err
                check('injected-'+failure+'-'+action,failure_case)
            def missing():
                rc,out,stats,err=driver.case(['-r','--rtc',str(d/'missing-rtc')],trace=True)
                expect(rc,1,out,'OPEN r\n'); assert stats['read']==0
            check('missing-rtc',missing)
            for failure in ['write','read','open','fdopen','writefile','closefile','rename']:
                def adjust_fail(failure=failure):
                    t=epoch((2024,2,29,12,34,56)); original=f'2 {t-86400} 0.5\n123\nUTC\n'; put(original)
                    rc,out,stats,err=driver.case(['-a'],adj=adj,fail=failure)
                    expect(rc,1,out); assert adj.read_text()==original
                    assert list(d.iterdir())==[adj],list(d.iterdir())
                check('adjust-failure-preserves-file-'+failure,adjust_fail)
            for failure in ['write','get','fdopen','writefile','closefile','rename']:
                def systohc_fail(failure=failure):
                    original='0 1 0\n1\nUTC\n'; put(original)
                    rc,out,stats,err=driver.case(['-w'],adj=adj,fail=failure)
                    expect(rc,1,out); assert adj.read_text()==original
                    assert list(d.iterdir())==[adj]
                check('systohc-failure-preserves-file-'+failure,systohc_fail)
            def equals_options():
                put('0 0 0\n0\nUTC\n')
                rc,out,stats,err=driver.case(['--show','--rtc=/fixture/rtc','--adjfile='+str(adj)],noadj=False)
                expect(rc,0,out,'2024-02-29T12:34:56\n')
                rc,out,stats,err=driver.case(['--systohc','--utc','--adjfile='+str(adj)],now=1709210096)
                expect(rc,0,out); assert adj.read_text()=='0.000000 1709210096 0.000000\n1709210096\nUTC\n'
            check('equals-path-options-and-long-actions',equals_options)
            invalid_args=[['--rtc'],['-f'],['--rtc='],['--rtc',''],['--adjfile'],['--adjfile='],['--adjfile',''],
                          ['--utc','--localtime'],['-r','-s'],['-a','-w'],['--bogus'],['operand'],['-a','--noadjfile']]
            for a in invalid_args:
                def bad_args(a=a):
                    rc,out,stats,err=driver.case(a); expect(rc,2,out); assert stats['open']==stats['get']==0
                check('invalid-options-'+repr(a),bad_args)
            def repeated():
                commands=[('fixture','reset'),('fixture','rtc',2024,2,29,12,34,56),('fixture','quiet')]
                for _ in range(100):
                    commands += [('hwclock','-r','--noadjfile','-f','/fixture/rtc'),
                                 ('hwclock','-s','--noadjfile','-f','/fixture/rtc')]
                commands += [('fixture','stats')]
                statuses,out,err=driver.run(commands)
                assert all(s==0 for s in statuses),statuses
                assert out.count('2024-02-29T12:34:56\n')==100
                assert 'open=200 read=200 write=0 close=200 get=0 set=100 live=0 bad=0' in out,out
            check('100-repeated-native-empty-PATH',repeated)
            def mode_state():
                put('0 0 0\n0\nLOCAL\n')
                common=['--rtc','/fixture/rtc']
                commands=[('fixture','reset'),('fixture','rtc',2024,7,1,12,0,0),
                          ('hwclock','-s','-u','--noadjfile',*common),('fixture','stats'),
                          ('hwclock','-s','--adjfile',str(adj),*common),('fixture','stats'),
                          ('hwclock','-s','--noadjfile',*common),('fixture','stats')]
                statuses,out,err=driver.run(commands,tz='America/New_York')
                assert all(s==0 for s in statuses),statuses
                times=[int(v) for v in re.findall(r' sys=(-?\d+)',out)]
                expected=epoch((2024,7,1,12,0,0))
                assert times==[expected,expected+14400,expected],times
            check('repeated-calls-reset-option-and-mode-state',mode_state)
            if not args.host:
                def fd_cleanup():
                    t=epoch((2024,2,29,12,34,56)); put(f'2 {t-86400} 0\n1\nUTC\n')
                    extra=f'''hwclock_fixture reset
hwclock_fixture quiet
hwclock_fixture rtc 2024 2 29 12 34 56
hwclock_fixture fail writefile
before=(/proc/$$/fd/*)
for ((i=0;i<100;i++)); do
  hwclock -a --adjfile {shlex.quote(str(adj))} -f /fixture/rtc 2>/dev/null && exit 93
done
after=(/proc/$$/fd/*)
[[ ${{#before[@]}} == ${{#after[@]}} ]] || exit 94
hwclock_fixture stats
'''
                    _,out,err=driver.run([],extra=extra)
                    assert 'open=200 read=100 write=100 close=200' in out,out
                    assert list(d.iterdir())==[adj]
                check('100-failed-adjtime-writes-no-FD-or-temp-leak',fd_cleanup)
                def util_linux():
                    tool=next((p for p in ('/usr/sbin/hwclock','/sbin/hwclock','/usr/bin/hwclock') if Path(p).is_file()),None)
                    assert tool, 'util-linux hwclock unavailable'
                    version=subprocess.check_output([tool,'--version'],text=True).strip()
                    print('REFERENCE',version)
                    # --predict parses adjtime and a date without accessing an RTC.
                    # Zero drift makes its whole-second calendar independent of the host clock.
                    for mode in ('UTC','LOCAL'):
                        put(f'0 1700000000 0\n1700000000\n{mode}\n')
                        for vals in [(2000,2,29,0,0,0),(2024,2,29,12,34,56),(2038,1,19,3,14,8)]:
                            env=dict(os.environ,TZ='UTC0',LC_ALL='C')
                            p=subprocess.run([tool,'--predict','--date',iso(vals).replace('T',' '),'--adjfile',str(adj)],
                                             env=env,text=True,capture_output=True)
                            assert p.returncode==0,(p.returncode,p.stdout,p.stderr)
                            match=re.match(r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})',p.stdout)
                            assert match,p.stdout
                            rc,out,stats,err=driver.case(['-r'],rtc=vals,adj=adj)
                            expect(rc,0,out,match[1]+'T'+match[2]+'\n')
                            print('REFERENCE-CALENDAR', mode, p.stdout.strip())
                check('util-linux-safe-predict-calendar-and-adjtime',util_linux)
    report=dict(cases=results,passed=sum(r['status']=='pass' for r in results),failed=sum(r['status']=='fail' for r in results),
                binary=driver.binary,module=driver.module,host=driver.host)
    Path(args.report).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('passed','failed')}))
    return bool(report['failed'])
if __name__=='__main__': raise SystemExit(main())
