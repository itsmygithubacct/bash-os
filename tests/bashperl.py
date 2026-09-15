#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare embedded Perl with Perl itself and check the surrounding Bash process."""
import argparse
import json
import os
from pathlib import Path
import shlex
import select
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', nargs='?', type=Path, default=ROOT/'out/bash-perl')
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--module', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if args.reference:
        reference = args.reference.resolve()
    else:
        target = subprocess.check_output(['cc', '-dumpmachine'], text=True).strip()
        reference = ROOT/'out/perl'/target/'bin/perl'
    env = {k: v for k, v in os.environ.items()
           if k not in ('BASH_ENV', 'ENV', 'PERL5OPT', 'PERL5LIB', 'PERLLIB',
                        'PERL_UNICODE', 'PERLIO', 'PERL_DESTRUCT_LEVEL')}
    env.update(PATH='', LC_ALL='C', PERL_DL_NONLAZY='1')
    prefix = '' if not args.module else f'enable -f {shlex.quote(str(args.module.resolve()))} bashperl || exit\n'
    checks = 0
    with tempfile.TemporaryDirectory(prefix='bashperl-') as directory:
        root = Path(directory)

        def run(script, data=b'', extra=None, timeout=20):
            result = subprocess.run([str(binary), '--noprofile', '--norc', '-c',
                                     prefix+script, 'bashperl-test'], input=data,
                                    capture_output=True, cwd=root, env={**env, **(extra or {})},
                                    timeout=timeout)
            assert b'AddressSanitizer' not in result.stderr, result.stderr
            assert b'runtime error:' not in result.stderr, result.stderr
            return result

        def check(script, output=b'', status=0, **kwargs):
            nonlocal checks
            p = run(script, **kwargs)
            assert (p.returncode, p.stdout) == (status, output), (script, p, status, output)
            checks += 1

        def parity(arguments, data=b'', stderr=False):
            nonlocal checks
            expected = subprocess.run([str(reference), *arguments], input=data,
                                      capture_output=True, cwd=root, env=env, timeout=20)
            actual = run('bashperl '+shlex.join(arguments), data=data)
            assert (actual.returncode, actual.stdout) == (expected.returncode, expected.stdout), (
                arguments, actual, expected)
            if stderr:
                assert actual.stderr == expected.stderr, (arguments, actual.stderr, expected.stderr)
            checks += 1

        check('type -t bashperl', b'builtin\n')
        check('bashperl -e \'print "$$\\n"\' > pid; read -r p < pid; [[ $p == "$BASHPID" ]]')
        programs = [
            'print 6 * 7, "\\n"',
            'my @a = (1..5); print join(q{,}, map {$_ * $_} @a), "\\n"',
            'my %h=(b=>2,a=>1); print join(q{,}, map {"$_=$h{$_}"} sort keys %h)',
            'sub fac { my ($n)=@_; $n < 2 ? 1 : $n*fac($n-1) } print fac(8)',
            '$_="a12 b345"; s/(\\d+)/$1 * 2/ge; print',
            'my $s="abc\\0def"; print unpack("H*", $s)',
            'my $x=eval { die "caught\\n" }; print $@',
            'BEGIN { print "begin\\n" } END { print "end\\n" } print "run\\n"',
            'use strict; use warnings; print "modules\\n"',
            'use JSON::PP; print JSON::PP->new->canonical->encode({z=>[1,2],a=>"ok"})',
            'use List::Util qw(sum); print sum(1..100)',
            'use POSIX qw(floor); print floor(3.9)',
            'use MIME::Base64; print encode_base64("abc\\0def")',
            'use utf8; binmode STDOUT, ":encoding(UTF-8)"; print uc("café"), "\\n"',
            'use feature "state"; sub nextnum { state $n=0; ++$n } print nextnum(),nextnum()',
            'print join("|", @ARGV)',
        ]
        for program in programs:
            parity(['-e', program, '--', 'a b', "'quote", '$(false)', '*', '-x'])
        for arguments, data in [
            (['-e', 'print "first\\n"', '-e', 'print "second\\n"'], b''),
            (['-E', 'say join q{,}, 1..3'], b''),
            (['-ne', 'print uc'], b'a\nb\nlast'),
            (['-pe', 's/a/A/g'], b'aaa\nba\n'),
            (['-0ne', 'print uc'], b'a\0b\0tail'),
            (['-0777ne', 'print length'], b'a\nb\0c\n'),
            (['-F:', '-alne', 'print join q{|}, @F'], b'a:b:c\nd:e\n'),
            (['-lne', 'print uc'], b'a\nb\n'),
            (['-MList::Util=sum', '-e', 'print sum(1, 2, 3)'], b''),
            (['-c', '-e', 'print "never\\n"'], b''),
            (['-'], b'print "program on stdin\\n";\n'),
            ([], b'print "default stdin\\n";\n'),
        ]:
            parity(arguments, data)
        for program in ['exit 0', 'exit 7', 'exit 255', 'exit 256',
                        'die "failure\\n"', 'BEGIN { die "compile\\n" }',
                        'BEGIN { exit 9 }', 'END { $?=23 } exit 7',
                        'END { exit 19 } print "end exit\\n"',
                        'print "must not run\\n"; my $x = ;']:
            parity(['-e', program], stderr=True)
        parity(['--not-a-perl-option'])
        (root/'program.pl').write_text('print join(q{|}, @ARGV), "\\n";\n')
        parity(['program.pl', 'first', 'second word'])
        (root/'Fixture.pm').write_text('package Fixture; sub value { 42 } 1;\n')
        parity(['-I', str(root), '-MFixture', '-e', 'print Fixture::value()'])
        manifest = binary.with_name(binary.name+'.manifest.json')
        static = manifest.exists() and json.loads(manifest.read_text()).get('static', False)
        if not static:
            # A new shared XS extension must resolve the API exported by the
            # embedding executable/module, beyond the built-in core extensions.
            config = json.loads(subprocess.check_output(
                [str(reference), '-MConfig', '-MJSON::PP', '-e',
                 'print encode_json({map {$_=>$Config{$_}} qw(archlib ccflags)})'],
                env=env, text=True))
            auto = root/'auto/BashPerlProbe'
            auto.mkdir(parents=True)
            (root/'BashPerlProbe.pm').write_text(
                'package BashPerlProbe; require XSLoader; XSLoader::load(__PACKAGE__); 1;\n')
            source = root/'probe.c'
            source.write_text('''/* SPDX-License-Identifier: MIT */
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
XS(probe_answer) {
    dXSARGS;
    ST(0) = sv_2mortal(newSViv(42));
    XSRETURN(1);
}
XS(boot_BashPerlProbe) {
    dXSARGS;
    newXS("BashPerlProbe::answer", probe_answer, __FILE__);
    XSRETURN_YES;
}
''')
            subprocess.run([os.environ.get('CC', 'cc'), '-shared', '-fPIC', '-O2',
                            *shlex.split(config['ccflags']),
                            '-I'+str(Path(config['archlib'])/'CORE'), str(source),
                            '-o', str(auto/'BashPerlProbe.so')], check=True, capture_output=True)
            parity(['-I', str(root), '-MBashPerlProbe', '-e', 'print BashPerlProbe::answer()'])
        (root/'one').write_bytes(b'one\n1\n')
        (root/'two').write_bytes(b'two\n2\n')
        parity(['-ne', 'print "$ARGV:$_"', 'one', 'two'])
        check('bashperl -pe \'s/o/O/g\' < one > first; '
              'bashperl -pe \'s/t/T/g\' < two > second; '
              'while IFS= read -r line; do printf "%s\\n" "$line"; done < first; '
              'while IFS= read -r line; do printf "%s\\n" "$line"; done < second',
              b'One\n1\nTwo\n2\n')
        check('bashperl -e \'our $x=99\'; bashperl -e \'print defined $x ? "leaked" : "fresh"\'', b'fresh')
        check('bashperl -e \'die "expected\\n"\'; printf "status:%s\\n" "$?"; '
              'bashperl -e \'print "recovered\\n"\'', b'status:255\nrecovered\n')
        check('export BP_VALUE=before; BP_LOCAL=temporary bashperl -e '
              '\'print "$ENV{BP_VALUE}:$ENV{BP_LOCAL}\\n"; $ENV{BP_VALUE}="after"; '
              '$ENV{BP_NEW}="leak"; delete $ENV{PATH}\'; '
              'bashperl -e \'print "$ENV{BP_VALUE}:", exists $ENV{BP_NEW} ? "leak" : "clean", '
              '":", exists $ENV{BP_LOCAL} ? "leak" : "clean"\'', b'before:temporary\nbefore:clean:clean')
        check('before=$PWD; bashperl -e \'chdir "/" or die $!; umask 077; die "expected\\n"\'; '
              'bashperl -MCwd=getcwd -e \'print getcwd()\' > actual; '
              'read -r actual < actual; [[ $before == "$actual" ]]')
        check('umask 022; bashperl -e \'umask 077\'; umask', b'0022\n')
        check('readonly BP_READONLY=kept; export BP_READONLY; '
              'bashperl -e \'$ENV{BP_READONLY}="private"; print $ENV{BP_READONLY}, "\\n"\'; '
              'printf "%s\\n" "$BP_READONLY"', b'private\nkept\n')
        check('export BP_VALUE=kept; bashperl -e \'%ENV=(); print scalar keys %ENV\'; '
              'bashperl -e \'print ":$ENV{BP_VALUE}"\'', b'0:kept')
        # A long-running Perl program must reclaim replaced environment vectors
        # and values. ASan's quarantine deliberately retains freed allocations;
        # exercise the same mutations there without imposing an RSS limit.
        memory_limit = 0 if env.get('ASAN_OPTIONS') else 16384
        churn = '''sub rss {
            open my $f, "<", "/proc/self/status" or die $!;
            while (<$f>) { return $1 if /^VmRSS:\\s+(\\d+)/ }
            die "missing RSS";
        }
        $ENV{"BP_FILL$_"}="x" for 1..128;
        $ENV{BP_CHURN}="warm";
        my $before=rss();
        $ENV{BP_CHURN}="v$_" for 1..50000;
        die "environment retention" if $ARGV[0] && rss()-$before > $ARGV[0];
        print $ENV{BP_CHURN}, ":";
        delete $ENV{"BP_FILL$_"} for 1..128;
        %ENV=(); $ENV{BP_AFTER}="fresh";
        print scalar(keys %ENV), ":", $ENV{BP_AFTER};'''
        check('bashperl -e '+shlex.quote(churn)+' '+str(memory_limit)+
              '; [[ ! -v BP_CHURN && ! -v BP_AFTER ]]', b'v50000:1:fresh')
        check('bashperl -MPOSIX -e \'POSIX::setlocale(POSIX::LC_ALL(), "C")\'; '
              'printf "%d\\n" "\'é"', b'233\n', extra={'LC_ALL': 'C.UTF-8'})
        check('bashperl -e \'$0="changed" x 1000\'; printf "%s\\n" "$0"', b'bashperl-test\n')
        check('bashperl -e \'close STDOUT\'; printf "stdout survived\\n"', b'stdout survived\n')
        check('bashperl -e \'close STDIN; close STDERR\'; '
              'read -r line; printf "%s\\n" "$line"', b'stdin survived\n', data=b'stdin survived\n')
        check('bashperl -e \'exit 0\' 0<&- 1>&- 2>&-; printf "%s\\n" "$?"', b'0\n')
        check('trap \'printf "bash trap\\n"\' USR1; '
              'bashperl -e \'$SIG{USR1}="IGNORE"\'; kill -USR1 "$BASHPID"; '
              'printf "after\\n"', b'bash trap\nafter\n')
        check('trap "" INT; bashperl -e \'kill "INT", $$; print "ignored\\n"\'', b'ignored\n')
        check('exec 7> kept; bashperl -e \'print "hello\\n"\'; '
              'printf "still open\\n" >&7; exec 7>&-; read -r line < kept; printf "%s\\n" "$line"',
              b'hello\nstill open\n')
        check('(exit 17) & child=$!; bashperl -e \'print "perl\\n"\'; '
              'wait "$child"; printf "%s\\n" "$?"', b'perl\n17\n')
        child = ('my $p=fork; die $! unless defined $p; '
                 'if (!$p) { print "child\\n"; exit 3 } '
                 'waitpid($p,0); print "parent:", $? >> 8, "\\n"')
        check('bashperl -e '+shlex.quote(child)+'; printf "shell\\n"',
              b'child\nparent:3\nshell\n')
        parity(['-e', 'system $ARGV[0], "-e", "exit 4"; print $? >> 8', str(reference)])
        check('bashperl -i.bak -pe \'s/one/ONE/\' one; '
              'read -r line < one; printf "%s\\n" "$line"; '
              'read -r line < one.bak; printf "%s\\n" "$line"', b'ONE\none\n')
        with open('/dev/full', 'wb') as full:
            expected = subprocess.run([str(reference), '-e', 'print "data\\n"'], stdout=full,
                                      stderr=subprocess.PIPE, env=env)
        p = run('bashperl -e \'print "data\\n"\' > /dev/full')
        assert p.returncode == expected.returncode, (p, expected)
        checks += 1
        for program in ['$|=1; print "ready\\n"; 1 while 1',
                        'BEGIN { $|=1; print "ready\\n"; 1 while 1 }',
                        'END { $|=1; print "ready\\n"; 1 while 1 }']:
            script = ('trap \'printf "bash interrupt\\n"\' INT; bashperl -e '+shlex.quote(program)+
                      '; printf "status:%s\\n" "$?"; bashperl -e \'print "after\\n"\'')
            p = subprocess.Popen([str(binary), '--noprofile', '--norc', '-c', prefix+script],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root, env=env)
            try:
                assert select.select([p.stdout], [], [], 10)[0], 'Perl did not reach interrupt fixture'
                assert p.stdout.readline() == b'ready\n'
                p.send_signal(signal.SIGINT)
                stdout, stderr = p.communicate(timeout=10)
                assert (p.returncode, stdout) == (0, b'bash interrupt\nstatus:130\nafter\n'), (
                    p.returncode, stdout, stderr)
                checks += 1
            finally:
                if p.poll() is None:
                    p.kill()
                    p.communicate()
        # The first XS import may allocate process-lifetime loader descriptors.
        # Later fresh interpreters must neither retain globals nor leak FDs.
        check('bashperl -MList::Util=sum -e \'exit(sum(1,2) != 3)\'; '
              'before=(/proc/$BASHPID/fd/*); '
              'for ((i=0;i<150;i++)); do '
              'bashperl -MList::Util=sum -e \'our $x; die "state" if defined $x; $x=42; '
              'exit(sum(1..10) != 55)\' || exit; done; '
              'after=(/proc/$BASHPID/fd/*); [[ ${#before[@]} == ${#after[@]} ]]', timeout=60)
        if args.module:
            check('bashperl -e \'print "first\\n"\'; enable -d bashperl; '
                  f'enable -f {shlex.quote(str(args.module.resolve()))} bashperl; '
                  'bashperl -MList::Util=sum -e \'print sum(1,2), "\\n"\'', b'first\n3\n')
            check('bashperl -MHash::Util -MUnicode::Normalize -MList::Util -e \'exit 0\'; '
                  'enable -d bashperl; '
                  f'enable -f {shlex.quote(str(args.module.resolve()))} bashperl; '
                  'bashperl -MStorable -MList::Util=sum -MMIME::Base64=encode_base64 '
                  '-e \'print sum(1,2), encode_base64("ok")\'', b'3b2s=\n')
    print(f'bashperl: {checks} compatibility and shell-state checks passed')


if __name__ == '__main__':
    main()
