#!/usr/bin/env python3
"""Focused PCRE contract, independent PCRE2 capture oracle, and state checks.
No compilation. SOL_PCRE_LOAD_ENV can load an instrumented production module.
Use --baseline to report all failures against an unmodified binary.
"""
import ctypes as C
import ctypes.util
import os
from pathlib import Path
import shlex
import selectors
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
baseline = '--baseline' in sys.argv
setup = ('. '+shlex.quote(os.environ['SOL_PCRE_LOAD_ENV'])+'; ') if os.environ.get('SOL_PCRE_LOAD_ENV') else ''
env = {**os.environ, 'LC_ALL':'C.UTF-8', 'TZ':'UTC', 'PATH':''}
env.pop('LD_PRELOAD', None)  # sanitizer applies to the tested child, not Python
if os.environ.get('SOL_PCRE_ASAN_LIB'):
    env.update(LD_PRELOAD=os.environ['SOL_PCRE_ASAN_LIB'], ASAN_OPTIONS='detect_leaks=0:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
lib = C.CDLL(ctypes.util.find_library('pcre2-8'))
def fn(name, result, args):
    f = getattr(lib,name+'_8'); f.restype=result; f.argtypes=args; return f
ptr, size, u32 = C.c_void_p, C.c_size_t, C.c_uint32
compile_ = fn('pcre2_compile',ptr,[ptr,size,u32,C.POINTER(C.c_int),C.POINTER(size),ptr])
create = fn('pcre2_match_data_create_from_pattern',ptr,[ptr,ptr])
match = fn('pcre2_match',C.c_int,[ptr,ptr,size,size,u32,ptr,ptr])
ovector = fn('pcre2_get_ovector_pointer',C.POINTER(size),[ptr])
free_data = fn('pcre2_match_data_free',None,[ptr])
free_code = fn('pcre2_code_free',None,[ptr])
checks, failures = 0, []
original_directory = Path.cwd()
def run(script, expected=b'', rc=0, data=b'', extra=None):
    global checks
    checks += 1
    r = subprocess.run([binary,'-e','-c',setup+'PATH=; '+script],input=data,capture_output=True,
                       env={**env,**(extra or {})},timeout=20)
    good = (r.returncode == rc and r.stdout == expected and b'AddressSanitizer' not in r.stderr
            and b'runtime error:' not in r.stderr)
    if not good:
        problem = (script[:180],r.returncode,r.stdout[:160],r.stderr[:700],rc,expected[:160])
        if not baseline: raise AssertionError(problem)
        failures.append(problem)
    return r
q = shlex.quote
with tempfile.TemporaryDirectory() as tmp:
    os.chdir(tmp)
    # Retain the four PCRE assertions from helper-smoke without building unrelated consumers.
    run("pcre match '(?<=id:)([0-9]+)' 'id:123'; [[ ${BPCRE_MATCH[0]} == 123 && ${BPCRE_MATCH[1]} == 123 ]]")
    run("pcre subst '([0-9]+)' '<$1>' a12b34 -g",b'a<12>b<34>\n')
    run("pcre find-all '[0-9]+' a12b34",b'12\n34\n')
    # Independent PCRE2 API gives the expected sparse capture indices and bytes.
    for pat, subject in [(b'(a)'*32,b'a'*32), (b'(a)(b)',b'ab'), (b'(a)?(b)',b'b'), (b'(a)(b)?',b'a'),
                         (b'(?<word>\\p{L}+)', 'café'.encode()), (b'(a\x00)(b)?',b'a\x00'),
                         (b'()',b''), (b'(\\xff)',b'\xff')]:
        err, off = C.c_int(), size()
        # Hex CLI is a byte transport; default text mode is UTF|UCP.
        ishex = b'\0' in pat or b'\xff' in subject
        code = compile_(pat,len(pat),0 if ishex else 0x00080000|0x00020000,C.byref(err),C.byref(off),None)
        assert code, (pat,err.value,off.value)
        md = create(code,None); count = match(code,subject,len(subject),0,0,md,None)
        assert count > 0, (pat, subject, count)
        ov = ovector(md)
        expected = {i:subject[ov[2*i]:ov[2*i+1]] for i in range(count) if ov[2*i] != size(-1).value}
        args = [pat.hex(),subject.hex(),'-X'] if ishex else [pat.decode(),subject.decode()]
        script = 'BPCRE_MATCH=(stale stale stale stale); pcre match '+ ' '.join(map(q,args))+'; '
        script += '[[ ${#BPCRE_MATCH[@]} == '+str(len(expected))+' ]]; '
        for i,value in expected.items():
            text = value.hex() if ishex else value.decode()
            script += '[[ ${BPCRE_MATCH['+str(i)+']} == '+q(text)+' ]]; '
        run(script)
        free_data(md); free_code(code)
    run("pcre match 'a.b' $'a\\nb' -s; [[ ${BPCRE_MATCH[0]} == $'a\\nb' ]]")
    run("pcre match '^b$' $'a\\nb\\nc' -m; [[ ${BPCRE_MATCH[0]} == b ]]")
    run("pcre match 'a.*b' axbxxb -U; [[ ${BPCRE_MATCH[0]} == axb ]]")
    run("pcre match 'a # comment' a -x; [[ ${BPCRE_MATCH[0]} == a ]]")
    run(r"pcre match '([a-z]+)\1' abcabc; [[ ${BPCRE_MATCH[1]} == abc ]]")
    for sub in ('match','find-all','subst','sed','grep'):
        args = {'match':"'[' x",'find-all':"'[' x",'subst':"'[' y x",'sed':"'[' y",'grep':"'['"}[sub]
        run('pcre '+sub+' '+args,rc=1)
    run("pcre match a a; if pcre match z a; then exit 9; fi; [[ ${#BPCRE_MATCH[@]} == 0 ]]")
    run("pcre match a a; if pcre match '[' a; then exit 9; fi; [[ ${#BPCRE_MATCH[@]} == 0 ]]")
    run("readonly -a BPCRE_MATCH=(keep); pcre match a a",rc=1)
    run("readonly -a BPCRE_MATCH=(keep); if pcre match a a; then exit 9; fi; [[ ${BPCRE_MATCH[0]} == keep ]]")
    run("declare -n BPCRE_MATCH=target; target=keep; if pcre match a a; then exit 9; fi; [[ $target == keep ]]")
    run("declare -A BPCRE_MATCH=([old]=old); pcre match '(a)' a; [[ ${BPCRE_MATCH[1]} == a ]]")
    run("declare -n BPCRE_MATCH=target; target=keep; pcre match a a",rc=1)
    run("BPCRE_MATCH=(global); f() { local -a BPCRE_MATCH=(old); pcre match '(a)' a; [[ ${BPCRE_MATCH[1]} == a ]]; }; f; [[ ${BPCRE_MATCH[0]} == global ]]")
    run("BPCRE_MATCH=old; pcre match '(a)' a; [[ ${BPCRE_MATCH[1]} == a ]]")
    run("pcre match -- -a -a; [[ ${BPCRE_MATCH[0]} == -a ]]")
    for args in ('match a a --bogus', 'match a a -z', 'match a', 'subst a b',
                 'find-all a a -X', 'grep a -X', 'compile a', 'free 999999', 'match a a extra'):
        run('pcre '+args,rc=2)
    for args in ('match 0 00 -X','match zz 00 -X','subst 61 0 61 -X'):
        run('pcre '+args,rc=2)
    run("pcre subst '(?<n>[0-9]+)' '<${n}>' a12b34 -g",b'a<12>b<34>\n')
    run(r"pcre subst '(a)(b)' '\2\1' ab",b'ba\n')
    run(r"pcre subst '(?<n>a)' '\g<n>\g<n>' a",b'aa\n')
    run("pcre subst z y abc",b'abc\n')
    run("pcre subst 'a?' X a -g",b'XX\n')
    run("pcre subst 00 ff 610062 -X -g",b'61ff62\n')
    run("pcre subst '(a)' '$9' a",rc=1)
    # Expansion far beyond the initial guess; every byte checked.
    run('pcre subst a '+q('x'*5000)+' '+q('a'*200)+' -g',b'x'*1000000+b'\n')
    for pat,s,wanted in [('','é','\n\n'),('(?:|a)','a','\na\n\n'),
                         (r'.\K','ab','\n\n'),('a*','ba','\na\n\n'),
                         ('(*CRLF)(?:)','\r\n','\n\n')]:
        run('pcre find-all '+q(pat)+' '+q(s),wanted.encode())
    run("pcre find-all '(*UTF)' é -b",b'\n\n')
    run("pcre match '\\p{L}+' café; [[ ${BPCRE_MATCH[0]} == café ]]")
    run("pcre match . $'\\xff'",rc=1)
    run("pcre match . $'\\xff' -b; [[ ${BPCRE_MATCH[0]} == $'\\xff' ]]")
    # Cache keys must include flags, full binary length and NUL suffixes.
    run('''for ((j=0;j<80;j++)); do
      pcre match "(a)(?#$j)" a
      pcre match 6100 6100 -X
      if pcre match 610062 610063 -X; then exit 9; fi
      pcre match a A -i
      if pcre match a A; then exit 9; fi
    done''')
    Path('first').write_bytes(b'a\x00b\nlast a')
    Path('second').write_bytes(b'next a\n')
    Path('directory').mkdir()
    run('pcre grep a first',b'a\x00b\nlast a\n')
    run('pcre grep a missing second',b'second:next a\n',rc=1)
    run('pcre sed a X missing second',b'next X\n',rc=1)
    run('pcre sed a X directory second',b'next X\n',rc=1)
    run('pcre sed a X < first; pcre sed a X < second',b'X\x00b\nlXst Xnext X\n')
    run('pcre sed a '+q('x'*5000),b'x'*1000000+b'\n',data=b'a'*200+b'\n')
    run('pcre sed 00 ff -X',b'61ff62\n',data=b'610062\n')
    run('pcre sed 61 62 -X',rc=2,data=b'zz\n')
    run('pcre sed 61 62 -X',rc=2,data=b'61\x00zz\n')
    run('pcre grep a '+ ' '.join(['second']*17),rc=2)
    run('pcre sed a b '+ ' '.join(['second']*17),rc=2)
    run("pcre sed a X",b'X\x00b\n',data=b'a\x00b\n')
    # Error does not poison later builtin output in the same process.
    for command in ("pcre subst a b a", "pcre find-all a a", 'pcre sed a b < second','pcre grep a second'):
        run('if '+command+' >/dev/full; then exit 9; fi; printf recovered',b'recovered')
    # Limits change dynamically, with bounded default fallback for malformed values.
    evil = 'a'*100+'!'
    for command in ["pcre match '(*NO_START_OPT)(a+)+$' "+q(evil),
                    "pcre find-all '(?:x|(*NO_START_OPT)(a+)+$)' "+q('x'+evil),
                    "pcre subst '(*NO_START_OPT)(a+)+$' X "+q(evil),
                    "pcre sed '(*NO_START_OPT)(a+)+$' X",
                    "pcre grep '(*NO_START_OPT)(a+)+$'"]:
        # Directive must appear at pattern start.
        command = command.replace('(?:x|(*NO_START_OPT)(a+)+$)', '(*NO_START_OPT)(?:x|(a+)+$)')
        r = run(command,expected=b'x\n' if 'find-all' in command else b'',rc=1,data=(evil+'\n').encode(),extra={'BASHPCRE_MATCH_LIMIT':'100'})
        if not baseline: assert b'limit' in r.stderr, r.stderr
    for limits in ({'BASHPCRE_MATCH_LIMIT':'1'}, {'BASHPCRE_DEPTH_LIMIT':'1'}):
        run("pcre match '(*NO_START_OPT)(a)' a",rc=1,extra=limits)
    run("export BASHPCRE_MATCH_LIMIT=1; if pcre match '(a)' a; then exit 9; fi; export BASHPCRE_MATCH_LIMIT=1000000; pcre match '(a)' a")
    for value in ('4294967296','-1','12junk','0'):
        run("pcre match '(a)' a",extra={'BASHPCRE_MATCH_LIMIT':value})
    # Repeated file streams and cache eviction must not leak descriptors/state.
    run('''before=(/proc/$$/fd/*)
    for ((j=0;j<1000;j++)); do
      pcre sed a X < second >/dev/null
      pcre grep a < second >/dev/null
      pcre match "(a)(?#$j)" a
      pcre match 286129 61 -X
    done
    after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]]
    pcre sed a X < second''',b'next X\n')
    if setup:
        run('for ((j=0;j<40;j++)); do pcre match a a; enable -d pcre; '+setup+'pcre match 6100 6100 -X; done')
os.chdir(original_directory)
# A regex limit error must return even when its input producer stays open.
script = setup + "pcre sed '(*NO_START_OPT)(a+)+$' X"
process = subprocess.Popen([binary,'-c',script],env={**env,'BASHPCRE_MATCH_LIMIT':'100'},
                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
    process.stdin.write(b'a'*100+b'!\n'); process.stdin.flush()
    with selectors.DefaultSelector() as ready:
        ready.register(process.stderr,selectors.EVENT_READ)
        assert ready.select(timeout=5), 'no regex limit diagnostic'
    assert b'limit' in process.stderr.readline()
    try:
        assert process.wait(timeout=2) == 1
        checks += 1
    except subprocess.TimeoutExpired:
        if not baseline: raise AssertionError('sed waited for producer after regex failure')
        failures.append(('sed producer-open limit failure',))
finally:
    if process.poll() is None: process.kill(); process.wait()
    for stream in (process.stdin,process.stdout,process.stderr): stream.close()
# A bounded memory/FD correctness checkpoint, not a throughput measurement.
if not setup:
    script = r'''pcre match a a; printf 'ready\n'; read -r token
    for ((j=0;j<10000;j++)); do
      pcre match "(a)(?#$j)" a
      [[ ${BPCRE_MATCH[1]} == a ]]
      pcre match 286129280029 6100 -X
      [[ ${BPCRE_MATCH[2]} == 00 ]]
    done
    printf 'done\n'; read -r token'''
    process = subprocess.Popen([binary,'-e','-c','PATH=; '+script],env=env,
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def checkpoint(expected):
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout,selectors.EVENT_READ)
            assert ready.select(timeout=20), 'memory checkpoint did not arrive'
        assert process.stdout.readline() == expected
        values = Path(f'/proc/{process.pid}/status').read_text().splitlines()
        return int(next(x.split()[1] for x in values if x.startswith('VmRSS:')))
    try:
        before = checkpoint(b'ready\n')
        process.stdin.write(b'go\n'); process.stdin.flush()
        after = checkpoint(b'done\n')
        assert after - before < 8192, (before,after)
        process.stdin.write(b'go\n'); process.stdin.flush()
        assert process.wait(timeout=5) == 0, process.stderr.read()
        checks += 1
    finally:
        if process.poll() is None: process.kill(); process.wait()
        for stream in (process.stdin,process.stdout,process.stderr): stream.close()
print(f'sol-pcre-check: {checks} checks; {len(failures)} failures')
for failure in failures: print(repr(failure))
sys.exit(bool(failures))
