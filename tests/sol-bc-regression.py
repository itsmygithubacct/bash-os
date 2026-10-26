#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent language programs and persistent-shell bc regression checks."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C', BC_LINE_LENGTH='0')
env.pop('BC_ENV_ARGS', None)
prefix = 'if [[ -n ${BC_MODULE:-} ]]; then enable -f "$BC_MODULE" bc; fi\nPATH=\n'
checks = 0


def run(script='bc', data=b'', args=(), cwd=None):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script,
                        '_', *map(str, args)], input=data, capture_output=True,
                       env=env, cwd=cwd, timeout=60)
    assert not any(s in p.stderr for s in
                   (b'AddressSanitizer', b'LeakSanitizer', b'runtime error:')), p.stderr
    return p


def differential(program, options=()):
    global checks
    data = program.encode() if isinstance(program, str) else program
    ref = subprocess.run(['/usr/bin/bc', *options], input=data,
                         capture_output=True, env=env, timeout=60)
    assert ref.returncode == 0, ref
    p = run('bc "$@"', data, options)
    assert (p.stdout, p.returncode, bool(p.stderr)) == (
        ref.stdout, ref.returncode, bool(ref.stderr)), (
        data[:500], p.returncode, p.stdout[:500], p.stderr[:500],
        ref.stdout[:500], ref.stderr[:500])
    checks += 1


# Constants use the base at entry to each function, after argument evaluation.
# The global ibase still changes immediately and governs nested calls.
for program in [
    'define f(){ibase=2;return 10}\nf();10\nf();ibase=A;f()\n',
    'define g(){return 10}\ndefine f(){ibase=2;return 10+g()}\nf();10\n',
    'define f(n){if(n>0){ibase=2;return f(n-1)+10};return 10}\nf(1);10\n',
    'define f(x){return 10}\nf(ibase=2);10\n',
    'define f(){ibase=2;return 10/0}\nf()\n10\nibase=A\n10\n',
    'define f(){ibase=2;10;ibase=A;10}\nf();f()\n',
    'define f(){auto x; x=10;ibase=2;while(x>8){x--;10};return x}\nf()\n',
]:
    differential(program)

# Independent algorithms exercise nested/multiline parse, arrays, local state,
# pass-by-reference, recursion, break and continue together.
for program in [
    """define gcd(a,b) {
auto r
while (b) {
r=a%b
a=b
b=r
}
return a
}
for(i=1;i<15;i++) { gcd(i*91, i*143) }
a;b;r
""",
    """define part(*v[],lo,hi) {
auto p,i,j,t
p=v[hi];i=lo
for(j=lo;j<hi;j++) {
if(v[j]>=p) continue
t=v[i];v[i]=v[j];v[j]=t;i++
}
t=v[i];v[i]=v[hi];v[hi]=t
return i
}
define void sort(*v[],lo,hi) {
auto p
if(lo>=hi) return
p=part(v[],lo,hi)
sort(v[],lo,p-1)
sort(v[],p+1,hi)
}
for(i=0;i<32;i++) v[i]=(i*17)%31
sort(v[],0,31)
for(i=0;;i++){if(i==32)break;v[i]}
p;lo;hi
""",
    """define f(n) {
auto a[],i
for(i=0;i<n;i++) a[i]=i^2
if(n==0) return 0
return a[n-1]+f(n-1)
}
a[1]=99;i=77;n=88
f(15);a[1];i;n
""",
    'define f(n){auto x;x=n;if(n==0)return 1/0;return f(n-1)}\n'
    'x=9;n=8;f(24)\nx;n\n',
    'define f(*a[],b[]){a[0]+=7;b[0]+=9;return a[0]+b[0]}\n'
    'x[0]=3;f(x[],x[]);x[0]\n',
    'define f(){return 9}\ndefine f(x){auto x;return x}\nf()\n',
    'if(0){halt};"still running"\nif(1){halt}\n"unreachable"\n',
    'define f(){if(0)quit}\n"unreachable"\n',
    '/* block\n# inside block\n*/ "a\\nb"\n# line comment\nprint "c\\nd\\n"\n',
]:
    differential(program)

# Each constant's radix, fractional precision and obase digit grouping vary
# independently; decimal assignments are made before changing ibase.
for ibase in (2, 3, 7, 10, 16, 36):
    for obase in (2, 3, 10, 16, 17, 100, 2147483647):
        for scale in (0, 1, 8):
            differential(f'scale={scale};obase={obase};ibase={ibase}\n'
                         '10.01;ZZ;A;100/11;scale(10.010);length(100.01)\n')
for scale in (0, 1, 20, 55):
    differential(f'scale={scale}\nsqrt(2);2^256;1.000^0;0/3;2^-9\n')
    differential(f'scale={scale}\ns(1);c(1);a(1);e(1);l(2);j(2,1)\n', ('-l',))

# Token starts and ends straddle the private input block.
for width in (4094, 4095, 4096, 8191):
    for suffix in ('/* comment\n*/ 6*7\n', '\\\n6*7\n', '"text\ntext"\n'):
        differential(' ' * width + suffix)

with tempfile.TemporaryDirectory(prefix='sol-bc-') as tmp:
    d = Path(tmp)
    (d/'1+2').write_bytes(b'11\n')
    (d/'lib').write_text('define f(x){auto y;y=x*x;return y}\n')
    (d/'main').write_text('f(12)\n')
    p = run('bc -f "1+2" </dev/null; bc -e "1+2"; '
            'bc lib main <<< "f(5)"; bc -e "3*(4+5)"', cwd=d)
    assert (p.returncode, p.stdout, p.stderr) == (0, b'11\n3\n144\n25\n27\n', b''), p
    checks += 1
    p = run('bc -f missing </dev/null; echo "rc=$?"; bc -e 6', cwd=d)
    assert (p.returncode, p.stdout) == (0, b'rc=1\n6\n') and b'missing' in p.stderr, p
    checks += 1
    ref = subprocess.run(['/usr/bin/bc', str(d/'missing')], input=b'6\n',
                         capture_output=True, env=env)
    assert ref.returncode == 1 and ref.stdout == b'' and ref.stderr, ref
    checks += 1
    p = run('bc -e "read()" < "$1"; echo "rc=$?"; '
            'bc -e "define f(){return read()}\nf()" < "$1"; echo "rc=$?"; '
            'bc -e 42', args=(d,))
    assert (p.returncode, p.stdout) == (0, b'rc=1\nrc=1\n42\n'), p
    assert p.stderr.count(b'read():') == 2, p
    checks += 1

    # read() deliberately accepts expressions. Interning unexecuted calls
    # grows the function vector while an outer call is binding arguments.
    growth = '0&&(' + '+'.join(f'fresh{i}()' for i in range(80)) + ')\n'
    (d/'values').write_text(growth)
    for call in ('f(read(),2)', 'f(1,read())'):
        p = run('bc -e "$1" < "$2"; bc -e "scale;ibase;obase;last;x"',
                args=('define f(x,y){auto z;z=x+y;return z}\n' + call,
                      d/'values'))
        want = b'2\n' if call.startswith('f(read') else b'1\n'
        assert (p.returncode, p.stdout, p.stderr) == (
            0, want + b'0\n10\n10\n10\n0\n', b''), p
        checks += 1
    p = run('bc -l -e "s(read())" < "$1"', args=(d/'values',))
    assert (p.returncode, p.stdout, p.stderr) == (0, b'0\n', b''), p
    checks += 1
    p = run('bc -e "define f(){ibase=2;return read()+10}\nf()"', b'10\n')
    assert (p.returncode, p.stdout, p.stderr) == (0, b'12\n', b''), p
    checks += 1

    # More than eight parameters uses the heap argument binding path.
    params = ','.join(f'x{i}' for i in range(12))
    p = run('bc -e "$1" < "$2"', args=(
        f'define f({params}){{auto z;return x0+x11}}\n'
        'f(read(),1,2,3,4,5,6,7,8,9,10,11)', d/'values'))
    assert (p.returncode, p.stdout, p.stderr) == (0, b'11\n', b''), p
    checks += 1

    # Repeated explicit files, failed calls, recursion, mathlib and an empty
    # program share a shell without retaining arithmetic state or descriptors.
    (d/'error').write_text('define f(n){auto x;if(n)return f(n-1);return 1/0}\nf(20)\n')
    p = run('a=(/proc/$$/fd/*); for ((i=0;i<30;i++)); do '
            'bc -f "$1" </dev/null 2>/dev/null; [[ $? == 1 ]] || exit 9; '
            'bc -l -e "scale=3;1/8" || exit; bc </dev/null || exit; '
            'bc -e "scale;ibase;obase;x" || exit; done; '
            'b=(/proc/$$/fd/*); [[ ${#a[@]} == ${#b[@]} ]]', args=(d/'error',))
    assert (p.returncode, p.stdout, p.stderr) == (
        0, b'.125\n0\n10\n10\n0\n' * 30, b''), p
    checks += 1
    p = run('exec 0<&-; bc -e "" -f "$1"; [[ ! -e /proc/self/fd/0 ]]',
            args=(d/'main',))
    assert p.returncode == 0 and b'not defined' in p.stderr, p
    checks += 1

for data, out, rc in [(b'{1;2}', b'1\n2\n', 0),
                      (b'define f(){return 7}\nf()', b'7\n', 0),
                      (b'1+\n3\n', b'3\n', 1),
                      (b'1/0\n3\n', b'3\n', 1),
                      (b'/* unfinished', b'', 1)]:
    p = run('bc --strict-errors', data=data)
    assert (p.stdout, p.returncode) == (out, rc), p
    checks += 1
ref = subprocess.run(['/usr/bin/bc'], input=b'{1;2}', capture_output=True, env=env)
assert ref.stdout == b'' and b'syntax error' in ref.stderr and ref.returncode == 0
checks += 1
p = run('bc -e "for(i=0;i<10000;i++)i" >/dev/full; '
        'echo "rc=$?"; bc -e "6*7"')
assert p.stdout == b'rc=1\n42\n' and b'write error' in p.stderr, p
checks += 1
with open('/dev/full', 'wb') as full:
    ref = subprocess.run(['/usr/bin/bc'], input=b'42\n', stdout=full,
                         stderr=subprocess.PIPE, env=env)
assert ref.returncode == 1 and ref.stderr, ref
checks += 1

# Unary parsing and the borrowing/purity walk also obey the stack bound.
# A low shell stack makes this small fixture reach the bound reliably.
for program in (b'- ' * 40000 + b'1\n',
                b'x=1+(' + b'+'.join([b'1'] * 40000) + b')\n'):
    p = run('ulimit -c 0; ulimit -s 512; bc; echo "rc=$?"; bc -e 42', program)
    assert (p.returncode, p.stdout) == (0, b'rc=1\n42\n'), p
    assert b'nested too deeply' in p.stderr, p
    checks += 1
print(f'sol-bc: {checks} independent differential and lifetime checks passed')
