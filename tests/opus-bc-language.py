#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""bc as a language: GNU bc differential programs and the builtin's contracts.

tests/bc-parity.py covers repeated input in one shell. This suite covers the
language: user functions and their local state, arrays, control flow,
quit/halt, comments, strings, obase rendering, line splitting, named-file
operands and -e/-f, the final-newline and exit-status contract, recursion
limits and the cleanup after errors, output failures and interrupts.

Every program in the differential corpora runs through the builtin and
through GNU bc 1.07.1 as a separate process; standard output must be
byte-identical. GNU always exits 0; the builtin exits 1 exactly when GNU
reports an error rather than only warnings (docs/bc.md), and writes a
diagnostic exactly when GNU does.
"""
from pathlib import Path
import os
import random
import signal
import subprocess
import sys
import tempfile
import time

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
external = '/usr/bin/bc'
environment = dict(os.environ, LC_ALL='C', TZ='UTC', PATH='', BC_LINE_LENGTH='0')
host_environment = dict(os.environ, LC_ALL='C', TZ='UTC', BC_LINE_LENGTH='0')
# bc-sanitize.sh can substitute an instrumented module for the builtin.
prefix = 'if [[ -n ${BC_MODULE:-} ]]; then enable -f "$BC_MODULE" bc; fi\nPATH=\n'
checks = 0

if not os.access(external, os.X_OK):
    sys.exit(f'missing comparison program: {external}')
version = subprocess.run([external, '--version'], capture_output=True).stdout.split(b'\n')[0]
if not version.startswith(b'bc 1.07'):
    sys.exit(f'comparison program is not GNU bc 1.07: {version!r}')


def bashos(script, *args, data=None, env=None, timeout=60):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script, '_',
                        *map(str, args)], input=data, capture_output=True,
                       env=env or environment, timeout=timeout)
    assert b'AddressSanitizer' not in p.stderr and b'LeakSanitizer' not in p.stderr, p.stderr
    assert b'runtime error:' not in p.stderr, p.stderr
    return p


def gnu(program, options=(), env=None, cwd=None):
    return subprocess.run([external, *options], input=program, capture_output=True,
                          env=env or host_environment, timeout=60, cwd=cwd)


def gnu_failed(stderr):
    """GNU bc prints warnings and errors alike to stderr and exits 0."""
    return any(b'warning' not in line.lower() for line in stderr.splitlines() if line)


def differential(program, options=(), line_length='0', label=None):
    global checks
    if isinstance(program, str):
        program = program.encode()
    env = dict(environment)
    host = dict(host_environment)
    if line_length is None:
        env.pop('BC_LINE_LENGTH', None)
        host.pop('BC_LINE_LENGTH', None)
    else:
        env['BC_LINE_LENGTH'] = host['BC_LINE_LENGTH'] = line_length
    ours = bashos('bc "$@"', *options, data=program, env=env)
    ref = gnu(program, options, env=host)
    want_rc = 1 if gnu_failed(ref.stderr) else 0
    assert (ours.stdout, ours.returncode, bool(ours.stderr)) == (
        ref.stdout, want_rc, bool(ref.stderr)), (
        label, program[:300], options, line_length, ours.stdout[:400], ref.stdout[:400],
        ours.returncode, want_rc, ours.stderr[:300], ref.stderr[:300])
    checks += 1


LANGUAGE = [
    '1;quit\n',
    'if (0==1) quit\n5\n',
    '1/0; 5\n6\n',
    '"multi\nline"\n7\n',
    'define f(x) { return x*2 }\nf(3)\n',
    'define f(x) {\nreturn (x*2)\n}\nf(3)\n',
    'define void g() { print "hi\\n" }\ng()\n',
    'define f(){print "x";return 1}\n0 && f()\n1 || f()\n',
    'if (0) print "a\\n" else print "b\\n"\n',
    '1+\n2+2\n',
    'x[3]=5; x[3]; x[2]\n',
    'a = 3 < 5\na\n',
    '-2^2\n2^-1\n',
    'ibase=2; A; 12; 1A\n',
    '.\n5\n.\n',
    '/* c\n omment */ 1 # x\n2\n',
    'x=5\nx==5\n!x\n',
    'for(i=0;;i++) { if (i>2) break; i }\n',
    'i=0; while (i<3) { i; i+=1 }\nwhile (i<6)\n i++\n',
    'for(i=0;i<5;i++) { if (i%2) continue; i }\n',
    'break\n1\n',
    'if (1) {\n 1\n} else {\n 2\n}\n',
    'if (1) { 1 }\nelse { 2 }\n3\n',
    'define f(x) { auto y; y = x*2; return y }\ny=7; f(3); y; x\n',
    'define g() { return z }\ndefine f(z) { return g() }\nf(5)\n',
    'define f(a[]) { a[0]=99; return a[1] }\nb[0]=1; b[1]=2; f(b[]); b[0]\n',
    'define f(*a[]) { a[0]=99; return a[1] }\nb[0]=1; b[1]=2; f(b[]); b[0]\n',
    'define f(x,y) { return x+y }\nf(1)\nf(1,2,3)\n7\n',
    'h(1)\ndefine h(x) { return x }\nh(4)\n',
    'define f(x) { return 1 }\ndefine f(x) { return 2 }\nf(0)\n',
    'halt\n5\n',
    '1; halt; 2\n3\n',
    'print 1, "a", 2+3, "\\n"\n',
    'last=7\nlast\n',
    'x = "s"\n',
    'sqrt(-1)\n5\n',
    '2^1.5\n',
    'scale=3; length(0); length(0.001); length(100); scale(0.10); length(-12.3)\n',
    'define f() { return }\nf()\ndefine g() { 5 }\ng()\n',
    'define f(x) {\n auto a, b[]\n a = x; b[0]=1\n return (a+b[0])\n}\nf(4)\n',
    'define f()\n{\nreturn 3\n}\nf()\n',
    '{ 1; 2 }\n{ 3\n4 }\n',
    'x=3; x^=2; x; x%=4; x; x/=2; x; x*=5; x; x-=1; x\n',
    'a=0; a++ + a++\na\n',
    '1 == 1 == 1\n2 > 1 > 0\n!0 + 1\n!(0) && 1\n',
    'define f(x) { auto y; y=5; return x/0 }\ny=1; x=2; f(3)\nx; y\n',
    'define f(n) { if (n==0) return 1/0; return f(n-1) }\nf(5)\nn\n',
    'x[1]=3\ndefine f(x[]) { return x[1] }\nf(x[])\n',
    'z=4\nprint z, "\\n"\nlast\n',
    '++last\n',
    'scale=5; x=1.5; x++; x; scale=0; 3.75%1\n',
    'ibase=16; obase=A; FF; ibase=A; 10\n',
    'define f() {\n auto i\n for (i=0; i<3; i++) print i\n print "\\n"\n}\nf(); f()\n',
    'x=2^100; x/3; length(x); scale=3; sqrt(x)\n',
    '-0\n- 0.000\n0.000\nscale(0.000)\nlength(0.000)\n',
    '1 = 2\n',
    'print\n',
    '3 4\n',
    'obase=16; -1/3\nscale=4; -1/3\n',
    '++x[2]; x[2]++; x[2]\n',
    'a[1.9]=5; a[1]\n',
    'for(i=0;i<2;i++) {\n  i\n}\n',
    'while (0) 1; 2\n',
    'if(0)1;2\n',
    'print "a", "b"\n',
    'scale=0; 2^-1; scale=10; 3^-2; 2^-0\n',
    'x=5; -x; --x; -(-x)\n',
    '012\n00.50\n',
    'ibase=16; 1.8\nibase=16; .01\nibase=8; 0.4\nibase=3; .1\n',
    'i=0; while (i<5) { i+=1; if (i==2) continue; i }\n',
    '(scale=2.9)\n(ibase=40)\n(x=1.50)\n',
    'x=3\nx++\nx\n(x)++\n',
    'if (1)\n\n 5\n',
    'define f(a[],b) { return a[0]+b }\nx[0]=4; f(x[], 2)\n',
    'a[0]=1; a[0]+=2; a[0]; a[0]^=3; a[0]\n',
    'define f() { auto a[]; a[0]=7; return a[0] }\na[0]=1; f(); a[0]\n',
    '2^99999999999999999999\n',
    'obase=0\nobase=2147483648\n',
    'scale=3; 1/0.001; -7/2; -7%2\n',
    'obase=1000; 2^40; obase=17; 16.5\n',
    'obase=8; scale=10; 1/3\n',
    '1 + x = 2\nx\na=1; b=0; a < b = 3\nb\n2 * y = 3 + 1\ny\n',
    '7 % 0\n',
    '1; limits\n',
    'ibase=40\nibase\nibase=1\nibase\n',
    'define void f() { return (5) }\nf()\n',
    'define f(x,x) { return x }\nf(1,2)\n',
    'define f(x) { auto x; return x }\nf(7)\n',
    'define f() { auto x,x; return x }\nf()\n',
    'define f(a[]) { auto a[]; return a[0] }\nx[0]=3;f(x[])\n',
    'define f(*a[]) { auto a[]; return a[0] }\nx[0]=3;f(x[])\n',
    'define f() { auto a[],a[]; return 1 }\nf()\n',
    'define f(x) { auto x[]; x[0]=2; return x+x[0] }\nf(7)\n',
    'define f(x[]) { auto x; x=2; return x+x[0] }\na[0]=7;f(a[])\n',
    'define f() { return 9 }\ndefine f(x) { auto x; return x }\nf()\n',
    'define f(x) { 1; auto y; return 2 }\nf(1)\n9\n',
    'return 5\n1\n',
    'define f() { quit }\n1\n',
    '1 + \\\n2\n',
    'define f() { return 1 }; f()\n',
    'define f() { return (1) } f()\n',
    'for (i=0; i<2; i++) for (j=0;j<2;j++) { if (j==1) break; i*10+j }\n',
    'while (1) { while (1) break; break }; 5\n',
    'if (1) if (0) 1 else 2\n',
    'define f(x) { if (x) { return (x) } else { return (-1) } }\nf(0); f(2)\n',
    'length(1.000); scale(1.000); sqrt(16); scale=4; sqrt(15)\n',
]

MATHLIB = [
    'scale=8; s(1); c(0); a(1)\n',
    '4*a(1)\n',
    'e(1); l(2); j(2, 1.5)\n',
    'define s(x) { return x*2 }\ns(3)\n',
    'scale=50; e(10); l(1000); a(.2); a(-3); s(-100); c(2.5)\n',
    'ibase=16; e(1)\n',
    'obase=16; 4*a(1)\n',
    'define f(x) { return e(x) + 1 }\nf(0)\n',
    'scale=0; e(1); s(1)\n',
    'j(0,0); j(-3, 2); j(1.7, 3)\n',
]

WRAPPING = [
    '2^1000\n',
    'obase=16; 2^1000\n',
    'obase=1000; 7^200\n',
    'print "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"\n"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"\n2^300\n',
    'scale=200; 1/7\n',
    'for (i=0; i<40; i++) print i, " "\nprint "\\n"\n',
    'x = 2^500; x; -x; obase=2; 2^80\n',
]

# Nested and multiline parsing: blocks, definitions and comments spread over
# lines, continuation lines, and newlines where the grammar allows one.
NESTED = [
    'define f(n) {\n  auto i, s\n  s = 0\n  for (i = 1; i <= n; i++) {\n    if (i % 2) {\n      s += i\n    } else {\n      if (i % 3 == 0) { s -= i } else s += 2 * i\n    }\n  }\n  return (s)\n}\nf(10); f(0); f(37)\n',
    'define g(x)\n{\n  /* comment with\n     several lines */\n  if (x > 0)\n    return (x * g(x - 1))   # trailing comment\n  return (1)\n}\ng(20)\n',
    '{\n{\n{\n1\n}\n2\n}\n3\n}\n',
    'x = 1\nwhile (x < 1000)\n  x *= 3\nx\n',
    'for (i = 0; i < 3; i++)\n  for (j = 0; j < 3; j++)\n    if (i == j) print i, j, "\\n"\n',
    'i = 0\nwhile (1) {\n  i += 1\n  if (i > 5) break\n  if (i % 2) continue\n  print i, "\\n"\n}\ni\n',
    '12345\\\n67890\n1.2\\\n34\n"a\\\nb"\n',
    'a = 1 + \\\n  2 + \\\n  3\na\n',
    '/* one */ /* two */ 7 /* three */ # four\n8\n',
    '#!/usr/bin/bc\n# a script header is a comment\n2 + 2\n',
    'if (1) { "a" } else { "b" }; if (0) { "c" } else { "d" }\n"\\n"\n',
    'define f() {\n  "inside\n"\n  return (1)\n}\nf()\n',
    'define h(x) { if (x) { return (1) }\n return (2) }\nh(0); h(5)\n',
    'x = 0\nif (x == 0) if (x != 1) print "both\\n" else print "inner else\\n"\n',
    '{ x = 1; y = 2\n z = 3 }; x + y + z\n',
    'for (;;) { break }; "done\\n"\n',
    'define void p(n) {\n  auto i\n  for (i = 0; i < n; i++) print "*"\n  print "\\n"\n}\np(3); p(0); p(5)\n',
    'define f(a[], n) { auto i, s; for (i = 0; i < n; i++) s += a[i]; return (s) }\nfor (i = 0; i < 10; i++) v[i] = i * i\nf(v[], 10)\n',
    'define s(*a[], n) { auto i, j, t\n for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) if (a[j] < a[i]) { t = a[i]; a[i] = a[j]; a[j] = t } }\nq[0]=5; q[1]=-2; q[2]=9; q[3]=0.5\ns(q[], 4)\nq[0]; q[1]; q[2]; q[3]\n',
    'define void s(*a[], n) { auto i, j, t\n for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) if (a[j] < a[i]) { t = a[i]; a[i] = a[j]; a[j] = t } }\nq[0]=5; q[1]=-2; q[2]=9; q[3]=0.5\ns(q[], 4)\nq[0]; q[1]; q[2]; q[3]\n',
    'define even(n) { if (n == 0) return (1); return (odd(n - 1)) }\ndefine odd(n) { if (n == 0) return (0); return (even(n - 1)) }\neven(30); odd(30); even(7)\n',
    'define a(m, n) {\n  if (m == 0) return (n + 1)\n  if (n == 0) return (a(m - 1, 1))\n  return (a(m - 1, a(m, n - 1)))\n}\na(2, 3)\n',
    'define fact(n) { if (n <= 1) return (1); return (n * fact(n - 1)) }\nfact(100)\n',
    'define fib(n) { auto a, b, t, i; a = 0; b = 1; for (i = 0; i < n; i++) { t = a + b; a = b; b = t }; return (a) }\nfib(300)\n',
    'define f(x) { x = x * 2; return (x) }\nx = 5; f(x); x\n',
    'define f() { y = 9; return (y) }\ny = 1; f(); y\n',
    'define f(n) { auto v; v = n; if (n > 0) z = f(n - 1); return (v) }\nf(5); z\n',
    'define f(a[]) { a[0] = 1; return (a[0]) }\ndefine g(a[]) { return (f(a[]) + a[0]) }\nb[0] = 7; g(b[]); b[0]\n',
    'define f(*a[]) { a[5] = 42 }\nf(r[]); r[5]\n',
    'define f(x) { return (x + 1) }\ndefine g(x) { return (f(x) * 2) }\ndefine f(x) { return (x + 100) }\ng(1)\n',
    'define f(n) { return (n) }\nf(f(f(f(f(3)))))\n',
    'scale = 5\ndefine r(x) { auto scale; scale = 0; return (x / 3) }\nr(10); scale; 10 / 3\n',
    'define f() { ibase = 16; return (A) }\nf(); A; ibase\n',
    'define f() { auto i; for (i = 0; i < 3; i++) { if (i == 1) return (i * 10) }; return (-1) }\nf()\n',
    'x[0] = 1; x = 2; define x() { return (3) }\nx[0]; x; x()\n',
    'define f(x[], x) { return (x[0] + x) }\na[0] = 4; f(a[], 5)\n',
    'last = 3; . + 1; last * 2; .\n',
    'x = 5; x += x -= 3; x\n',
    'a[1] = 10; i = 1; a[i++] += 5; i; a[1]; a[2]\n',
    'scale = 3; x = 1; x /= 3; x; x++; x; ++x; x--; --x\n',
    'if (1 < 2 && 2 < 3 || 0) "yes\\n"\nif (!(1 && 0)) "no\\n"\n',
    'x = 0; (x = 5) && (x = 7); x; (x = 0) || (x = 9); x\n',
    '0.000 && 1\n(0.000 && 1) + 1\n2 && 0.0 + 1\n1 || 0\n0 || 0\n',
    'print "no newline"\n',
    'print 1, 2, 3; print "\\n"; print "a\\tb\\n"; print -1.5, "\\n"\n',
    'print "\\q\\\\\\a\\b\\f\\r\\z"\n',
    '"string\\twith\\nno escapes\n"\n',
    'quit\n1\n',
    '1\n2; quit; 3\n4\n',
    'define f() { 5; halt }\nf()\n6\n',
    'while (1) { 1; halt }\n2\n',
    'halt; 1\n',
    'limits\n',
    '1 == 1; 1 != 1; 2 < 1; 2 <= 2; 3 > 2; 3 >= 4\n',
    'x = 3 < 5; x\ny = (3 < 5); y\n',
    '-3 ^ 2; -(3 ^ 2); 2 ^ 3 ^ 2; (2 ^ 3) ^ 2\n',
    '!1 + 1; !0 * 5; !!7\n',
    '++a; a++; a; --a; a--; a\n',
    '++scale; scale; obase++; obase; ibase--; ibase\n',
    'x = .; y = last; x + y\n',
    'length(12345.6789); length(.000123); length(1000000); scale(12.000); scale(-1); length(-0.5)\n',
    'define void f() {}\n1; 1 + f()\n2\n',
    'define void f() {}\nx = f()\nf() + 1\nprint f()\nif (f()) 1\nf(); 3\n',
    'define void v(x) { print x, "\\n"; return }\nv(4); (v(5))\n',
    'sqrt(0); sqrt(1); sqrt(2); scale = 30; sqrt(2); sqrt(.25); sqrt(1000000); sqrt(10^40 + 1)\n',
    'scale = 0; sqrt(99); sqrt(100); sqrt(101); sqrt(0.99)\n',
]

# Base and scale boundaries.
BASES = [
    'ibase = 2; 1010; 1.1; ibase = 1010; 99\n',
    'ibase = 36; ZZ; Z.Z; ibase = A\nZZ\n',
    'ibase = 16; FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF; -1A.8; obase = A; 7F\n',
    'ibase = 8; 777; 0.7; 8; 18; ibase = 12\n10\n',
    'ibase = 0\nibase\nibase = 37\nibase\nibase = -5\nibase\n',
    'obase = 2; 0; 1; -1; 255; .5; .1; 1.25; -7.75\n',
    'obase = 3; 10; 1/3; scale = 5; 1/3; 2/3\n',
    'obase = 16; 2^64; 2^64 - 1; -(2^31); scale = 6; 1/7; 3.14159265\n',
    'obase = 17; 16; 17; 288; 1000; .5; scale = 3; 1/3\n',
    'obase = 36; 35; 36; 1295; 46655.999\n',
    'obase = 100; 99; 100; 101; 123456789; 0.01; 9.99\n',
    'obase = 1000; 999; 1000; 10^12; -10^12 + 1\n',
    'obase = 65536; 2^64; 65535.5\n',
    'obase = 2147483647; 2147483646; 2147483647; 2^62\n',
    'obase = 1; obase\nobase = 0\nobase = -2\nobase\nobase = 2147483648\nobase\n',
    'obase = 16; ibase = 16; A0 * 2; obase = 2; 1010\n',
    'scale = 0; 7 / 2; -7 / 2; 7 % 2; -7 % 2; 7 % -2\n',
    'scale = 1; 7 / 2; 7 % 2; 1 / 3 * 3; 10 % 3.3\n',
    'scale = 100; 1 / 3; 2 / 7; scale(1 / 3)\n',
    'scale = 400; 4 * (1 / 7)\n',
    'scale = -1\nscale\nscale = 2.7; scale\nscale = 10^20\nscale\n',
    'scale = 5; 0 / 1; 0 / 1 + 1; 0 * 1.000; 0.0 * 1.000 + 2; 1 - 1.00; (1 - 1.00) + 3\n',
    'scale = 3; x = 0.0001; x; x * 10; x + 1; x / 1\n',
    '0.000; -0.000; 0.000 + 1; 0 - 0.000; 1.000 - 1\n',
    'x = -0.001 ^ 3; x; x == 0; x < 0; -x; x + 0; sqrt(-x)\n',
    'scale = 2; (-0.1) ^ 3; ((-0.1) ^ 3) * 1; 0.0 ^ 3; 0.00 ^ 1; 0 ^ 0\n',
    '2 ^ 0; 2 ^ -0; 2.5 ^ 0; 0.5 ^ 3; scale = 4; 0.5 ^ -2; 3 ^ -3; (-2) ^ 5; (-2) ^ -3\n',
    '2 ^ 2.5; 4 ^ 0.5; 2 ^ 9223372036854775808\n',
    '10 ^ 100; -(10 ^ 100) + 1; 99999999999999999999 * 99999999999999999999\n',
    '123456789012345678901234567890 / 9876543210; 123456789012345678901234567890 % 9876543210\n',
    'scale = 20; 123456789012345678901234567890.123456789 / 0.000000001\n',
    'scale = 10; 1 / 0.0000000007; -5.5 % 2.25; 5.5 % -2.25\n',
    'a[16777215] = 1; a[16777215]; a[-1] = 2\nb[16777216]\nc[0.9] = 3; c[0]\n',
    'x = 2^200; obase = 16; x; obase = 8; x; obase = 2; x / 2^190\n',
]


def fuzz_programs(seed, count):
    """Random arithmetic over every operator, scale and obase: an independent
    GNU oracle for the number core and the output-base renderer."""
    rnd = random.Random(seed)

    def num():
        k = rnd.randrange(6)
        if k == 0: return str(rnd.randrange(10))
        if k == 1: return str(rnd.randrange(10 ** rnd.randrange(1, 40)))
        if k == 2: return '%d.%0*d' % (rnd.randrange(1000), rnd.randrange(1, 9), rnd.randrange(10 ** 8))
        if k == 3: return '.%d' % rnd.randrange(10 ** 7)
        if k == 4: return '0.%s' % ('0' * rnd.randrange(4))
        return rnd.choice(['x', 'y', 'a[1]', 'a[2]', '(x+1)', 'f(x)', 'last'])

    def expr(depth=0):
        if depth > 3 or rnd.random() < 0.3:
            return num()
        op = rnd.choice(['+', '-', '*', '/', '%', '^', '<', '==', '!=', '&&', '||'])
        left, right = expr(depth + 1), expr(depth + 1)
        if op == '^':
            right = str(rnd.randrange(-3, 7))
        e = '%s %s %s' % (left, op, right)
        if rnd.random() < 0.3: e = '-(%s)' % e
        if rnd.random() < 0.2: e = '(%s)' % e
        if rnd.random() < 0.1: e = '!(%s)' % e
        return e

    for _ in range(count):
        lines = ['define f(v) { auto t; t = v * 2 - 1; return (t / 3) }',
                 'scale=%d' % rnd.randrange(0, 30), 'x=%d.%d' % (rnd.randrange(100), rnd.randrange(1000)),
                 'y=-7.25', 'a[1]=2;a[2]=.5',
                 'obase=%d' % rnd.choice([10, 10, 10, 2, 3, 8, 16, 17, 36, 100, 1000, 7, 99999])]
        for _ in range(6):
            lines.append(rnd.choice(['', 'z=', 'print ']) + expr())
            if lines[-1].startswith('print '): lines[-1] += ', "\\n"'
        yield '\n'.join(lines) + '\n'


with tempfile.TemporaryDirectory(prefix='bash-os-bc-language-') as tmp:
    d = Path(tmp)

    # 1. Differential corpora.
    for program in LANGUAGE + NESTED + BASES:
        differential(program)
    for program in MATHLIB:
        differential(program, ('-l',))
    for program in ['scale=8; s(0); c(0); a(0); e(0); l(1)\n', 's(0) + 1; e(0) * 2; l(0); l(-1)\n',
                    'define e(x) { return (x) }\ne(5); s(0)\n', 'scale=5; j(0, 1); j(1, -2); j(-2, 3); j(3, 0)\n',
                    'obase=16; e(1); obase=7; a(1)\n', 'ibase=16; s(1); ibase=A; scale=3; c(3.14159)\n',
                    'define void f() { print e(1), "\\n" }\nf()\n']:
        differential(program, ('-l',))
    differential('s(1)\n')                 # the library exists only with -l
    for length in ('0', '10', '70', None, '2', '3', '25', 'abc', '-5'):
        for program in WRAPPING:
            differential(program, line_length=length)
    for seed in range(4):
        for program in fuzz_programs(seed, 60):
            differential(program, label=f'fuzz seed {seed}')

    # 2. State never survives an invocation: functions, arrays, obase, ibase,
    #    scale, last, -l, and the parameter stack after a failed call.
    p = bashos('''bc <<< 'define f(x) { return (x * 2) }; f(4); a[3] = 7; obase = 16; 255; x = 5; 9'
bc <<< 'f(4)'; echo "rc=$?"
bc <<< 'a[3]; obase; 255; last; x'
bc -l <<< 'scale; s(0)'
bc <<< 'scale; s(0)'; echo "rc=$?"
bc <<< 'define f(n) { auto v; v = n; return (1 / (n - 3) + f(n + 1)) }
v = 99; n = 42
f(0)
v; n; f(4 - 1)
v; n'; echo "rc=$?"
bc <<< 'v; n
define g() { return (v + n) }; g()'
''')
    assert p.stdout == (b'8\nFF\n9\nrc=1\n0\n10\n255\n255\n0\n20\n0\n0\nrc=1\n'
                        b'99\n42\n99\n42\nrc=1\n0\n0\n0\n'), (p.stdout, p.stderr)
    assert p.stderr.count(b'function f not defined') == 1, p.stderr
    assert p.stderr.count(b'divide by zero') == 2, p.stderr
    checks += 1
    # Twenty-five calls in one shell, each defining and recursing.
    p = bashos('for ((i = 0; i < 25; i++)); do bc <<< "define f(n) { if (n < 2) return (n); return (f(n-1) + f(n-2)) }; f(15); a[i++] = i; a[0]"; done')
    assert (p.returncode, p.stdout) == (0, b'610\n1\n' * 25), (p.returncode, p.stdout, p.stderr)
    checks += 1

    # 3. Recursion: deep enough for real programs, bounded before the shell's
    #    stack, and cleaned up after the error so the next item and call work.
    # Instrumented frames are several times larger, so the sanitized run
    # checks a shallower recursion; the ordinary build must manage 8000.
    sanitized = 'ASAN_OPTIONS' in os.environ
    deep = 'define f(n) { if (n == 0) return (0); return (1 + f(n - 1)) }\nf(%d)\n'
    differential(deep % (200 if sanitized else 1000))
    if not sanitized:
        p = bashos('bc', data=(deep % 8000).encode())
        assert (p.returncode, p.stdout) == (0, b'8000\n'), (p.returncode, p.stdout, p.stderr[:200])
        checks += 1
    p = bashos('''bc <<< 'define f(n) { return (f(n + 1)) }
x = 7
f(0)
x'; echo "rc=$?"; bc <<< '2 + 2'
''')
    assert p.stdout == b'7\nrc=1\n4\n', (p.stdout, p.stderr)
    assert b'nested too deeply' in p.stderr, p.stderr
    checks += 1
    p = bashos('bc; echo "rc=$?"; bc <<< "3 * 3"', data=b'(' * 200000 + b'1' + b')' * 200000 + b'\n')
    assert p.stdout == b'rc=1\n9\n' and b'nested too deeply' in p.stderr, (p.stdout, p.stderr[:200])
    checks += 1
    p = bashos('bc; echo "rc=$?"', data=b'{' * 100000 + b'1' + b'}' * 100000 + b'\n')
    assert p.stdout == b'rc=1\n' and b'nested too deeply' in p.stderr, (p.stdout, p.stderr[:200])
    checks += 1

    # 4. Named-file operands: read in order, then standard input (GNU), with
    #    file names in diagnostics; quit or halt in a file ends everything.
    (d/'lib.bc').write_bytes(b'define sq(x) { return (x * x) }\nk = 3\n')
    (d/'main.bc').write_bytes(b'sq(k) + 1\n')
    (d/'stop.bc').write_bytes(b'"before\\n"\nquit\n"after\\n"\n')
    (d/'halt.bc').write_bytes(b'"before\\n"; halt; "after\\n"\n')
    (d/'bad.bc').write_bytes(b'1 +\n2 * 3\n')
    (d/'reader.bc').write_bytes(b'x = read(); y = read(); x * y\n')
    for files, data in [(['lib.bc', 'main.bc'], b'sq(5)\n'), (['lib.bc'], b'sq(k)\n'),
                        (['stop.bc'], b'1\n'), (['halt.bc'], b'1\n'), (['bad.bc'], b'4 + 4\n'),
                        (['lib.bc', 'bad.bc', 'main.bc'], b''), (['reader.bc'], b'6\n7\n')]:
        ours = bashos('cd "$1" && shift && bc "$@"', d, *files, data=data)
        ref = gnu(data, files, cwd=d)
        assert (ours.stdout, ours.returncode, bool(ours.stderr)) == (
            ref.stdout, 1 if gnu_failed(ref.stderr) else 0, bool(ref.stderr)), (
            files, ours.stdout, ref.stdout, ours.stderr, ref.stderr)
        checks += 1
    p = bashos('bc "$1" < /dev/null', d/'bad.bc')
    assert p.stdout == b'6\n' and p.returncode == 1, (p.stdout, p.stderr)
    assert str(d/'bad.bc').encode() + b' 2: syntax error' in p.stderr, p.stderr
    checks += 1
    # A missing -f file stops the run with status 1, before standard input.
    p = bashos('bc -f "$1" -f "$2"; echo "rc=$?"', d/'lib.bc', d/'missing.bc', data=b'k\n')
    assert p.stdout == b'rc=1\n' and b'missing.bc' in p.stderr, (p.stdout, p.stderr)
    checks += 1
    # -e and -f run in order; -e means standard input is not read, unless -f -.
    p = bashos('bc -e "k = 10" -f "$1" -e "sq(k)"; bc -f "$1" -e "k = 10" -e "sq(k)"; '
               'bc -f "$1" -e "sq(k)" -f -', d/'lib.bc', data=b'k * 2\n')
    assert (p.returncode, p.stdout) == (0, b'9\n100\n9\n6\n'), (p.returncode, p.stdout, p.stderr)
    checks += 1
    p = bashos('bc -l -e "scale=5" -e "4*a(1)"; bc -le"3+4"; bc --expression="2^10"; bc --file="$1" <<< "sq(2)"',
               d/'lib.bc')
    assert (p.returncode, p.stdout) == (0, b'3.14156\n7\n1024\n4\n'), (p.returncode, p.stdout, p.stderr)
    checks += 1
    # A bare operand that names no file keeps the expression form.
    p = bashos('cd "$1"; bc "sq(2)"; echo "rc=$?"; bc "1 +" 2; bc lib.bc main.bc < /dev/null', d)
    assert p.stdout == b'rc=1\n3\n10\n', (p.stdout, p.stderr)
    checks += 1
    # Descriptors opened for files are closed; repeated file calls work.
    p = bashos('a=(/proc/$$/fd/*); for i in 1 2 3; do bc "$1" "$2" < /dev/null; done; '
               'bc -f "$3" 2>/dev/null; b=(/proc/$$/fd/*); echo "fds ${#a[@]} ${#b[@]}"',
               d/'lib.bc', d/'main.bc', d/'missing.bc')
    lines = p.stdout.split(b'\n')
    assert lines[:3] == [b'10'] * 3 and lines[3].split()[1] == lines[3].split()[2], (p.stdout, p.stderr)
    checks += 1
    # A directory operand is an input error, not a hang or a crash.
    p = bashos('bc "$1" < /dev/null; echo "rc=$?"; bc <<< 1', d)
    assert p.stdout == b'rc=1\n1\n' and p.stderr, (p.stdout, p.stderr)
    checks += 1

    # 5. Final newline and exit status (docs/bc.md).  An unterminated final
    #    line is evaluated, where GNU reports a syntax error; a syntax or
    #    runtime error anywhere makes the status 1 although later lines still
    #    run; warnings, quit and halt leave it 0.
    for data, out, rc in [(b'7*6', b'42\n', 0), (b'x=2\nx*3', b'6\n', 0), (b'define f() { return (5) }\nf()', b'5\n', 0),
                          (b'1/0\n2\n', b'2\n', 1), (b'1 +\n2\n', b'2\n', 1), (b'f()\n3\n', b'3\n', 1),
                          (b'scale=-1\n2\n', b'2\n', 0), (b'2^1.5\n', b'2\n', 0), (b'ibase=99\n', b'', 0),
                          (b'1\nquit\n2\n', b'1\n', 0), (b'1\nhalt\n2\n', b'1\n', 0), (b'', b'', 0), (b'\n\n', b'', 0),
                          (b'/* unterminated', b'', 1), (b'"unterminated', b'', 1), (b'print "x\n', b'', 1)]:
        p = bashos('bc', data=data)
        assert (p.stdout, p.returncode) == (out, rc), (data, p.stdout, p.returncode, p.stderr)
        checks += 1
    reference = gnu(b'7*6')
    assert reference.stdout == b'' and b'syntax error' in reference.stderr, reference
    checks += 1

    # 6. Output failures are reported and stop the program, even an endless one.
    if os.path.exists('/dev/full'):
        p = bashos('bc <<< "1" > /dev/full; echo "rc=$?" >&2')
        assert b'rc=1' in p.stderr and b'write error' in p.stderr, p.stderr
        checks += 1
        start = time.monotonic()
        p = bashos('bc <<< "while (1) 123456789" > /dev/full; echo "rc=$?" >&2; bc <<< 5', timeout=30)
        assert b'rc=1' in p.stderr and p.stdout == b'5\n', (p.stdout, p.stderr)
        assert time.monotonic() - start < 20
        checks += 1

    # 7. An endless loop stops on SIGINT, and the shell does not keep running it.
    proc = subprocess.Popen([binary, '--noprofile', '--norc', '-c', prefix + 'bc <<< "while (1) { x += 1 }"; echo after'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                            start_new_session=True)
    time.sleep(0.5)
    os.killpg(proc.pid, signal.SIGINT)
    try:
        out, err = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise AssertionError('bc did not stop on SIGINT')
    assert b'after' not in out, (out, err)
    checks += 1

    # 8. Nothing accumulates in the shell across calls: every path that
    #    allocates (functions, arrays by value and reference, autos, errors
    #    inside recursion, syntax errors, read(), obase output, the library)
    #    runs 400 times and the shell's resident size must stay flat.  Under
    #    bc-sanitize.sh, where ASan's quarantine inflates the resident size,
    #    LeakSanitizer checks the same shell for unreachable blocks instead.
    churn_env = dict(environment, ASAN_OPTIONS=os.environ['ASAN_OPTIONS'].replace(
        'detect_leaks=0', 'detect_leaks=1')) if sanitized else None
    (d/'churn.bc').write_bytes(b"""define f(a[], n) { auto b[], i; for (i = 0; i < n; i++) b[i] = a[i] * 2; return (b[n-1]) }
define g(*a[], n) { auto t; t = a[0]; a[0] = n; if (n > 0) return (g(a[], n - 1) + t); return (1 / n) }
for (i = 0; i < 50; i++) v[i] = i ^ 3
f(v[], 50); g(v[], 20)
x = read(); y = read()
obase = 16; 2 ^ 300 + x; obase = 7; 1 / 3 + y
s(1); "str"; print "p\\n"
1 + ; define bad(x) { auto ; }
quit
""")
    p = bashos("""rss() { local k v rest; while read -r k v rest; do [[ $k == VmRSS: ]] && echo "$v"; done < /proc/$$/status; }
for ((i = 0; i < 40; i++)); do bc -l "$1" <<< $'3\\n@'; done > /dev/null 2>&1; a=$(rss)
for ((i = 0; i < 400; i++)); do bc -l "$1" <<< $'3\\n@'; done > /dev/null 2>&1; b=$(rss); echo "$a $b"
bc -l "$1" <<< $'3\\n4'""", d/'churn.bc', env=churn_env, timeout=600)
    lines = p.stdout.split(b'\n')
    before, after = map(int, lines[0].split())
    assert sanitized or after - before < 256, (before, after, p.stderr[-300:])
    assert lines[1] == b'235298' and lines[-3:] == [b'.561424135265014541343501', b'strp', b''], (
        p.stdout, p.stderr)
    assert p.returncode == 1 and b'func=g): divide by zero' in p.stderr, p.stderr
    checks += 1

    # 9. With an empty PATH the command is the builtin.
    p = bashos('type -t bc; bc <<< "2^64"')
    assert p.stdout == b'builtin\n18446744073709551616\n', p.stdout
    checks += 1

    # 10. Usage errors and informational options.
    p = bashos('bc -z; echo "rc=$?"; bc -e; echo "rc=$?"; bc -h; bc --version')
    assert p.stdout.startswith(b'rc=2\nrc=2\nusage: bc') and b'bash-os' in p.stdout, (p.stdout, p.stderr)
    checks += 1

print(f'bc-language: {checks} GNU differential and builtin contract checks passed')
