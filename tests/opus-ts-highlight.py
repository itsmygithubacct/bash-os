#!/usr/bin/env python3
"""ts: capture precedence, spans, rendering, handles and incremental edits.

tests/opus-ts-highlight.py [BINARY]

Every command runs as a builtin under an empty PATH. Expected spans are
written out by hand from the fixtures' byte layout; a second oracle
recomputes precedence in Python from the raw `ts query` captures (a code
path separate from the highlight resolver) over generated fixtures.
With TS_LOAD_ENV/TS_ASAN_LIB set (tests/opus-ts-sanitize.sh) the ts, hl
and nano builtins come from an ASan/UBSan-instrumented shared object.
"""
import os
from pathlib import Path
import random
import re
import subprocess
import sys

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
checks = 0
SGR = re.compile(rb'\x1b\[[0-9;]*m')


def sh(script, *args, data=None, rc=0, stderr=None):
    """Run SCRIPT in the target shell with PATH empty; return stdout."""
    global checks
    env = {**os.environ, 'LC_ALL': 'C', 'PATH': '/nonexistent'}
    if os.environ.get('TS_LOAD_ENV'):
        env.update(BASH_ENV=os.environ['TS_LOAD_ENV'], LD_PRELOAD=os.environ['TS_ASAN_LIB'],
                   ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                   LSAN_OPTIONS='suppressions=' + os.environ.get('TS_LSAN_SUPP', '/dev/null'),
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    p = subprocess.run([binary, '--norc', '--noprofile', '-c', 'PATH=; ' + script, '_', *args],
                       input=data, capture_output=True, timeout=60, env=env)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr \
        and b'LeakSanitizer' not in p.stderr, (script, p.stderr[:4000])
    assert p.returncode == rc, (script, p.returncode, p.stdout[:400], p.stderr[:2000])
    if stderr is not None:
        assert re.search(stderr, p.stderr), (script, p.stderr[:2000])
    checks += 1
    return p.stdout


def spans(lang, data):
    out = sh('ts highlight -L "$1" -S', lang, data=data).decode()
    return [tuple(line.split(' ')) for line in out.splitlines()]


def render(lang, data):
    return sh('ts highlight -L "$1"', lang, data=data)


def esc(code, text):
    return b'\x1b[' + code.encode() + b'm' + text + b'\x1b[0m'


# Failed handle publication must preserve the old tree, source and generation.
for decl in ['readonly out=unchanged', 'declare -i out=0', 'declare -a out',
             'declare -A out', 'declare -l out', 'declare -u out',
             'readonly locked=unchanged; declare -n out=locked',
             "declare -n out='array[1]'", 'declare -n out=out']:
    out = sh(decl + "; ts parse-tree -L json -t T <<<'[1]'; old=$T; "
             "ts edit $T 1 2 2 -t out <<<'[2]'; echo rc=$?; "
             "echo $T $old; ts node-text $old; ts free $old").decode()
    assert out == 'rc=1\nT0g1 T0g1\n[1]\n', (decl, out)
    # Failed parse-tree bindings release their slots; failures cannot exhaust it.
    out = sh(decl + "; for i in {1..40}; do "
             "ts parse-tree -L json -t out <<<'[1]' && exit 90; done; "
             "ts parse-tree -L json -t T <<<'[3]' || exit 91; "
             "ts node-text $T; ts free $T").decode()
    assert out == '[3]\n', (decl, out)
assert sh("declare -n ref=T; ts parse-tree -L json -t ref <<<'[1]'; "
          "ts edit $T 1 2 2 -t ref <<<'[2]'; ts node-text $T; ts free $T") == b'[2]\n'

# ---- JSON object keys versus ordinary strings ------------------------------

src = b'{"k":"v\\n"}'
assert spans('json', src) == [
    ('1-4', '1;36', 'string.special.key'),
    ('5-7', '32', 'string'), ('7-9', '1;33', 'escape'), ('9-10', '32', 'string')]
# -A lists every capture before precedence: the key really is captured twice.
assert sh('ts highlight -L json -A', data=src).decode().splitlines() == [
    '1-4 1;36 string.special.key', '1-4 32 string', '5-10 32 string', '7-9 1;33 escape']
assert render('json', src) == (b'{' + esc('1;36', b'"k"') + b':' + esc('32', b'"v')
                               + esc('1;33', b'\\n') + esc('32', b'"') + b'}')

# Strings that are not keys stay ordinary, wherever they sit.
src = b'["k",{"k":"k"},"k"]'
assert spans('json', src) == [
    ('1-4', '32', 'string'), ('6-9', '1;36', 'string.special.key'),
    ('10-13', '32', 'string'), ('15-18', '32', 'string')]

# Nested objects: keys at every depth, values of every builtin type.
src = b'{"o":{"i":[true,null,1.5,{"d":false}]},"s":"x"}'
assert spans('json', src) == [
    ('1-4', '1;36', 'string.special.key'), ('6-9', '1;36', 'string.special.key'),
    ('11-15', '35', 'constant.builtin'), ('16-20', '35', 'constant.builtin'),
    ('21-24', '33', 'number'), ('26-29', '1;36', 'string.special.key'),
    ('30-35', '35', 'constant.builtin'), ('39-42', '1;36', 'string.special.key'),
    ('43-46', '32', 'string')]
# An escape inside a key is the narrower capture and wins inside it only.
assert spans('json', b'{"a\\tb":1}') == [
    ('1-3', '1;36', 'string.special.key'), ('3-5', '1;33', 'escape'),
    ('5-7', '1;36', 'string.special.key'), ('8-9', '33', 'number')]
# A number as an object key (error-tolerant tree): key capture wins too.
assert spans('json', b'{"":0}') == [('1-3', '1;36', 'string.special.key'), ('4-5', '33', 'number')]
# Uncaptured input renders unchanged with no escapes at all.
assert render('json', b'[ ]\n') == b'[ ]\n'
assert render('json', b'') == b'' and spans('json', b'') == []

# ---- nested captures in other grammars -------------------------------------

src = b'f() { echo "a $x b" # c\n}\n'
assert spans('bash', src) == [
    ('0-1', '36', 'function'), ('6-10', '36', 'function'),
    ('11-14', '32', 'string'), ('14-16', '37', 'variable'), ('16-19', '32', 'string'),
    ('20-23', '90', 'comment')]
assert render('bash', src) == (esc('36', b'f') + b'() { ' + esc('36', b'echo') + b' '
                               + esc('32', b'"a ') + esc('37', b'$x') + esc('32', b' b"')
                               + b' ' + esc('90', b'# c') + b'\n}\n')
assert spans('toml', b'[t]\nk = "v" # c\nd = 1979-05-27\n') == [
    ('1-2', '1;36', 'property'), ('4-5', '1;36', 'property'), ('8-11', '32', 'string'),
    ('12-15', '90', 'comment'), ('16-17', '1;36', 'property'),
    ('20-30', '1;35', 'string.special')]
assert spans('markdown_inline', b'**b** `c`') == [
    ('0-5', '1', 'emphasis.strong'), ('6-9', '32', 'string')]
# Adjacent captures with the same SGR but different classes stay two spans,
# and the renderer still switches only when the code changes.
assert spans('toml', b'a.b=1') == [('0-1', '1;36', 'property'), ('2-3', '1;36', 'property'),
                                   ('4-5', '33', 'number')]

# ---- Unicode: offsets are bytes, never characters --------------------------

src = '{"é":"日本","ü\\u00e9":[1]}'.encode()
assert spans('json', src) == [
    ('1-5', '1;36', 'string.special.key'), ('6-14', '32', 'string'),
    ('15-18', '1;36', 'string.special.key'), ('18-20', '1;33', 'escape'),
    ('20-25', '1;36', 'string.special.key'), ('27-28', '33', 'number')]
# (the vendored JSON grammar's escape_sequence token is the two bytes `\u`)
assert SGR.sub(b'', render('json', src)) == src
assert sh('ts query -L json -q "(pair key: (_) @k)"', data=src).decode().splitlines() == [
    'k 1:2-1:6 1-5 "é"', 'k 1:16-1:26 15-25 "ü\\u00e9"']

# ---- independent oracle over generated fixtures ----------------------------

JSON_SCM = ('(pair key: (_) @string.special.key) (string) @string (number) @number '
            '[(null) (true) (false)] @constant.builtin (escape_sequence) @escape (comment) @comment')
BASH_SCM = ('(comment) @comment (string) @string (raw_string) @string (ansi_c_string) @string '
            '(translated_string) @string (number) @number (variable_name) @variable '
            '(simple_expansion) @variable (command_name) @function '
            '(function_definition name: (word) @function)')
CODES = {'string.special.key': '1;36', 'string': '32', 'number': '33', 'constant.builtin': '35',
         'escape': '1;33', 'comment': '90', 'variable': '37', 'function': '36'}


def oracle(lang, scm, data):
    """Per-byte winner by the documented rule, from raw query captures.

    In these queries each capture name first appears in pattern order, so
    first-appearance order of the name stands in for the pattern index."""
    order = {n: i for i, n in enumerate(dict.fromkeys(re.findall(r'@([\w.]+)', scm)))}
    owner = [None] * len(data)
    caps = []
    for line in sh('ts query -L "$1" -q "$2"', lang, scm, data=data).decode('utf-8', 'replace').splitlines():
        name, _, rng = line.split(' ', 3)[:3]
        sb, eb = map(int, rng.split('-'))
        if sb < eb:
            caps.append((sb, eb, name))
    for sb, eb, name in sorted(caps, key=lambda c: (-(c[1] - c[0]), -order[c[2]], -c[0])):
        owner[sb:eb] = [name] * (eb - sb)
    out, b = [], 0
    while b < len(data):
        e = b + 1
        while e < len(data) and owner[e] == owner[b]:
            e += 1
        if owner[b]:
            out.append((f'{b}-{e}', CODES[owner[b]], owner[b]))
        b = e
    return out


rng = random.Random(20261019)
def gen_json(depth=0):
    r = rng.random()
    if depth > 3 or r < 0.3:
        return rng.choice(['1', '-2.5e3', 'true', 'null', 'false', '"s"', '"\\n\\"x"', '"é"'])
    if r < 0.6:
        return '[' + ','.join(gen_json(depth + 1) for _ in range(rng.randint(0, 4))) + ']'
    return '{' + ','.join(f'"k{rng.choice(["", "\\t", "é"])}{i}":{gen_json(depth + 1)}'
                          for i in range(rng.randint(0, 4))) + '}'


for _ in range(25):
    data = gen_json().encode()
    assert spans('json', data) == oracle('json', JSON_SCM, data), data
words = ['echo', '"a $x b"', "'raw'", '$y', '${z}', '"$(id)"', '42', '# c']
for _ in range(15):
    data = '\n'.join(' '.join(rng.choice(words) for _ in range(rng.randint(1, 5)))
                     for _ in range(rng.randint(1, 6))).encode() + b'\n'
    assert spans('bash', data) == oracle('bash', BASH_SCM, data), data
big = ('{' + ','.join(f'"key{i}":["v{i}",{i},true,{{"n{i}":"\\u{i:04x}"}}]' for i in range(400)) + '}').encode()
assert spans('json', big) == oracle('json', JSON_SCM, big)
assert sum(1 for s in spans('json', big) if s[2] == 'string.special.key') == 800

# ---- repeat renders, hl and the in-shell state ------------------------------

src = b'{"a":[1,"b"]}'
once = render('json', src)
tmp = Path(os.environ.get('TMPDIR', '/tmp')) / f'opus-ts-{os.getpid()}'
tmp.mkdir()
try:
    (tmp / 'a.json').write_bytes(src)
    (tmp / 'b.json').write_bytes(b'{"z":null}')
    out = sh('for i in 1 2 3 4 5; do ts highlight -L json < "$1"; ts highlight -L json < "$2"; done',
             str(tmp / 'a.json'), str(tmp / 'b.json'))
    assert out == (once + render('json', b'{"z":null}')) * 5
    assert sh('hl -L json "$1"; hl -L json -S < "$1"', str(tmp / 'a.json')) == \
        once + sh('ts highlight -L json -S', data=src)
    # No descriptor survives repeated highlights, handle work or failures.
    out = sh('a=(/proc/$$/fd/*); for i in {1..50}; do ts highlight -L json < "$1" >/dev/null; '
             'hl -L json "$1" >/dev/null; hl -L json /nonexistent 2>/dev/null; '
             'ts parse-tree -L json -t T < "$1"; ts highlight -t $T -S >/dev/null; ts free $T; done; '
             'b=(/proc/$$/fd/*); echo ${#a[@]} ${#b[@]}', str(tmp / 'a.json')).split()
    assert out[0] == out[1], out
finally:
    for f in tmp.iterdir():
        f.unlink()
    tmp.rmdir()

# ---- handles: generations, freed handles, malformed handles -----------------

out = sh('''
ts parse-tree -L json -t A <<<'{"é":"ü","b":[1,2]}'
echo $A; ts node-children $A; ts node-children $A:0 -n
ts node-type $A:0,3; ts node-text $A:0,1,0; echo; ts node-range $A:0,1,0
kids=$(ts node-children $A:0,3 -n); echo $kids
last=${kids##*$'\n'}; ts node-type $last; ts node-text $last; echo
ts free $A
ts node-type $A 2>&1; echo rc=$?
ts parse-tree -L toml -t B <<<'k=1'; echo $B
ts node-type $A:0 2>&1; echo rc=$?; ts free $A 2>&1; echo rc=$?
ts node-type $B:0,0; ts free $B
''').decode().splitlines()
out = [re.sub(r'^_: line \d+: ', '', line) for line in out]
assert out == ['T0g1', 'T0g1:0', 'T0g1:0,1', 'T0g1:0,3', 'pair', '"é"', '1 2 1 6 1 5',
               'T0g1:0,3,0 T0g1:0,3,2', 'array', '[1,2]',
               'ts: node-type: invalid node handle: T0g1', 'rc=2',
               'T0g2',  # same slot, next generation: the freed handle stays dead
               'ts: node-type: invalid node handle: T0g1:0', 'rc=2',
               'ts: free: invalid tree handle: T0g1', 'rc=2', 'bare_key'], out

# A path through named-only listing names the same node as the full listing.
out = sh('''ts parse-tree -L bash -t T <<<'if a; then b; fi'
for h in $(ts node-children $T:0 -n); do ts node-type $h; done
ts free $T''').decode().split()
assert out == ['command', 'command'], out

for bad in ['T0g01', 'T00g1', 'T0g+1', 'T-0g1', 'T 0g1', 'T0g1x', 'T0g4294967297', 'T32g1',
            'T0g0', 'T0g1:', 'T0g1:0,', 'T0g1:,0', 'T0g1:00', 'T0g1:9', 'X0g1', '']:
    r = sh('ts parse-tree -L json -t T <<<"{}"; ts node-type "$1"; echo rc=$?', bad).decode()
    if bad == 'T0g1:':
        assert r == 'document\nrc=0\n', r  # empty path is the root
    else:
        assert r == 'rc=2\n', (bad, r)

# Pool exhaustion is reported, and freeing makes room again with a new gen.
out = sh('''for i in {1..32}; do ts parse-tree -L json -t "t$i" <<<'[]' || exit 9; done
ts parse-tree -L json -t x <<<'[]' 2>&1; echo rc=$?
ts free $t5; ts parse-tree -L json -t x <<<'[]'; echo $t5 $x
ts node-type $t5 2>/dev/null; echo rc=$?''').decode().splitlines()
assert 'tree pool exhausted (32 slots)' in out[0] and out[1] == 'rc=1', out
assert out[2] == 'T4g1 T4g2' and out[3] == 'rc=2', out

# ---- incremental edits -------------------------------------------------------

def edit_case(lang, before, after):
    """Apply BEFORE→AFTER as one edit; incremental results must equal fresh ones."""
    p = 0
    while p < min(len(before), len(after)) and before[p] == after[p]:
        p += 1
    s = 0
    while s < min(len(before), len(after)) - p and before[-1 - s] == after[-1 - s]:
        s += 1
    old_end, new_end = len(before) - s, len(after) - s
    d = Path(os.environ.get('TMPDIR', '/tmp')) / f'opus-ts-e{os.getpid()}'
    d.mkdir()
    try:
        (d / 'b').write_bytes(before)
        (d / 'a').write_bytes(after)
        out = sh('ts parse-tree -L "$1" -t T < "$2"; old=$T; ts highlight -t $T -S; echo @@; '
                 'ts edit $T "$4" "$5" "$6" -t T < "$3" || exit; [[ $T != "$old" ]] || exit 7; '
                 'ts node-type $old 2>/dev/null && exit 8; ts node-sexp $T; echo @@; '
                 'ts highlight -t $T -S; echo @@; ts highlight -t $T; echo @@; ts free $T',
                 lang, str(d / "b"), str(d / "a"), str(p), str(old_end), str(new_end))
    finally:
        for f in d.iterdir():
            f.unlink()
        d.rmdir()
    pre, sexp, span_out, rendered, _ = out.split(b'@@\n')
    assert pre == sh('ts highlight -L "$1" -S', lang, data=before)
    assert sexp == sh('ts parse -L "$1"', lang, data=after), (before, after)
    assert span_out == sh('ts highlight -L "$1" -S', lang, data=after), (before, after)
    assert rendered == render(lang, after), (before, after)


edit_case('json', b'["k"]', b'{"k":1}')          # a string becomes a key
edit_case('json', b'{"k":1}', b'["k"]')          # and back
edit_case('json', b'{"a":"x"}', b'{"a":"x\\n","b":[true]}')
edit_case('json', '{"é":1}'.encode(), '{"日本é":1}'.encode())
edit_case('bash', b'echo "a b"\n', b'echo "a $x b"\n')
edit_case('json', big, big[:5000] + b'"inserted":"s\\t",' + big[5000:])
out = sh('''ts parse-tree -L json -t T <<<'{"a":1}'
ts edit $T 2 3 4 -t T <<<'{"bb":1}'; ts highlight -t $T -S
ts edit $T 1 5 5 -t T <<<'{"cc":1}'; ts highlight -t $T -S
ts edit $T 7 7 10 -t T <<<'{"cc":1234}'; ts highlight -t $T -S; echo $T''').decode().splitlines()
assert out == ['1-5 1;36 string.special.key', '6-7 33 number',
               '1-5 1;36 string.special.key', '6-7 33 number',
               '1-5 1;36 string.special.key', '6-10 33 number', 'T0g4'], out

# Ranges that do not describe the change are refused and leave the tree as it was.
for args, new in [('0 1 1', b'x'), ('1 2 2', b'{"b":1}\n'), ('1 1 1', b'{"a":1}\n '),
                  ('9 9 9', b'{"a":1}\n'), ('3 2 2', b'{"a":1}\n'), ('a 1 1', b'{"a":1}\n'),
                  ('-1 1 1', b'{"a":1}\n'), ('1 1', b'{"a":1}\n')]:
    out = sh('ts parse-tree -L json -t T <<<\'{"a":1}\'; old=$T; set -- $1; '
             'ts edit $T "$@" -t T; echo rc=$? $T $old; ts highlight -t $T -S',
             args, data=new).decode().splitlines()
    assert out[0] == 'rc=2 T0g1 T0g1', (args, out)
    assert out[1:] == ['1-4 1;36 string.special.key', '5-6 33 number'], (args, out)

# ---- invalid input and output failures --------------------------------------

sh('ts highlight', rc=2, stderr=rb'-L LANG or -t TREE required')
sh('ts highlight -L nope', rc=2, stderr=rb'unknown language: nope')
sh('ts highlight -L json -Z', rc=2, stderr=rb'unexpected arg: -Z')
sh('ts highlight -t T0g1', rc=2, stderr=rb'invalid tree handle')
sh('ts parse-tree -L json -t T <<<1; ts highlight -t $T:0', rc=2, stderr=rb'invalid tree handle')
sh('ts parse-tree -L json -t T <<<1; ts highlight -t $T -L bash', rc=2, stderr=rb'parsed as json, not bash')
sh('ts parse-tree -L json -t T <<<1; ts query -t $T -q "(number) @n"', rc=0)
assert sh('ts parse-tree -L json -t T <<<"[1,2]"; ts query -t $T -q "(number) @n"') == \
    b'n 1:2-1:3 1-2 1\nn 1:4-1:5 3-4 2\n'
sh('ts cursor-walk -L json -d x', rc=2, stderr=rb'invalid depth: x')
sh('ts parse-tree -L json -t 1x', rc=2, stderr=rb'not a valid identifier')
sh('ts edit', rc=2, stderr=rb'usage: ts edit')
sh('ts frob', rc=2, stderr=rb'unknown verb: frob')
sh('ts node-type T0g1 extra', rc=2, stderr=rb'unexpected arg: extra')
for script in ['ts highlight -L json', 'ts highlight -L json -S', 'ts highlight -L json -A',
               'ts parse -L json', 'ts query -L json -q "(number) @n"', 'ts cursor-walk -L json',
               'ts language-list', 'ts version', 'hl -L json',
               'ts parse-tree -L json -t T <<<"[1]"; ts node-text $T']:
    sh(script + ' <<<"$1" >/dev/full', '[1,"a"]', rc=1, stderr=rb'write error: No space left')
    # The failure is not sticky: the next call in the same shell writes normally.
    assert sh(script + ' <<<"$1" >/dev/full; ' + script + ' <<<"$1"', '[1,"a"]') != b''
# nano's renderer uses the same resolver through bashts_compute_sgr_map;
# its plain selftest ends in a bn_render of shell text that reaches it.
assert b'not ok ' not in sh('nano selftest')
# Enable on the combined corrected nano build, including its LSan cleanup fix.
if os.environ.get('TS_REQUIRE_NANO_STATUSBAR') == '1':
    assert b'not ok ' not in sh('nano selftest-statusbar')

print(f'opus-ts-highlight: {checks} checks passed')
