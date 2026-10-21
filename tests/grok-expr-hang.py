#!/usr/bin/env python3
"""expr must not hand glibc a set_regs loop, and must match GNU expr otherwise.

Usage: grok-expr-hang.py BASH-BINARY

Every probe is wrapped in timeout. ulimit -v is applied unless ASAN_OPTIONS
or UBSAN_OPTIONS is set, because a sanitizer reserves a huge address space.
A pattern GNU expr does not finish is an error from this builtin (exit 2).
A pattern GNU expr finishes must match its stdout, stderr, and status.
STRING : REGEX and match STRING REGEX are both covered, in C and C.UTF-8.
"""
from pathlib import Path
import os
import subprocess
import sys

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash").resolve())
if not os.access(binary, os.X_OK):
    sys.exit(f"not executable: {binary}")
if not os.access("/usr/bin/expr", os.X_OK):
    sys.exit("missing /usr/bin/expr")

# (subject, pattern). Subjects are raw byte strings. Patterns are the BRE
# text expr compiles with regcomp flags 0.
CASES = [
    # The two probes that hang the shell, plus the open-ended intervals.
    (b".b", br".\(\|^b\)\+"),
    (b".b", br".\(\|\`b\)\+"),
    (b".b", br".\(\|^b\)\{1,\}"),
    (b".b", br".\(\|^b\)\{2,\}"),
    (b".b", br".\(\|^b\)\{3,\}"),
    (b"ab", br".\(\|^b\)\+"),
    (b"a", br".\(\|^b\)\+"),
    (b"b", br".\(\|^b\)\+"),
    (b"\nb", br".\(\|^b\)\+"),
    (b"a\nb", br".\(\|^b\)\+"),
    (b".b ", br".\(\|^b\)\+"),
    # Nested group, anchor with no consumer, leading .*, star and bounds.
    (b".b", br".\(\(\|^b\)\)\+"),
    (b".b", br".\(\|^\)\+"),
    (b".b", br".*\(\|^b\)\+"),
    (b".b", br".\(\|^b\)*"),
    (b".b", br".\(\|^b\)\?"),
    (b".b", br".\(\|^b\)\{0,\}"),
    (b".b", br".\(\|^b\)\{1,2\}"),
    (b".b", br".\(\|^b\)\{2\}"),
    (b".b", br".\(\|^b\)\{0,2\}"),
    (b"\nb", br".\(\|\`b\)\+"),
    (b"b", br".\(\|\`b\)\+"),
    # Word anchors. Some subjects hang and some return, including a second
    # iteration that moves into a bad context (.b<space> under \<).
    (b".b", br".\(\|\<b\)\+"),
    (b"ab", br".\(\|\<b\)\+"),
    (b"b", br".\(\|\<b\)\+"),
    (b".b ", br".\(\|\<.\)\+"),
    (b"..", br".\(\|\<.\)\+"),
    (b"a ", br".\(\|\< \)\+"),
    (b". ", br".\(\|\< \)\+"),
    (b".b", br".\(\|\>b\)\+"),
    (b"ab", br".\(\|\>b\)\+"),
    (b"b", br".\(\|\>b\)\+"),
    (b"\nb", br".\(\|\>b\)\+"),
    (b"..", br".\(\|\>.\)\+"),
    (b"ab", br".\(\|\>.\)\+"),
    (b"  ", br".\(\|\> \)\+"),
    (b"a ", br".\(\|\> \)\+"),
    # $, \', \b, \B do not enter the loop. Back-references do not either.
    (b".b", br".\(\|$b\)\+"),
    (b".b", br".\(\|\'b\)\+"),
    (b".b", br".\(\|\bb\)\+"),
    (b".b", br".\(\|\Bb\)\+"),
    (b"bb", br"\(b\)\1"),
    (b".b", br".\(\|^b\)\+\1"),
    (b"b", br"\(b\)\(\|\1\)\+"),
    # No group, an ordinary group, and the non-hanging shapes from the survey.
    (b".b", b"."),
    (b"abc", b"ab"),
    (b"abcd", br"\(ab\)"),
    (b".b", br"\(.\|^\)\+"),
    (b".b", br"\(\|^b\)\+"),
    (b".b", br".\(\|\bb\)*"),
    (b"ab", br"a\(\|^b\)\+"),
    (b".x", br".\(x\|^b\)\+"),
    (b".b", br".\(b\|^\)\+"),
    # Wide characters. Word class differs between C and C.UTF-8.
    (b"\xc3\xa9 b", br".\(\|\< \)\+"),
    (b"a\xc3\xa9b", br".\(\|\<.\)\+"),
    (b"a\xc3\xa9b", br".\(\|\>.\)\+"),
    (b"\xc3\xa9b", br".\(\|^b\)\+"),
]

# Arithmetic and string forms that must keep agreeing with GNU expr.
PLAIN = [
    ["6", "*", "7", "+", "1"],
    ["length", "abcdef"],
    ["substr", "abcdef", "2", "3"],
    ["match", "abcdef", "abc"],
]


def invoke(argv, loc):
    limit = "ASAN_OPTIONS" not in os.environ and "UBSAN_OPTIONS" not in os.environ
    prefix = "ulimit -v 1048576; " if limit else ""
    script = prefix + 'exec timeout -k 1 1 "$@"'
    env = dict(os.environ)
    env["LC_ALL"] = loc
    env["LANG"] = loc
    proc = subprocess.run(
        ["/bin/sh", "-c", script, "sh", *argv],
        capture_output=True,
        env=env,
    )
    return proc.returncode, proc.stdout[:200], proc.stderr[:400]


def gnu(args, loc):
    return invoke(["/usr/bin/expr", *args], loc)


def ours(args, loc):
    return invoke(
        [binary, "--noprofile", "--norc", "-c", 'PATH=; expr "$@"', "_", *args],
        loc,
    )


def show(data):
    return repr(data)


fails = 0
checked = 0
refused = 0
matched = 0


def check(label, args, loc):
    global fails, checked, refused, matched
    checked += 1
    gr, go, ge = gnu(args, loc)
    br, bo, be = ours(args, loc)
    if gr == 124:
        refused += 1
        if br == 2 and bo == b"" and b"does not finish" in be:
            print(f"PASS refuse {label}")
            return
        fails += 1
        print(f"FAIL refuse {label}: bash rc={br} out={show(bo)} err={show(be)}")
        return
    matched += 1
    if (br, bo, be) == (gr, go, ge):
        print(f"PASS match {label} rc={br}")
        return
    fails += 1
    print(
        f"FAIL match {label}: gnu rc={gr} out={show(go)} err={show(ge)} "
        f"bash rc={br} out={show(bo)} err={show(be)}"
    )


for loc in ("C", "C.UTF-8"):
    for subject, pattern in CASES:
        sub = subject.decode("latin1")
        pat = pattern.decode("latin1")
        for args, how in (
            ([sub, ":", pat], "colon"),
            (["match", sub, pat], "match"),
        ):
            bits = subject.decode("latin1").encode("unicode_escape").decode()
            check(f"{how} {loc} subj={bits} pat={pat}", args, loc)
    for args in PLAIN:
        check(f"plain {loc} {' '.join(args)}", args, loc)

print(f"checked={checked} matched={matched} refused={refused} fails={fails}")
sys.exit(1 if fails else 0)
