#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the signal handoff between the Perl engine and its Bash wrapper."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
record = json.loads(subprocess.check_output(
    ['python3', str(ROOT/'config/build-perl.py'), '--flags'], text=True))
with tempfile.TemporaryDirectory(prefix='bashperl-engine-') as directory:
    source = Path(directory)/'engine-check.c'
    source.write_text('''/* SPDX-License-Identifier: MIT */
#include <signal.h>
#include <stdio.h>
#include "engine.h"
int main(void) {
    char name[]="bashperl", option[]="-e";
    char program[]="$SIG{USR1}=sub {}; END { print qq(end\\\\n) } exit 7";
    char *args[]={name,option,program,0};
    struct sigaction saved, saved_int;
    sigset_t before, after;
    if (sigaction(SIGUSR1,0,&saved) || sigaction(SIGINT,0,&saved_int) ||
        sigprocmask(SIG_SETMASK,0,&before))
        return 1;
    for (int i=0;i<3;i++) {
        int status=bos_perl_run(3,args);
        if (status!=7 || sigprocmask(SIG_SETMASK,0,&after) ||
            sigismember(&after,SIGUSR1)!=1 || sigismember(&after,SIGINT)!=1) {
            fputs("Perl freed its context with signals unblocked\\n",stderr);
            return 1;
        }
        /* A signal delivered in the handoff window must stay pending until
           the host restores its own action. IGNORE then discards this one. */
        if (raise(SIGUSR1) || sigpending(&after) || sigismember(&after,SIGUSR1)!=1)
            return 1;
        signal(SIGUSR1,SIG_IGN);
        if (sigaction(SIGUSR1,&saved,0) || sigaction(SIGINT,&saved_int,0) ||
            sigprocmask(SIG_SETMASK,&before,0))
            return 1;
    }
    return 0;
}
''')
    binary = Path(directory)/'engine-check'
    command = [os.environ.get('CC', 'cc'), '-O2', '-I'+str(ROOT/'loadables/_perl'),
               *shlex.split(record['flags']['cppflags']), str(source),
               str(ROOT/'loadables/_perl/engine.c'), str(ROOT/'loadables/_perl/environment.c'),
               '-o', str(binary), *shlex.split(record['flags']['libraries'])]
    subprocess.run(command, check=True, capture_output=True)
    result = subprocess.run([str(binary)], capture_output=True, timeout=20)
    assert (result.returncode, result.stdout, result.stderr) == (0, b'end\n'*3, b''), result
print('perl-engine: three interpreter teardowns keep signals blocked until host restoration')
