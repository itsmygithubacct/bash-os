#!/usr/bin/env python3
"""Build standalone production-source fixtures; invoke only through the build gate."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser()
p.add_argument('output', type=Path)
p.add_argument('--source', type=Path, default=Path('loadables/doas.c'))
p.add_argument('--sudoedit', type=Path, default=Path('loadables/_bashauth/sudoedit.c'))
p.add_argument('--auth-source', type=Path, default=Path('loadables/auth.c'))
p.add_argument('--sanitize', action='store_true')
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)
(a.output/'config.h').write_text('#define HAVE_UNISTD_H 1\n')
(a.output/'loadables.h').write_text('''#ifndef SOL_DOAS_LOADABLES_H
#define SOL_DOAS_LOADABLES_H
#include <stdarg.h>
typedef struct word_desc { char *word; int flags; } WORD_DESC;
typedef struct word_list { struct word_list *next; WORD_DESC *word; } WORD_LIST;
struct builtin { char *name; int (*function)(WORD_LIST *); int flags; char **doc; char *usage; void *handle; };
#define BUILTIN_ENABLED 1
#define EXECUTION_SUCCESS 0
#define EXECUTION_FAILURE 1
#define EX_USAGE 2
void builtin_error(const char *, ...);
void builtin_warning(const char *, ...);
void builtin_usage(void);
void *builtin_bind_variable(char *, char *, int);
#endif
''')
(a.output/'_mbedtls_sha256.h').write_text('#include "'+str(Path('loadables/_mbedtls/sha256.h').resolve())+'"\n')
for directory in ['_bashauth', '_bashos_authcrypto', '_monocypher']:
    for header in Path('loadables', directory).glob('*.h'):
        (a.output/(directory+'_'+header.name)).write_text('#include "'+str(header.resolve())+'"\n')
flags = ['-std=gnu11', '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', '-D_GNU_SOURCE', '-O2', '-g', '-Wall', '-Wextra', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter', '-I'+str(a.output.resolve()), '-Iloadables/common', '-Iloadables']
if a.sanitize:
    flags += ['-O1', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
command = ['cc', *flags, '-DAUTH_SOURCE="'+str(a.auth_source.resolve())+'"', '-DDOAS_SOURCE="'+str(a.source.resolve())+'"', '-DSUDOEDIT_SOURCE="'+str(a.sudoedit.resolve())+'"', 'tests/sol-doas-fixture.c', 'loadables/_mbedtls/sha256.c', '-o', str(a.output/'fixture')]
paths = [a.auth_source, a.source, a.sudoedit, Path('tests/sol-doas-fixture.c'), Path('loadables/common/bashcred_privdrop.h'), Path('loadables/_mbedtls/sha256.c'), Path('loadables/sudo.c')]
hashes = lambda: {str(f.resolve()): hashlib.sha256(f.read_bytes()).hexdigest() for f in paths}
inputs = hashes()
subprocess.run(command, check=True)
assert hashes() == inputs, 'fixture inputs changed during compilation'
(a.output/'build.json').write_text(json.dumps(dict(command=command, sources=inputs, binary_sha256=hashlib.sha256((a.output/'fixture').read_bytes()).hexdigest()), indent=2)+'\n')
