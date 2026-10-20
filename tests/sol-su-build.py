#!/usr/bin/env python3
"""Build genuine su and authentication helpers with syscall-boundary fixtures.
Invoke only through the campaign build gate. No compilation in the check driver.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser()
p.add_argument('output', type=Path)
p.add_argument('--sanitize', action='store_true')
p.add_argument('--source', type=Path, default=Path('loadables/su.c'))
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)
(a.output/'config.h').write_text('#define HAVE_UNISTD_H 1\n')
(a.output/'loadables.h').write_text('''#ifndef SOL_SU_LOADABLES_H
#define SOL_SU_LOADABLES_H
typedef struct word_desc { char *word; int flags; } WORD_DESC;
typedef struct word_list { struct word_list *next; WORD_DESC *word; } WORD_LIST;
struct builtin { char *name; int (*function)(WORD_LIST *); int flags; char **doc; char *usage; void *handle; };
#define BUILTIN_ENABLED 1
#define EXECUTION_SUCCESS 0
#define EXECUTION_FAILURE 1
#define EX_USAGE 2
void builtin_error(const char *, ...);
void builtin_warning(const char *, ...);
#endif
''')
for directory in ['_bashauth', '_bashos_authcrypto', '_monocypher']:
    for header in Path('loadables', directory).glob('*.h'):
        (a.output/(directory+'_'+header.name)).write_text('#include "'+str(header.resolve())+'"\n')
sources = [Path('tests/sol-su-fixture.c'), a.source,
           *Path('loadables/_bashauth').glob('*.h'),
           *[Path('loadables/_bashauth', n+'.c') for n in ['secure_read','passwd_lookup','pwverify','cred_exec']],
           Path('loadables/_bashos_authcrypto/argon2id.c'), Path('loadables/_bashos_authcrypto/argon2id.h'),
           Path('loadables/_monocypher/monocypher.c'), *Path('loadables/_monocypher').glob('*.h'),
           Path('loadables/common/bashcred_privdrop.h'), Path('loadables/common/child-wait.h')]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
inputs = {str(f.resolve()):sha(f) for f in sources}
flags = ['-std=gnu11','-D_GNU_SOURCE','-O2','-g','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-variable',
         '-I'+str(a.output.resolve()),'-Iloadables/common','-Iloadables']
if a.sanitize:
    flags += ['-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie']
cmd = ['cc',*flags,'-DSU_SOURCE="'+str(a.source.resolve())+'"','tests/sol-su-fixture.c',
       'loadables/_bashos_authcrypto/argon2id.c','loadables/_monocypher/monocypher.c','-o',str(a.output/'fixture')]
subprocess.run(cmd, check=True)
assert inputs == {str(f.resolve()):sha(f) for f in sources}
(a.output/'build.json').write_text(json.dumps(dict(command=cmd,sources=inputs,binary_sha256=sha(a.output/'fixture')),indent=2)+'\n')
