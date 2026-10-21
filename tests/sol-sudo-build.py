#!/usr/bin/env python3
"""Build the standalone sudo production-source fixture; invoke only through the build gate."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('output', type=Path)
p.add_argument('--source', type=Path, default=Path('loadables/doas.c'),
               help='doas.c to include (a historical copy builds the regression baseline)')
p.add_argument('--sudoedit', type=Path, default=Path('loadables/_bashauth/sudoedit.c'))
p.add_argument('--auth-source', type=Path, default=Path('loadables/auth.c'))
p.add_argument('--sanitize', action='store_true')
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)
(a.output/'config.h').write_text('#define HAVE_UNISTD_H 1\n')
(a.output/'loadables.h').write_text('''#ifndef SOL_SUDO_LOADABLES_H
#define SOL_SUDO_LOADABLES_H
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
flags = ['-std=gnu11', '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', '-D_GNU_SOURCE', '-O2', '-g', '-Wall', '-Wextra', '-Wno-unused-function',
         '-Wno-unused-parameter', '-Wno-format-truncation', '-I'+str(a.output.resolve()),
         '-Iloadables/common', '-Iloadables']
if a.sanitize:
    flags += ['-O1', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
fixture = Path('tests/sol-sudo-fixture.c')
command = ['cc', *flags, '-DAUTH_SOURCE="'+str(a.auth_source.resolve())+'"', '-DDOAS_SOURCE="'+str(a.source.resolve())+'"', '-DSUDOEDIT_SOURCE="'+str(a.sudoedit.resolve())+'"',
           str(fixture), 'loadables/_mbedtls/sha256.c', '-o', str(a.output/'fixture')]
paths = [Path('tests/astra-sudo-list-preload.c'), a.auth_source, a.source, a.sudoedit, fixture, Path('loadables/common/bashcred_privdrop.h'), Path('loadables/common/child-wait.h'),
         Path('loadables/common/_bashos_auth_uapi.h'), Path('loadables/_bashauth/sudoedit.h'),
         Path('loadables/_mbedtls/sha256.c'), Path('loadables/sudo.c')]
hashes = lambda: {str(f.resolve()): hashlib.sha256(f.read_bytes()).hexdigest() for f in paths}
inputs = hashes()
compiler = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
subprocess.run(command, check=True)
assert hashes() == inputs, 'fixture inputs changed during compilation'
preload_command = ['cc', '-std=gnu11', '-O2', '-U_FORTIFY_SOURCE', '-g', '-fPIC', '-shared',
                   'tests/astra-sudo-list-preload.c', 'loadables/_mbedtls/sha256.c',
                   '-ldl', '-o', str(a.output/'list-preload.so')]
subprocess.run(preload_command, check=True)
assert hashes() == inputs, 'fixture inputs changed during compilation'
(a.output/'build.json').write_text(json.dumps(dict(command=command, preload_command=preload_command,
    preload_sha256=hashlib.sha256((a.output/'list-preload.so').read_bytes()).hexdigest(), compiler=compiler, sources=inputs,
    binary_sha256=hashlib.sha256((a.output/'fixture').read_bytes()).hexdigest()), indent=2)+'\n')
