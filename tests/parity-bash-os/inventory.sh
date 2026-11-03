#!/bin/bash
# Run with the candidate shell, inside its disposable container/VM.
set -euo pipefail
[[ $(id -u) != 0 ]] || { printf 'inventory must run nonroot\n' >&2; exit 2; }
[[ $BASH_VERSION == 5.3.20* ]] || { printf "unexpected Bash version: %s\n" "$BASH_VERSION" >&2; exit 1; }
count=0
while IFS='|' read -r name synopsis; do
    [[ -n $name ]] || continue
    [[ $(type -t "$name") == builtin ]] || { printf 'missing builtin: %s\n' "$name" >&2; exit 1; }
    ((count+=1))
done < /usr/share/bash-os/loadables.list
# Disabling a builtin must not expose a GNU counterpart through the image PATH.
enable -n ls
if command -v ls >/dev/null; then
    printf 'external ls unexpectedly reachable through PATH\n' >&2
    exit 1
fi
enable ls
perl_json=$(bashperl -MJSON::PP -e 'print encode_json({version=>"$^V",answer=>6*7})')
uv_version=$(uv --version)
bashpython - "$count" "$perl_json" "$uv_version" <<'PY'
import hashlib,json,ssl,sqlite3,sys
from pathlib import Path
metadata=Path('/usr/share/bash-os')
build=json.loads((metadata/'build.json').read_text())
assert int(sys.argv[1]) == build['full_count']+build['optional_count']
assert hashlib.sha256(Path('/bin/bash-os').read_bytes()).hexdigest()==build['binary_sha256']
perl=json.loads(sys.argv[2]);assert perl['answer']==42
assert perl['version'].lstrip('v')==json.loads((metadata/'catalog/perl.json').read_text())['version']
assert sys.version.split()[0]==json.loads((metadata/'catalog/python.json').read_text())['version']
uv_pin=json.loads((metadata/'catalog/uv.json').read_text())['version']
assert sys.argv[3].split()[1]==uv_pin
assert sqlite3.connect(':memory:').execute('select 6*7').fetchone()==(42,)
assert ssl.create_default_context().cert_store_stats()['x509_ca']>0
print(json.dumps({'image_audit':'PASS','full_catalog':build['full_count'],
                  'optional_catalog':build['optional_count'],'binary_bytes':build['binary_bytes'],
                  'binary_sha256':build['binary_sha256'],'perl':perl['version'],
                  'python':sys.version.split()[0],'uv':sys.argv[3],
                  'qualification':'builtin/runtime availability; behavioral parity is separate'}))
PY
