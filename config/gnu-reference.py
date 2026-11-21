"""Record version-dependent command conventions for a native build."""
import os
from pathlib import Path
import subprocess
import tempfile


def probe(command, *args, data=b''):
    path = Path('/usr/bin') / command
    if not path.is_file():
        return None
    return subprocess.run([path, *args], input=data, capture_output=True,
                          env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}, check=False)


with tempfile.TemporaryDirectory() as directory:
    os.chdir(directory)
    Path('source').touch()
    Path('destination').touch()
    cp = probe('cp', '-n', 'source', 'destination')
    if cp and b'behavior of -n is non-portable' in cp.stderr:
        print('#define BASHOS_CP_WARN_NO_CLOBBER 1')
    uniq = probe('uniq', '-f', '-0')
    if uniq and uniq.returncode == 1 and b'invalid number of fields to skip' in uniq.stderr:
        print('#define BASHOS_UNIQ_REJECT_NEGATIVE_ZERO 1')
    base64 = probe('base64', '-d', data=b'YQ')
    if base64 and base64.returncode == 1 and base64.stdout == b'a':
        print('#define BASHOS_BASE64_REQUIRE_PADDING 1')
    iconv = probe('iconv', '-c', '-f', 'UTF-8', '-t', 'ASCII', data=b'a\xffb')
    if iconv and iconv.returncode == 0 and iconv.stdout == b'ab':
        print('#define BASHOS_ICONV_OMIT_SUCCEEDS 1')
    mv = probe('mv', '-n', 'source', 'destination')
    if mv and mv.returncode == 1 and b'not replacing' in mv.stderr:
        print('#define BASHOS_MV_DIAGNOSE_NO_CLOBBER 1')
