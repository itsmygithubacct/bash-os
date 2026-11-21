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
