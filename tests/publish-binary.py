#!/usr/bin/env python3
"""Updating a running shell must preserve both the process and failed builds."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

publisher = Path(__file__).resolve().parents[1]/'config/publish-binary.py'
with tempfile.TemporaryDirectory(prefix='bashos-publish-test-') as tmp:
    destination = Path(tmp)/'program'
    shutil.copy2('/bin/sleep', destination)
    process = subprocess.Popen([str(destination), '30'])
    try:
        before = destination.stat().st_ino
        subprocess.run([sys.executable, str(publisher), '/bin/echo', str(destination)], check=True)
        assert destination.stat().st_ino != before and process.poll() is None
        assert subprocess.check_output([str(destination), 'updated']) == b'updated\n'
        content = destination.read_bytes()
        for strip_tool in ('/bin/false', str(Path(tmp)/'missing-strip')):
            result = subprocess.run([sys.executable, str(publisher), '/bin/sleep', str(destination), strip_tool],
                                    capture_output=True)
            assert result.returncode != 0 and destination.read_bytes() == content
        assert sorted(p.name for p in Path(tmp).iterdir()) == ['program']
    finally:
        process.terminate()
        process.wait(timeout=5)
print('publish-binary: running process, new executable, failed strip, and cleanup verified')
