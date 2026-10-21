#!/usr/bin/env python3
"""Readiness must not block service output that the probe itself depends on."""
import importlib.util
from pathlib import Path
import sys
import tempfile
spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('sol-sv-check.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
with tempfile.TemporaryDirectory(prefix='sv-readiness-') as root:
    x=f.Fixture(sys.argv[1],root)
    try:
        payload=b'buffered-before-ready\n'*20000
        d=x.producer('writer',payload)
        run=d/'run';run.write_text(run.read_text().replace('# restart: never\n','# restart: never\n# readiness: ./check\n# readiness-timeout: 10\n').replace('\nexec ', '\n'))
        # Keep the service alive after writing its receipt.
        run.write_text(run.read_text()+'exec '+sys.executable+' -c "import time; time.sleep(20)"\n')
        check=d/'check'
        check.write_text('#!'+x.binary+'\n'+sys.executable+' -c \'import os,time,pathlib; p=pathlib.Path(os.environ["SV_TEST_ROOT"])/"writer.receipt"; exec("while not p.exists(): time.sleep(.01)")\'\n')
        check.chmod(0o700)
        x.up('writer')
        x.wait(lambda: x.text('writer','status').startswith(('ready pid=','readiness-failed')), 'readiness outcome',timeout=15)
        status=x.text('writer','status');print('status:',status,flush=True)
        assert status.startswith('ready pid='),status
        x.run('down','writer')
        x.wait(lambda: not x.text('writer','super-pid'),'stop')
        assert f.unframe((x.root/'logs/writer').read_bytes())==payload
        print('PASS readiness and service log backpressure, exact bytes, owned cleanup')
    finally:
        x.cleanup()
