#!/usr/bin/env python3
"""Root-relative SDP control paths stay at the RTSP authority root."""
import importlib.util
from pathlib import Path
import struct
import sys
spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('sol-rtspcat-loopback.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
binary=str(Path(sys.argv[1]).resolve())
standalone='--standalone' in sys.argv[2:]
s=f.Server(f.good_stream(1)[0],auth='digest')
s.control=f'rtsp://127.0.0.1:{s.port}/trackID=1'
s.sdp=b'm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:/trackID=1\r\n'
p=f.invoke(binary,s,['-n','1'],standalone)
assert p.returncode==0 and p.stdout==f.unit(b'\x65'+struct.pack('!I',0)+b'fixture-payload'*8),(p.returncode,p.stderr)
print('PASS root-relative authenticated SDP control URL and exact frame')
