#!/usr/bin/env python3
"""Negative controls for the independent frame boundary and pixel oracle."""
import base64
import importlib.util
import os
from pathlib import Path

path = Path(__file__).with_name('sol-gpu-frames.py')
spec = importlib.util.spec_from_file_location('frames',path)
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
wanted = f.solid(2,2,(17,24,39))


def stream(pixels, w=2, h=2):
    return (b'\x1b[?2026h\x1b_Ga=t,t=d,i=10,q=2,f=32,s='+str(w).encode()+
            b',v='+str(h).encode()+b',m=0;'+base64.b64encode(pixels)+
            b'\x1b\\\x1b_Ga=p,i=10,p=1,C=1,q=2,z=-1;\x1b\\\x1b[?2026l')


def check(data, valid):
    terminal = f.FrameTerminal([(2,2,wanted)])
    try:
        try:
            # Every protocol marker and base64 block crosses a receive boundary.
            for byte in data: terminal.receive(bytes([byte]))
            assert len(terminal.ends)==1 and not terminal.pending_frame
        except AssertionError:
            if valid: raise
        else:
            assert valid,'oracle accepted corrupt frame'
    finally:
        os.close(terminal.master);os.close(terminal.slave)


check(stream(wanted),True)
check(stream(bytes([wanted[0]^255])+wanted[1:]),False)
check(stream(wanted,1,4),False)
check(stream(wanted)+b'\x1b[?2026l',False)
check(stream(wanted)[:-1],False)
assert f.normalize_protocol(b'\x1b_Ga=t,t=s,i=42;L3NobS1h\x1b\\') == f.normalize_protocol(b'\x1b_Ga=t,t=s,i=123456;L3NobS1sb25n\x1b\\')
assert f.normalize_protocol(stream(wanted)) != f.normalize_protocol(stream(bytes([wanted[0]^255])+wanted[1:]))
print('sol-gpu-oracle-check: valid bytewise replay, four rejection controls and metadata normalization passed')
