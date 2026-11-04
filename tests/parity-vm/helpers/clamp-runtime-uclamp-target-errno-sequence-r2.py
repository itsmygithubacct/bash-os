#!/usr/bin/python3
"""Compatibility argument adapter to the receipt-bearing r2 supervisor."""
import os,sys
from pathlib import Path
if len(sys.argv)<5 or sys.argv[3]!='--':raise SystemExit(125)
source=Path(__file__).with_name('clamp-system-sequence-r2.py')
os.execv('/usr/bin/python3',['/usr/bin/python3','-I',str(source),'--target-errno',sys.argv[1],'--notify','sched_getattr','--notify','sched_setattr','--log-args','sched_getattr=0','--log-args','sched_setattr=0','--log',sys.argv[2],'--',*sys.argv[4:]])
