#!/usr/bin/env python3
"""Typed proposal for top terminal evidence; data validation only, no execution.

A caller must independently bind each raw item to a reviewed run, source, case,
controls and primary receipt before treating this proposal as migration evidence.
"""
from dataclasses import dataclass, asdict
from enum import Enum

class Outcome(str, Enum):
    PASS = 'PASS'
    FAIL = 'FAIL'

class Incomplete(ValueError):
    pass

@dataclass(frozen=True)
class Observation:
    case_id: str
    requirement: str
    outcome: Outcome
    raw_error: str | None
    status: int
    input_hex: tuple[str, ...]
    reached: str
    unreached: tuple[str, ...]

    def to_dict(self):
        result=asdict(self);result['outcome']=self.outcome.value
        return result

PREFIX='migration-terminal213-'
KEY=PREFIX+'control-key'
SCREEN=PREFIX+'control-screen'
FIFO_CONTROL=PREFIX+'top-fifo-control'
FRAME=PREFIX+'top-frame-control'
FIFO=PREFIX+'top-fifo-redraw'
PROMPTS={PREFIX+'top-delay-valid':('n-valid',('6e','330d','71')),
         PREFIX+'top-delay-invalid':('n-invalid',('6e','300d','71')),
         PREFIX+'top-sort-prompt-valid':('o',('6f',)),
         PREFIX+'top-sort-prompt-invalid':('O',('4f',))}

def require(condition, reason):
    if not condition: raise Incomplete(reason)

def healthy(raw):
    require(isinstance(raw,dict),'raw record missing')
    require('harness_error' in raw and 'decoder_error' in raw and raw['harness_error'] is None and raw['decoder_error'] is None,'infrastructure or decoder error or missing decoder proof')
    require(type(raw.get('status')) is int and 'error' in raw and 'signal' in raw and type(raw.get('terminal_restored')) is bool,'missing typed terminal status')
    setup=raw.get('setup');require(isinstance(setup,dict) and setup.get('status')==0 and setup.get('error') is None and setup.get('harness_error') is None,'setup infrastructure failure')
    require(raw.get('stray_processes')==[],'cleanup or process proof missing')
    require(isinstance(raw.get('events'),list) and isinstance(raw.get('terminal181_input_writes'),list),'missing PTY event/input records')

def controls_required(case_id):
    if case_id in PROMPTS:return (KEY,)
    if case_id==FIFO:return (SCREEN,FIFO_CONTROL,FRAME)
    raise Incomplete('unknown top original requirement case')

def validate_controls(case_id, controls):
    require(isinstance(controls,dict),'controls missing')
    for cid in controls_required(case_id):
        item=controls.get(cid);require(isinstance(item,dict) and item.get('framework_status')=='PASS','required control missing or failed: '+cid)
        raw=item.get('raw');healthy(raw)
        require(raw.get('status')==0 and raw.get('signal') is None and raw.get('error') is None and raw.get('terminal_restored') is True,'control raw failure: '+cid)

def classify(case_id, raw, framework_status, controls, *, independent_data_verdict):
    """Classify reached outcomes only after independently supplied raw verdict.

    A product timeout error is not an infrastructure error when the exact o/O
    prompt-failure pattern, action prefix, signal and independent raw review
    establish that the prompt assertion was reached. All other errors fail closed.
    """
    validate_controls(case_id,controls);healthy(raw)
    writes=tuple(x.get('hex') for x in raw['terminal181_input_writes'] if isinstance(x,dict))
    require(len(writes)==len(raw['terminal181_input_writes']),'invalid input record')
    if case_id==FIFO:
        require(independent_data_verdict=='OBSERVED_PASS_PENDING_PRIMARY' and framework_status=='PASS' and raw.get('error') is None and raw.get('status')==0 and raw.get('signal') is None and raw.get('terminal_restored') is True,'FIFO evidence incomplete or failed')
        return Observation(case_id,'r1',Outcome.PASS,None,0,writes,'three visible frames and four source-bound samples',())
    kind,expected=PROMPTS[case_id]
    if kind.startswith('n-'):
        require(independent_data_verdict=='delay PASS' and framework_status=='PASS' and raw.get('error') is None and raw.get('status')==0 and raw.get('signal') is None and raw.get('terminal_restored') is True and writes==expected,'delay evidence incomplete or failed')
        return Observation(case_id,'r2',Outcome.PASS,None,0,writes,kind+' input and response',())
    error=raw.get('error');require(independent_data_verdict=='sort prompt FAIL; later input unreached; status 137 from timeout cleanup' and framework_status=='FAIL' and isinstance(error,str) and error.startswith('PTY wall-clock limit waiting for step 2 screen:') and raw.get('status')==137 and raw.get('signal')==9 and writes==expected,'sort failure not attributable or incomplete')
    events=raw['events'];require(any(x.get('step')==0 and x.get('action')=='screen' for x in events) and any(x.get('step')==1 and x.get('action')=='send' and x.get('bytes_hex')==expected[0] for x in events) and not any(x.get('step',-1)>=2 for x in events),'sort action prefix differs')
    return Observation(case_id,'r2',Outcome.FAIL,error,137,writes,'missing sort prompt after '+kind,('sort value','response','q'))
