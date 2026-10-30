"""Data-only case semantics extracted from reviewed checker; never execute guest code."""
import base64, hashlib, json, re, struct

def sha(b):
    return hashlib.sha256(b).hexdigest()

def need(x, msg):
    if not x:
        raise ValueError(msg)

def diag(raw, n):
    d = raw['diagnostics'][n]
    need(not d.get('missing') and d.get('truncated') is False and (not d.get('error')), 'diagnostic missing ' + n)
    b = base64.b64decode(d['base64'], validate=True)
    need(len(b) == d['captured_bytes'], 'diagnostic size ' + n)
    return b

def outcome_control(raw):
 need(raw.get('setup',{}).get('status')==0 and not raw.get('setup',{}).get('error') and not raw.get('error') and not raw.get('harness_error') and not raw.get('stray_processes'),'setup or harness incomplete')
 control=json.loads(diag(raw,'uclamp-control.json'));need(len(control)==3 and [x['label'] for x in control]==['independent-util-linux-control','independent-reset-control','independent-command-control'],'native control labels')
 for e,rc in zip(control,(0,0,7)):need(e['operation']['status']==rc and e['operation']['argv'][0]=='/usr/bin/uclampset' and e['operation']['stderr']=='','native positive control status/identity')
 need(control[0]['operation']['argv'][1:5]==['-m','100','-M','900'] and control[1]['operation']['argv'][1:5]==['-m','-1','-M','-1'] and control[0]['operation']['argv'][-1]==control[1]['operation']['argv'][-1] and control[0]['operation']['stdout']==control[1]['operation']['stdout']=='' and json.loads(control[2]['operation']['stdout'])==control[2]['after'],'native control raw bytes')
 a,b,c=[x['after'] for x in control];need((a['util_min'],a['util_max'])==(100,900) and (b['util_min'],b['util_max'])==(0,1024) and (c['attr']['util_min'],c['attr']['util_max'])==(100,800) and c['argv']==['a b',''],'native control observations')

def request(result,target):
 events=result['trace'];need(isinstance(events,list),'missing scheduler request trace');sets=[e for e in events if e.get('syscall')=='sched_setattr'];need(len(sets)==1 and sets[0].get('arg0')==target,'scheduler request target');m=sets[0]['memory1'];raw=bytes.fromhex(m['hex']);need(len(raw)==56 and m['length']==56,'scheduler request bytes');return {'flags':struct.unpack_from('<Q',raw,8)[0],'min':struct.unpack_from('<I',raw,48)[0],'max':struct.unpack_from('<I',raw,52)[0]}

def rowparse(s):
 pattern=re.compile(r'^(.*) \(([0-9]+)\) util_clamp: min: ([0-9]+) max: ([0-9]+)$');out=[]
 for line in s.splitlines():
  m=pattern.fullmatch(line)
  if not m:return None
  out.append((m[1],int(m[2]),int(m[3]),int(m[4])))
 return out

def delivery(result,target):
 outcome=result['observer_outcome'];trace=result['trace'];need(isinstance(outcome,dict) and outcome.get('schema')=='uclamp-notify-outcome-v1' and outcome.get('target')==target and outcome.get('observer_status')=='completed' and type(outcome.get('program_status')) is int and outcome['program_status']==result['status'] and isinstance(trace,list),'notify outcome missing')
 calls=[e for e in trace if e.get('kind')=='request' and e.get('syscall')=='sched_getattr' and e.get('arg0')==target and e.get('requested_reply')=='errno:3'];need(len(calls)==1,'target ESRCH request absent');acks=[(i,e) for i,e in enumerate(trace) if e.get('kind')=='send-ack' and e.get('id')==calls[0].get('id') and e.get('syscall')=='sched_getattr' and e.get('arg0')==target and e.get('sent_reply')=='errno:3'];need(len(acks)==1 and acks[0][0]>trace.index(calls[0]),'ESRCH send acknowledgement absent')

def independent_case(raw,case):
 result={'classification':'INCOMPLETE','candidate_mismatches':[],'control_valid':False,'candidate_reached':False};cid=case['id']
 def mismatch(ok,msg):
  if not ok:result['candidate_mismatches'].append(msg)
 try:
  outcome_control(raw)
  if cid=='uclamp-followup-command-dispatch':
   need(diag(raw,'dispatch-control-status')==b'73\n' and diag(raw,'dispatch-control-marker')==b'external','dispatch native external control');result['control_valid']=True
   candidate_status=diag(raw,'dispatch-status').strip();need(re.fullmatch(rb'\d+',candidate_status),'candidate status incomplete');result['candidate_reached']=True
   mismatch(candidate_status==b'0','builtin candidate status');mismatch(diag(raw,'dispatch-marker')==b'clean','external command marker changed')
  else:
   field='query-report.json' if '-query-' in cid else 'alltasks-report.json' if '-alltasks-' in cid else 'scheduler-mock-report.json' if '-mock-' in cid else 'setter-report.json'
   report=json.loads(diag(raw,field));events=report['events'];mode=cid.rsplit('-',1)[-1];result['observer_incomplete']=report.get('incomplete');result['report_sha256']=sha(diag(raw,field));need(report.get('control_valid') is True,'same-case native control incomplete')
   if '-query-' in cid:
    need(events['filter_kill_control']['status']==159,'query kill-filter control');task=events['task_self_read'];ids=[task['tid']]+[p['tid'] for p in task['peers']];before=events['before'];need(len(ids)==len(set(ids)) and task['pid']==task['tid'],'owned task identity');need(all(t['attr']==before[str(t['tid'])] for t in [{'tid':task['tid'],'attr':task['self_attr']}]+task['peers']),'independent task self-read');native=events['native'];nr=rowparse(native['stdout']);want={t:(before[str(t)]['util_min'],before[str(t)]['util_max']) for t in ids};need(native['status']==0 and native['stderr']=='' and nr is not None and len(nr)==len(ids) and {t:(lo,hi) for _,t,lo,hi in nr}==want,'native query values');result['control_valid']=True
    if mode=='threads':need(len(ids)==3 and len(set(want.values()))==3 and {(p['attr']['util_min'],p['attr']['util_max']) for p in task['peers']}=={(100,900),(200,800)},'thread seed controls')
    if mode=='p0':
     saved=events['p0_retained'];need(saved['p0-opstatus'] is not None and saved['p0-operation.out'] is not None and saved['p0-operation.err'] is not None,'p0 saved operation absent');status=int(saved['p0-opstatus']);need(status not in (125,126,127),'p0 status ambiguous');result['candidate_reached']=True;mismatch(status==0,'p0 operation status')
     need('p0_pid' in events and 'p0_before' in events and 'p0_after' in events,'p0 after observation incomplete');r=rowparse(saved['p0-operation.out']);a=events['p0_before'];b=events['p0_after'];mismatch(r is not None and len(r)==1 and r[0][1]==events['p0_pid'] and r[0][2:]==(a['util_min'],a['util_max']),'p0 pid or values');mismatch(a==b,'p0 state changed');mismatch(saved['p0-operation.err']=='','p0 stderr')
    else:
     cand=events['candidate'];need(type(cand['status']) is int and cand['status'] not in (125,126,127),'candidate process status ambiguous');result['candidate_reached']=True;mismatch(cand['status']==0,'query candidate status');r=rowparse(cand['stdout']);mismatch(r is not None and len(r)==len(ids) and len({v[1] for v in r})==len(ids) and {t:(lo,hi) for _,t,lo,hi in r}==want,'query format or values');mismatch(cand['stderr']=='','query stderr');need('after' in events,'query after observation missing');mismatch(before==events['after'],'query state changed')
     if mode=='self':mismatch(cand['stdout']==native['stdout'] and task['self_attr']==before[str(task['tid'])],'self/native comparison')
     if mode=='empty':mismatch(bool(r and r[0][0]==str(task['pid'])),'empty-comm fallback')
   elif '-setter-mock-' in cid:
    mode=cid.rsplit('-',1)[-1];policy,priority,run,deadline,period=(1,7,0,0,0) if mode=='rt' else (6,0,1000000,10000000,10000000);control=events['control'];candidate=events['candidate'];need(control['status']==0,'synthetic native control status')
    def parse_mock(o):
     gets=[e for e in o['events'] if e['syscall']=='sched_getattr'];sets=[e for e in o['events'] if e['syscall']=='sched_setattr'];need(len(gets)==len(sets)==1 and gets[0]['target']==sets[0]['target'] and gets[0]['reply']==sets[0]['reply']=='synthetic-zero','mock notification target');template=bytes.fromhex(gets[0]['synthetic_output_hex']);raw=bytes.fromhex(sets[0]['input']['hex']);need(len(template)==len(raw)==56,'mock request bytes');return struct.unpack('<IIQiIQQQII',template),struct.unpack('<IIQiIQQQII',raw)
    ct,cr=parse_mock(control);expected=(policy,priority,run,deadline,period);need((ct[1],ct[4],ct[5],ct[6],ct[7])==expected and (cr[1],cr[4],cr[5],cr[6],cr[7])==expected,'synthetic native control fields');result['control_valid']=True;need(type(candidate['status']) is int and candidate['status'] not in (125,126,127),'mock candidate status ambiguous');result['candidate_reached']=True;mismatch(candidate['status']==0,'mock candidate status');t,r=parse_mock(candidate);need((t[1],t[4],t[5],t[6],t[7])==expected,'synthetic template mismatch');mismatch((r[1],r[4],r[5],r[6],r[7])==expected,'synthetic RT/deadline field preservation')
   elif '-setter-' in cid:
    n=events['native_task']['pid'];c=events['candidate_task']['pid'];need(n!=c and events['native']['status']==0,'native setter control');nr=request(events['native'],n);after_n=events['after_native'];before_n=events['before_native']
    if mode=='reset':need(nr['flags']&0x60==0x60 and (nr['min'],nr['max'])==(0xffffffff,0xffffffff) and (after_n['util_min'],after_n['util_max'])==(0,1024),'native reset control')
    elif mode=='policy':need((before_n['policy'],before_n['nice'])==(3,5) and (after_n['policy'],after_n['nice'])==(3,5),'native policy control')
    elif mode=='fork':need((events['native_fork']['child_attr']['util_min'],events['native_fork']['child_attr']['util_max'])==(0,1024),'native reset-on-fork control')
    else:raise ValueError('unknown setter mode')
    result['control_valid']=True;cand=events['candidate'];need(type(cand['status']) is int and cand['status'] not in (125,126,127),'setter status ambiguous');result['candidate_reached']=True;mismatch(cand['status']==0,'setter candidate status');mismatch(cand['stderr']=='','setter stderr');cr=request(cand,c);after=events['after_candidate'];before=events['before_candidate']
    if mode=='reset':mismatch(cr['flags']&0x60==0x60 and (cr['min'],cr['max'])==(0xffffffff,0xffffffff) and (after['util_min'],after['util_max'])==(0,1024),'reset flags/values/readback')
    elif mode=='policy':need((before['policy'],before['nice'])==(3,5),'candidate policy seed incomplete');mismatch((after['policy'],after['nice'])==(3,5),'policy and nice changed')
    else:mismatch(bool(cr['flags']&1) and (events['candidate_fork']['child_attr']['util_min'],events['candidate_fork']['child_attr']['util_max'])==(0,1024),'reset-on-fork flag/readback')
   elif '-alltasks-' in cid:
    ids=events['enumerated_tids'];task=events['task_self_read'];need(len(ids)==3 and len(set(ids))==3 and set(ids)=={task['tid'],*[p['tid'] for p in task['peers']]} and {(p['attr']['util_min'],p['attr']['util_max']) for p in task['peers']}=={(100,900),(200,800)},'owned TID inventory and seed');native=events['native'];need(native['status']==0 and all((v['util_min'],v['util_max'])==(100,900) for v in events['native_after'].values()) and events['reset_control']['status']==0,'native all-task controls');nt=native['trace'];need({e.get('arg0') for e in nt if e.get('syscall')=='sched_getattr'}==set(ids) and {e.get('arg0') for e in nt if e.get('syscall')=='sched_setattr'}==set(ids),'native all-task trace')
    if mode=='readfail':delivery(events['readfail_control'],ids[-1]);need(events['readfail_control']['status'] not in (0,125,126,127) and bool(events['readfail_control']['stderr']),'native read failure control')
    if mode=='validation':need(events['seed_control']['status']==0 and events['before'][str(ids[-1])]['util_max']==100,'last TID seeded')
    result['control_valid']=True;cand=events['candidate'];need(type(cand['status']) is int and cand['status'] not in (125,126,127),'all-task status ambiguous')
    if mode=='readfail':delivery(cand,ids[-1])
    result['candidate_reached']=True;trace=cand['trace'];need(isinstance(trace,list),'all-task trace absent');gets=[e for e in trace if e.get('syscall')=='sched_getattr' and e.get('kind','request')=='request'];sets=[e for e in trace if e.get('syscall')=='sched_setattr' and e.get('kind','request')=='request'];before=events['before'];after=events['after']
    if mode=='success':mismatch(cand['status']==0 and [e['arg0'] for e in gets]==ids and [e['arg0'] for e in sets]==ids and len(trace)==2*len(ids) and all(e.get('syscall')=='sched_getattr' for e in trace[:len(ids)]) and all((v['util_min'],v['util_max'])==(100,900) for v in after.values()),'all-task order or readback')
    else:mismatch(cand['status']!=0 and bool(cand['stderr']),'all-task rejection');mismatch(not sets,'all-task unexpected setter');mismatch(before==after,'all-task mutation');mismatch([e['arg0'] for e in gets]==ids,'all-task prior and failing TID order')
   else:raise ValueError('unknown case')
  if result['candidate_mismatches']:result['classification']='REACHED_FAIL'
  else:
   need(raw['status']==0 and not result.get('observer_incomplete'),'outer execution incomplete');need(base64.b64decode(raw['stdout_base64'],validate=True)==case['stdout'].encode() and base64.b64decode(raw['stderr_base64'],validate=True)==case['stderr'].encode(),'wrapper output mismatch');result['classification']='BOUNDED_PASS'
 except (KeyError,ValueError,TypeError,IndexError,UnicodeError,struct.error) as e:
  result['classification']='REACHED_FAIL' if result['control_valid'] and result['candidate_reached'] and result['candidate_mismatches'] else 'INCOMPLETE';result['reason']=str(e)
 return result
