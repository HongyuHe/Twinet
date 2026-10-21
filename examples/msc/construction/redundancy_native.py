import argparse,hashlib,json,subprocess,time
from pathlib import Path
from datetime import datetime,timezone

def utc():return datetime.now(timezone.utc).isoformat()
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();base=Path(a.root);out=base/'exports/native-redundancy-events-v1';out.mkdir(parents=True,exist_ok=False);records=[];probes=[];started=utc();prefix='NR_'
def run(cmd,check=True):
 t=utc();r=subprocess.run(cmd,text=True,capture_output=True,timeout=30);records.append({'id':'redundancy-%04d'%len(records),'command':cmd,'started_at':t,'ended_at':utc(),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(str(records[-1]))
 return r
def ex(d,*args,check=True):return run(['docker','exec',prefix+d,*map(str,args)],check)
def state(label):
 for d in ['GR_A','GR_B','O_A1','O_A2','O_B1','O_B2']:
  if d.startswith('GR_'):ex(d,'vtysh','-c','show running-config')
  for cmd in [['ip','-j','route'],['iptables-save'],['ip','-s','xfrm','state','list','nokeys'],['ip','-j','-d','link']]:ex(d,*cmd)
  run(['docker','inspect','--format','{{.Id}} {{.State.Pid}} {{.State.StartedAt}}',prefix+d])
 records.append({'id':'phase-'+label,'started_at':utc(),'ended_at':utc(),'command':['phase',label],'returncode':0,'stdout':'','stderr':''})
current={n:1 for n in [1,2,3,4]}
def routes(mapping):
 for site,local,remote in [('A',110,200),('B',210,100)]:
  for n,hop in mapping.items():
   old=current[n]
   if old!=hop:ex('GR_'+site,'vtysh','-c','configure terminal','-c',f'no ip route 10.{remote}.{n}.2/32 10.{local}.{n}.{old}','-c',f'ip route 10.{remote}.{n}.2/32 10.{local}.{n}.{hop}','-c','end')
   for attempt in range(30):
    r=ex('GR_'+site,'ip','-j','route','get',f'10.{remote}.{n}.2')
    if json.loads(r.stdout)[0].get('gateway')==f'10.{local}.{n}.{hop}':break
    time.sleep(.2)
   else:raise RuntimeError('FRR route did not reach kernel')
 current.update(mapping)
def ping(label,level,expected):
 r=ex('R_A'+str(level),'ping','-n','-c','3','-W','1',f'10.2.{level}.10',check=False);probes.append({'id':label+'-'+str(level),'expected':expected,'observed':'delivered' if r.returncode==0 else 'no_reply' if r.returncode==1 else 'invocation_error','observation_id':records[-1]['id']})
error=None
try:
 state('initial-primary')
 for n in [1,2,3,4]:ping('primary',n,'delivered')
 routes({1:1,2:3,3:1,4:3});state('sharing-before-probes')
 for n in [1,2,3,4]:
  ex('GR_A','ip','route','get',f'10.200.{n}.2');ping('active-sharing',n,'delivered')
 state('sharing-after-probes')
 routes({n:1 for n in [1,2,3,4]})
 ex('O_A1','iptables','-I','FORWARD','1','-m','comment','--comment','csfc-v2-forwarding-outage','-j','DROP')
 state('primary-forwarding-outage');ping('primary-outage',1,'no_reply')
 routes({n:3 for n in [1,2,3,4]});state('standby-selected')
 for n in [1,2,3,4]:ping('standby-restored',n,'delivered')
 state('standby-after-probes')
except Exception as exc:error=str(exc)
finally:
 ex('O_A1','iptables','-D','FORWARD','-m','comment','--comment','csfc-v2-forwarding-outage','-j','DROP',check=False)
 routes({n:1 for n in [1,2,3,4]});state('original-routes-restored')
 for n in [1,2,3,4]:ping('original-restored',n,'delivered')
 (out/'events.json').write_text(json.dumps({'schema_version':'csfc-redundancy-events/v1','started_at':started,'ended_at':utc(),'records':records,'probes':probes,'error':error,'source_case_ids':['NET-009-C01','NET-020-C01','NET-020-C02'],'configuration_id':'native-redundant-four-levels','limitations':['Manual FRR route selection across pre-established independent Outer peer pairs; no automatic HA protocol or physical power-loss claim.','Failure is a tagged DROP rule on primary Outer forwarding. Existing SAs and packet counters remain intact; no key/nonce reset.','Source graph and baseline identity supplied by redundant-four-levels coherent snapshot; event interval is not atomic.']},indent=2)+'\n')
 files=[{'path':q.name,'bytes':q.stat().st_size,'sha256':hashlib.sha256(q.read_bytes()).hexdigest()} for q in out.iterdir()]
 (out/'manifest.json').write_text(json.dumps({'schema_version':'csfc-redundancy-events/v1','files':files,'code_hashes':{Path(__file__).name:hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},'spec_sha256':hashlib.sha256((base/'Twinet/examples/msc/construction/native-redundant-four-levels.json').read_bytes()).hexdigest(),'started_at':started,'ended_at':utc()},indent=2)+'\n')
 print(json.dumps({'output':str(out),'error':error,'probes':probes}))
