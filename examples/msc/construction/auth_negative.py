import argparse,hashlib,json,subprocess,time
from pathlib import Path
from datetime import datetime,timezone

def utc():return datetime.now(timezone.utc).isoformat()
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();base=Path(a.root);out=base/'exports/baseline-auth-negative-v1';out.mkdir(parents=True,exist_ok=False);records=[];started=utc()
def run(cmd,check=True):
 t=utc();r=subprocess.run(cmd,text=True,capture_output=True,timeout=45);records.append({'id':'neg-%03d'%len(records),'command':cmd,'started_at':t,'ended_at':utc(),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(str(records[-1]))
 return r
def ex(d,*args,check=True):return run(['docker','exec','twinet-csfc-v2-'+d.lower(),*args],check)
target=base/'private/ipsec-baseline/devices/I_A1/swanctl/swanctl.conf';original=target.read_text();(out/'I_A1.original.conf').write_text(original);error=None
try:
 assert original.count('auth = ecdsa-384-sha384')==2
 negative=original.replace('auth = ecdsa-384-sha384','auth = ike:ecdsa-sha256',1)
 target.write_text(negative);(out/'I_A1.negative.conf').write_text(negative)
 ex('I_A1','swanctl','--load-conns','--file','/etc/swanctl/swanctl.conf')
 ex('I_B1','cat','/etc/swanctl/swanctl.conf')
 for d in ['I_A1','I_B1']:ex(d,'swanctl','--terminate','--ike','msc',check=False)
 ex('I_A1','swanctl','--initiate','--child','protected',check=False)
 for d in ['I_A1','I_B1']:ex(d,'tail','-n','100','/tmp/charon.log')
finally:
 target.write_text(original);ex('I_A1','swanctl','--load-conns','--file','/etc/swanctl/swanctl.conf')
 for d in ['I_A1','I_B1']:ex(d,'swanctl','--terminate','--ike','msc',check=False)
 ex('I_A1','swanctl','--initiate','--child','protected')
 ex('R_A1','ping','-c','3','-W','1','10.2.1.10')
 for d in ['I_A1','I_B1']:ex(d,'tail','-n','60','/tmp/charon.log');ex(d,'swanctl','--list-sas')
 (out/'events.json').write_text(json.dumps({'schema_version':'csfc-auth-negative/v1','request_id':'ER-017','started_at':started,'ended_at':utc(),'records':records,'source_case_ids':['NET-001-C01','NET-024-C01'],'scope':'One representative Inner pair; exact rejection cause is in peer log. Restoring SHA384 success checks useful behavior.'},indent=2)+'\n')
 files=[{'path':q.name,'bytes':q.stat().st_size,'sha256':hashlib.sha256(q.read_bytes()).hexdigest()} for q in sorted(out.iterdir())]
 (out/'manifest.json').write_text(json.dumps({'schema_version':'csfc-auth-negative/v1','code_hashes':{Path(__file__).name:hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},'files':files,'started_at':started,'ended_at':utc()},indent=2)+'\n')
 print(json.dumps({'output':str(out),'records':len(records)}))
