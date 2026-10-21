"""Stable native profile launch, check, collect and teardown entrypoint."""
import argparse,hashlib,json,os,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
TWINET=HERE.parents[2]
PROFILES={
 'baseline':('native-ipsec-baseline','NET-001-C01,NET-002-C01,NET-024-C01','native-ipsec-baseline'),
 'samelevel':('native-shared-same-level','NET-005-C01','native-samelevel-identity'),
 'shared':('native-shared-four-levels','NET-006-C01,NET-013-C01,NET-020-C03','native-shared-four-levels'),
 'redundant':('native-redundant-four-levels','NET-009-C01,NET-020-C01,NET-020-C02','native-redundant-four-levels'),
 'management':('native-management-independent','NET-003-C01,NET-012-C01,NET-017-C02,NET-027-C03','native-management-independent')}
p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['up','check','collect','inventory','down']);p.add_argument('profile',choices=PROFILES);p.add_argument('--lab-root',type=Path,default=TWINET.parent);p.add_argument('--snapshot-name');p.add_argument('--deployer-sha256',help='Required when collecting a deployment created outside this helper');a=p.parse_args()
profile,cases,state=PROFILES[a.profile];binary=TWINET/'bin/twinet';spec=HERE/(profile+'.json');base=a.lab_root.resolve();deployment_record=base/'private'/state/'replay-deployer.json';started=datetime.now(timezone.utc).isoformat();binary_hash=hashlib.sha256(binary.read_bytes()).hexdigest()
if a.action in ['up','check','down']:
 cmd=[str(binary),'msc','--spec',str(spec),'--state-dir',str(base/'private'/state),a.action]
 if a.action=='check':cmd.append('--json')
elif a.action=='collect':
 deployed=a.deployer_sha256 or (json.loads(deployment_record.read_text())['deployer_sha256'] if deployment_record.exists() else None)
 if not deployed:raise SystemExit('No recorded deployer hash. Supply --deployer-sha256 for the binary that created the existing deployment.')
 name=a.snapshot_name or profile+'-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 ports=json.loads(subprocess.check_output(['ip','-j','link'],text=True));fallback=','.join(x for x in ['gre0','gretap0','erspan0'] if any(p['ifname']==x for p in ports))
 cmd=[sys.executable,str(HERE/'collect_native_v2.py'),'--spec',str(spec),'--output',str(base/'exports'/name),'--configuration-id',profile,'--case-ids',cases,'--confirm-loaded-config','--platform-interface-names',fallback,'--deployer-sha256',deployed]
 if a.profile=='samelevel':cmd+=['--probe-expectations',str(HERE/'native-same-level-probe-policy.json')]
else:
 name=a.snapshot_name or profile+'-inventory-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 cmd=[sys.executable,str(HERE/'native_inventory.py'),'--root',str(base),'--profiles',profile,'--output-name',name]
if os.geteuid()!=0:cmd=['sudo',*cmd]
print(json.dumps({'command':cmd,'scope':'Native FRR/OVS topology only; supplemental namespace experiments have separate entrypoints.'}),flush=True)
result=subprocess.run(cmd,cwd=TWINET)
if a.action=='up' and result.returncode==0:
 record={'deployer_sha256':binary_hash,'spec_sha256':hashlib.sha256(spec.read_bytes()).hexdigest(),'started_at':started,'ended_at':datetime.now(timezone.utc).isoformat()}
 if os.geteuid()==0:deployment_record.write_text(json.dumps(record,indent=2)+'\n')
 else:subprocess.run(['sudo',sys.executable,'-c','import sys;from pathlib import Path;Path(sys.argv[1]).write_text(sys.argv[2])',str(deployment_record),json.dumps(record,indent=2)+'\n'],check=True)
raise SystemExit(result.returncode)
