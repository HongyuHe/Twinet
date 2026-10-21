import argparse,hashlib,json,subprocess
from pathlib import Path
from datetime import datetime,timezone

def utc():return datetime.now(timezone.utc).isoformat()
INSIDE=r"""import os,json,pathlib,subprocess,re
records=[]
for p in sorted(pathlib.Path('/proc').glob('[0-9]*')):
 try:
  args=p.joinpath('cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace');name=p.joinpath('comm').read_text().strip()
  if int(p.name)==os.getpid():args='[inventory collector]'
  args=re.sub(r'(?i)(password|secret|token|mka_cak)([= ]+)[^ ]+',r'\1\2[REDACTED]',args)
  records.append({'pid':int(p.name),'name':name,'command':args,'process_state':p.joinpath('stat').read_text().rsplit(') ',1)[1].split()[0]})
 except (FileNotFoundError,PermissionError):pass
out={'processes':records,'commands':[],'public_files':{},'access':[],'startup_files':{}}
for cmd in [['ss','-H','-a','-n','-p','-A','all'],['systemctl','list-unit-files','--state=enabled','--no-pager'],['ip','-j','address'],['ip','-j','route','show','table','all'],['sysctl','net.ipv4.ip_forward','net.ipv6.conf.all.forwarding','net.ipv6.conf.all.autoconf','net.ipv6.conf.default.autoconf']]:
 try:
  r=subprocess.run(cmd,text=True,capture_output=True,timeout=10);out['commands'].append({'argv':cmd,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 except Exception as e:out['commands'].append({'argv':cmd,'unavailable':str(e)})
for name in ['/etc/resolv.conf','/etc/nsswitch.conf','/etc/network/interfaces','/etc/systemd/networkd.conf','/etc/ssh/sshd_config']:
 p=pathlib.Path(name);out['public_files'][name]={'exists':p.exists(),'content':p.read_text() if p.exists() else None}
for directory in ['/etc/init.d','/etc/rc0.d','/etc/rc1.d','/etc/rc2.d','/etc/rc3.d','/etc/rc4.d','/etc/rc5.d','/etc/rc6.d','/etc/netplan','/etc/systemd/network','/etc/dhcp']:
 p=pathlib.Path(directory);out['startup_files'][directory]=[str(q) for q in p.iterdir()] if p.exists() else []
shadow={}
p=pathlib.Path('/etc/shadow')
if p.exists():
 for line in p.read_text().splitlines():
  f=line.split(':');shadow[f[0]]={'password_locked':f[1].startswith(('!','*')),'empty_password':f[1]=='','hash_exported':False}
for line in pathlib.Path('/etc/passwd').read_text().splitlines():
 f=line.split(':');out['access'].append({'user':f[0],'uid':int(f[2]),'shell':f[-1],**shadow.get(f[0],{'password_status':'unavailable'})})
print(json.dumps(out))
"""
p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--profiles',default='native-ipsec-baseline,native-management-independent');p.add_argument('--output-name',default='native-component-inventory-v1');a=p.parse_args();base=Path(a.root);out=base/'exports'/a.output_name;out.mkdir(parents=True,exist_ok=False);start=utc();records=[];scopes=[]
def run(cmd):
 t=utc();r=subprocess.run(cmd,text=True,capture_output=True,timeout=30);records.append({'id':'inv-%04d'%len(records),'command':cmd if '-c' not in cmd else cmd[:4]+['[hashed inventory script]'],'started_at':t,'ended_at':utc(),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr});return r
for profile in a.profiles.split(','):
 bundle='separately supplied native snapshot for '+profile
 spec=base/'Twinet/examples/msc/construction'/(profile+'.json');s=json.loads(spec.read_text());scope={'configuration_id':profile,'spec_sha256':hashlib.sha256(spec.read_bytes()).hexdigest(),'prior_snapshot':bundle,'expected_device_ids':[d['id'] for d in s['devices']],'devices':[]}
 for d in s['devices']:
  c=d['id'] if s['version']==2 else 'twinet-'+s['name']+'-'+d['id'].lower();before=run(['docker','inspect','--format','{{json .}}',c]);r=run(['docker','exec',c,'python3','-c',INSIDE]);after=run(['docker','inspect','--format','{{.Id}} {{.State.Pid}} {{.State.StartedAt}}',c]);b=json.loads(before.stdout) if before.returncode==0 else {}
  scope['devices'].append({'device_id':d['id'],'container':c,'inventory_observation_id':records[-2]['id'],'identity_before':{'id':b.get('Id'),'image':b.get('Image'),'state':{k:b.get('State',{}).get(k) for k in ['Pid','StartedAt','Running']},'entrypoint':b.get('Config',{}).get('Entrypoint'),'command':b.get('Config',{}).get('Cmd')},'identity_after':after.stdout.strip(),'inventory':json.loads(r.stdout) if r.returncode==0 else None})
 scopes.append(scope)
namespace_owners={};namespace_processes=[];docker_associations=[]
for scope in scopes:
 for d in scope['devices']:
  pid=d['identity_before']['state']['Pid'];inode=Path('/proc')/str(pid)/'ns/net';identity=__import__('os').readlink(inode);d['network_namespace_identity']=identity;namespace_owners.setdefault(identity,[]).append(scope['configuration_id']+':'+d['device_id'])
for process in sorted(Path('/proc').glob('[0-9]*')):
 try:
  ns=__import__('os').readlink(process/'ns/net')
  if ns not in namespace_owners:continue
  args=process.joinpath('cmdline').read_bytes().replace(bytes([0]),b' ').decode(errors='replace')
  namespace_processes.append({'host_pid':int(process.name),'network_namespace':ns,'device_scopes':namespace_owners[ns],'name':process.joinpath('comm').read_text().strip(),'process_state':process.joinpath('stat').read_text().rsplit(') ',1)[1].split()[0],'command':args})
 except (FileNotFoundError,PermissionError):pass
all_containers=run(['docker','ps','-q'])
for cid in all_containers.stdout.split():
 r=subprocess.run(['docker','inspect','--format','{{.Id}} {{.Name}} {{.State.Pid}} {{.Image}} {{.HostConfig.NetworkMode}}',cid],text=True,capture_output=True)
 if r.returncode:continue
 f=r.stdout.strip().split()
 try:ns=__import__('os').readlink(Path('/proc')/f[2]/'ns/net')
 except FileNotFoundError:continue
 if ns in namespace_owners:docker_associations.append({'id':f[0],'name':f[1],'host_pid':int(f[2]),'image':f[3],'network_mode':f[4],'network_namespace':ns,'device_scopes':namespace_owners[ns]})
(out/'namespace-processes.json').write_text(json.dumps({'observed_at':utc(),'namespace_owners':namespace_owners,'processes':namespace_processes,'docker_associations':docker_associations,'scope':'Enumerate host process namespace symlinks; read commands only after matching an owned device namespace. No unrelated commands are exported.'},indent=2)+'\n')
(out/'collector-inside.py').write_text(INSIDE)
(out/'observations.json').write_text(json.dumps({'schema_version':'csfc-component-inventory/v1','request_id':'ER-018','started_at':start,'ended_at':utc(),'scopes':scopes,'records':records,'limitations':['Finite runtime and startup-file inventory; no historical vendor-default comparison.','Systemd may not run inside containers; missing service-manager observations remain explicit.','No password hashes, private keys or authentication secrets exported.','Absence of a named daemon is an observation, not a verified implementation-wide absence theorem.']},indent=2)+'\n')
files=[{'path':q.name,'bytes':q.stat().st_size,'sha256':hashlib.sha256(q.read_bytes()).hexdigest()} for q in sorted(out.iterdir())]
(out/'manifest.json').write_text(json.dumps({'schema_version':'csfc-component-inventory/v1','started_at':start,'ended_at':utc(),'code_hashes':{Path(__file__).name:hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},'files':files},indent=2)+'\n');print(json.dumps({'output':str(out),'devices':sum(len(s['devices']) for s in scopes),'observations':len(records)}))
