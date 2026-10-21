#!/usr/bin/env python3
"""Boot an isolated real KVM guest for the virtual AW alternative."""
import argparse
import json
from pathlib import Path
import subprocess
import time
from datetime import datetime,timezone
parser=argparse.ArgumentParser();parser.add_argument('--root',required=True);args=parser.parse_args();base=Path(args.root);private=base/'private';out=base/'outputs';private.mkdir(parents=True,exist_ok=True);out.mkdir(parents=True,exist_ok=True);records=[]
def run(cmd,check=True):
 start=datetime.now(timezone.utc).isoformat();r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=40);records.append({'command':list(map(str,cmd)),'started_at':start,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr)
 return r
error=None
try:
 key=private/'vm-access'
 run(['ssh-keygen','-q','-t','ed25519','-N','','-f',key])
 public=(private/'vm-access.pub').read_text().strip()
 (private/'user-data').write_text('#cloud-config\nhostname: csfc-aw-vm\nusers:\n  - name: lab\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    groups: users\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - '+public+'\nssh_pwauth: false\ndisable_root: true\n')
 (private/'meta-data').write_text('instance-id: csfc-aw-vm-v1\nlocal-hostname: csfc-aw-vm\n')
 run(['cloud-localds',private/'seed.img',private/'user-data',private/'meta-data'])
 run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',base/'images/ubuntu-noble.img',private/'aw-vm.qcow2','8G'])
 run(['sudo','qemu-system-x86_64','-enable-kvm','-cpu','host','-m','1024','-smp','2','-drive','file='+str(private/'aw-vm.qcow2')+',if=virtio','-drive','file='+str(private/'seed.img')+',format=raw,if=virtio','-netdev','user,id=net0,hostfwd=tcp:127.0.0.1:22220-:22','-device','virtio-net-pci,netdev=net0','-display','none','-serial','file:'+str(private/'vm-console.log'),'-daemonize','-pidfile',private/'qemu.pid'])
 for attempt in range(40):
  r=run(['ssh','-i',key,'-p','22220','-o','BatchMode=yes','-o','ConnectTimeout=2','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(private/'vm-known-hosts'),'lab@127.0.0.1','hostname; uname -a; systemd-detect-virt; sudo dmidecode -s system-product-name'],False)
  if r.returncode==0:break
  time.sleep(2)
 if r.returncode:raise RuntimeError('Guest did not become ready')
except Exception as exc:error=str(exc)
(out/'vm-boot.json').write_text(json.dumps({'records':records,'error':error},indent=2)+'\n');print(json.dumps({'error':error,'records':len(records)}))
