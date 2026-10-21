import argparse
from datetime import datetime,timezone
import hashlib,json,subprocess,time
from pathlib import Path

def utc():return datetime.now(timezone.utc).isoformat()
p=argparse.ArgumentParser();p.add_argument("--root",required=True);p.add_argument("--phase",choices=["before","after"],required=True);a=p.parse_args()
base=Path(a.root);out=base/"exports"/("baseline-auth-"+a.phase+"-v4");out.mkdir(parents=True,exist_ok=False);records=[];started=utc()
def run(cmd,check=True):
 t=utc();r=subprocess.run(cmd,text=True,capture_output=True,timeout=90)
 if "PRIVATE KEY-----" in r.stdout:raise RuntimeError("refuse secret")
 records.append({"id":"auth-%03d"%len(records),"command":cmd,"started_at":t,"ended_at":utc(),"returncode":r.returncode,"stdout":r.stdout,"stderr":r.stderr})
 if check and r.returncode:raise RuntimeError(str(records[-1]))
 return r.stdout
devices=[f"{role}_{site}{n}" for role in ["I","O"] for site in ["A","B"] for n in [1,2]]
error=None
try:
 for d in devices:
  c="twinet-csfc-v2-"+d.lower();iface="gray" if d.startswith("I") else "black"
  conf=run(["docker","exec",c,"cat","/etc/swanctl/swanctl.conf"])
  (out/(d+".before.conf")).write_text(conf)
  if a.phase=="after":
   mounts=json.loads(run(["docker","inspect","--format","{{json .Mounts}}",c]))
   mount=next(x for x in mounts if x["Destination"]=="/etc/swanctl")
   target=Path(mount["Source"])/"swanctl.conf"
   assert target.is_relative_to(base/"private/ipsec-baseline/devices")
   assert target.read_text()==conf and conf.count("auth = pubkey")==2
   changed=conf.replace("auth = pubkey","auth = ecdsa-384-sha384")
   target.write_text(changed)
   records.append({"id":"auth-%03d"%len(records),"command":["write_public_config",str(target)],"started_at":utc(),"ended_at":utc(),"returncode":0,"stdout":json.dumps({"before_sha256":hashlib.sha256(conf.encode()).hexdigest(),"after_sha256":hashlib.sha256(changed.encode()).hexdigest()}),"stderr":""})
  run(["docker","exec",c,"swanctl","--load-conns","--file","/etc/swanctl/swanctl.conf"])
  run(["docker","exec",c,"swanctl","--list-conns","--raw"])
  (out/(d+".loaded.conf")).write_text(run(["docker","exec",c,"cat","/etc/swanctl/swanctl.conf"]))
  run(["docker","exec",c,"openssl","x509","-in","/etc/swanctl/x509/cert.pem","-noout","-text","-fingerprint","-sha256"])
  run(["docker","exec",c,"cat","/etc/strongswan.conf"])
  run(["docker","cp",str(Path(__file__).with_name("auth_headers.py")),c+":/tmp/auth-headers.py"])
  run(["docker","exec",c,"sh","-ec",f"python3 /tmp/auth-headers.py {iface} >/tmp/auth-headers-{a.phase}.jsonl 2>/tmp/auth-headers-{a.phase}.err & echo $! >/tmp/auth-headers-{a.phase}.pid; timeout 60s stdbuf -oL -eL swanctl --log >/tmp/auth-log-{a.phase}.txt 2>&1 &"])
 time.sleep(1)
 for role in ["O","I"]:
  for n in [1,2]:run(["docker","exec",f"twinet-csfc-v2-{role.lower()}_a{n}","swanctl","--rekey","--ike","msc","--reauth"])
 time.sleep(3)
 for n in [1,2]:
  for site,remote in [("a","2"),("b","1")]:run(["docker","exec",f"twinet-csfc-v2-r_{site}{n}","ping","-c","3","-W","1",f"10.{remote}.{n}.10"],False)
 for d in devices:
  c="twinet-csfc-v2-"+d.lower()
  run(["docker","exec",c,"python3","-c",f"import os,signal;from pathlib import Path;os.kill(int(Path('/tmp/auth-headers-{a.phase}.pid').read_text()),signal.SIGTERM)"])
  for f in [f"/tmp/auth-headers-{a.phase}.jsonl",f"/tmp/auth-headers-{a.phase}.err",f"/tmp/auth-log-{a.phase}.txt"]:run(["docker","exec",c,"cat",f])
  run(["docker","exec",c,"tail","-n","250","/tmp/charon.log"])
  run(["docker","exec",c,"swanctl","--list-sas"])
  run(["docker","exec",c,"ip","-s","xfrm","state","list","nokeys"])
except Exception as e:error=str(e)
(out/"events.json").write_text(json.dumps({"schema_version":"csfc-auth-events/v1","phase":a.phase,"started_at":started,"ended_at":utc(),"records":records,"error":error,"limitations":["Finite exchange; no approved PKI or complete RFC conformance claim.","ecdsa-384 constrains minimum public key strength; actual certificates identify secp384r1.","Public headers contain no payload bytes or key material."]},indent=2)+"\n")
files=[{"path":q.name,"bytes":q.stat().st_size,"sha256":hashlib.sha256(q.read_bytes()).hexdigest()} for q in sorted(out.iterdir())]
(out/"manifest.json").write_text(json.dumps({"schema_version":"csfc-auth-events/v1","files":files,"started_at":started,"ended_at":utc(),"code_hashes":{q.name:hashlib.sha256(q.read_bytes()).hexdigest() for q in [Path(__file__),Path(__file__).with_name("auth_headers.py")]}},indent=2)+"\n")
print(json.dumps({"output":str(out),"error":error,"records":len(records)}))
