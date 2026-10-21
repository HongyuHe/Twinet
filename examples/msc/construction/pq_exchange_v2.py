#!/usr/bin/env python3
"""Run the Figure 10 IKEv2 sequence using a separate public-key test PKI."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time

def utc():return datetime.now(timezone.utc).isoformat()

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",required=True);a=p.parse_args()
    base=Path(a.root);out=base/"exports"/"ikev2-objective-v2";out.mkdir(parents=True,exist_ok=False)
    private=base/"private"/"pq2";private.mkdir(parents=True,exist_ok=True);private.chmod(0o700)
    started=utc();records=[]
    def run(cmd,check=True):
        begin=utc();r=subprocess.run(cmd,text=True,capture_output=True,timeout=90)
        record={"id":"pq-%03d"%len(records),"command":cmd,"started_at":begin,"ended_at":utc(),"returncode":r.returncode,"stdout":r.stdout,"stderr":r.stderr}
        if "PRIVATE KEY-----" in r.stdout:raise RuntimeError("Secret material refused")
        records.append(record)
        if check and r.returncode:raise RuntimeError(json.dumps(record))
        return r
    error=None
    try:
        run(["docker","network","create","--driver","bridge","--subnet","172.29.241.0/24","tcv2-pq2net"])
        issue="""set -eu
cd /pki
umask 077
mkdir -p ca bob/private bob/x509 bob/x509ca alice/private alice/x509 alice/x509ca
openssl genpkey -algorithm ML-DSA-87 -out ca/key.pem
openssl req -new -x509 -key ca/key.pem -out ca/cert.pem -days 1 -subj /CN=CSfC-Test-MLDSA-CA -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
for name in bob alice; do
 openssl genpkey -algorithm ML-DSA-87 -out $name/private/key.pem
 openssl req -new -key $name/private/key.pem -out $name/request.pem -subj /CN=$name.msc.test
 printf "subjectAltName=DNS:%s.msc.test\\nbasicConstraints=CA:FALSE\\nkeyUsage=critical,digitalSignature\\nextendedKeyUsage=1.3.6.1.5.5.8.2.2\\n" "$name" > $name/extensions.txt
 openssl x509 -req -in $name/request.pem -CA ca/cert.pem -CAkey ca/key.pem -CAcreateserial -days 1 -extfile $name/extensions.txt -out $name/x509/cert.pem
 cp ca/cert.pem $name/x509ca/ca.pem
done
openssl version
"""
        run(["docker","run","--rm","-v",str(private)+":/pki","twinet-msc:mldsa-construction-v2","sh","-ec",issue])
        for name,peer,idx,pidx in [("bob","alice",2,3),("alice","bob",3,2)]:
            config=f"""connections {{
 objective {{
  version = 2
  local_addrs = 172.29.241.{idx}
  remote_addrs = 172.29.241.{pidx}
  proposals = aes256gcm16-prfsha384-ecp384-ke1_mlkem1024
  fragmentation = yes
  rekey_time = 0s
  reauth_time = 3h
  local {{
   auth = pubkey
   certs = cert.pem
   id = {name}.msc.test
  }}
  remote {{
   auth = pubkey
   id = {peer}.msc.test
  }}
  children {{
   protected {{
    local_ts = 192.0.2.{idx}/32
    remote_ts = 192.0.2.{pidx}/32
    mode = tunnel
    esp_proposals = aes256gcm16-mlkem1024
    rekey_time = 50m
    life_time = 1h
   }}
  }}
 }}
}}
"""
            (private/name/"swanctl.conf").write_text(config)
            (out/(name+".swanctl.conf")).write_text(config)
            cname="tcv2-pq2-"+name
            run(["docker","run","-d","--name",cname,"--network","tcv2-pq2net","--ip",f"172.29.241.{idx}","--cap-add","NET_ADMIN","-v",str(private/name)+":/etc/swanctl","twinet-msc:mldsa-construction-v2"])
            run(["docker","exec",cname,"ip","addr","add",f"192.0.2.{idx}/32","dev","lo"])
            run(["docker","exec",cname,"sh","-ec","/usr/libexec/ipsec/charon >/tmp/charon.log 2>&1 &"])
            time.sleep(1)
            run(["docker","exec",cname,"swanctl","--load-all"])
            run(["docker","exec",cname,"swanctl","--list-algs"])
        run(["docker","exec","tcv2-pq2-bob","swanctl","--initiate","--child","protected"],False)
        run(["docker","exec","tcv2-pq2-bob","ping","-c","3","-W","1","-I","192.0.2.2","192.0.2.3"],False)
        for name in ["bob","alice"]:
            cname="tcv2-pq2-"+name
            for cmd in [["swanctl","--list-sas"],["swanctl","--list-certs","--utc"],["ip","-s","xfrm","state","list","nokeys"],["ip","xfrm","policy"],["cat","/tmp/charon.log"],["openssl","x509","-in","/etc/swanctl/x509/cert.pem","-noout","-text"],["openssl","verify","-CAfile","/etc/swanctl/x509ca/ca.pem","/etc/swanctl/x509/cert.pem"]]:
                run(["docker","exec",cname,*cmd],False)
            run(["docker","inspect","--format","{{.Image}}",cname])
    except Exception as e:error=str(e)
    evidence={"schema_version":"csfc-protocol-events/v1","case_ids":["NET-010-C01"],"group_ids":["RG-019","RG-020","RG-021","RG-023"],"started_at":started,"ended_at":utc(),"records":records,"error":error,"limitations":["Test CA and certificate validity do not establish approved PKI or NPE personnel authority.","No revocation response or long-duration reauthentication claim is made.","Finite protocol exchange does not certify complete RFC conformance."]}
    (out/"events.json").write_text(json.dumps(evidence,indent=2)+"\n")
    files=[{"path":q.name,"sha256":hashlib.sha256(q.read_bytes()).hexdigest(),"bytes":q.stat().st_size} for q in sorted(out.iterdir()) if q.is_file()]
    (out/"manifest.json").write_text(json.dumps({"schema_version":"csfc-protocol-events/v1","code_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"files":files,"started_at":started,"ended_at":utc()},indent=2)+"\n")
    print(json.dumps({"error":error,"records":len(records),"output":str(out)}))
if __name__=="__main__":main()
