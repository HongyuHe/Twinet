#!/usr/bin/env python3
"""Separate IKE certificate-authentication realizations for CA arrangements."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

CODE_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
def utc():return datetime.now(timezone.utc).isoformat()

def run_mode(base,mode,octet,case):
    out=base/'exports'/('ca-'+mode+'-v1');out.mkdir(parents=True,exist_ok=False)
    private=base/'private'/('ca-'+mode+'-v1');private.mkdir(parents=True,exist_ok=False);private.chmod(0o700)
    records=[];started=utc();error=None;authorities={};peers={}
    def run(cmd,check=True):
        begin=utc();r=subprocess.run(list(map(str,cmd)),text=True,capture_output=True,timeout=30)
        row={'id':'ca-%04d'%len(records),'command':list(map(str,cmd)),'started_at':begin,'ended_at':utc(),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr};records.append(row)
        if 'PRIVATE KEY-----' in r.stdout:raise RuntimeError('Secret export refused')
        if check and r.returncode:raise RuntimeError(json.dumps(row))
        return r
    def newca(name,parent=None):
        path=private/'authorities'/name;path.mkdir(parents=True)
        run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-384','-out',path/'key.pem'])
        if parent is None:run(['openssl','req','-new','-x509','-sha384','-key',path/'key.pem','-out',path/'cert.pem','-days','1','-subj','/CN='+name,'-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
        else:
            run(['openssl','req','-new','-sha384','-key',path/'key.pem','-out',path/'req.pem','-subj','/CN='+name])
            (path/'ca.ext').write_text('basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
            run(['openssl','x509','-req','-sha384','-in',path/'req.pem','-CA',parent/'cert.pem','-CAkey',parent/'key.pem','-CAcreateserial','-days','1','-extfile',path/'ca.ext','-out',path/'cert.pem'])
        (path/'index').write_text('');(path/'serial').write_text('1000\n');(path/'crlnumber').write_text('1000\n');(path/'newcerts').mkdir()
        (path/'openssl.cnf').write_text('[ca]\ndefault_ca=main\n[main]\ndatabase='+str(path/'index')+'\nnew_certs_dir='+str(path/'newcerts')+'\ncertificate='+str(path/'cert.pem')+'\nprivate_key='+str(path/'key.pem')+'\nserial='+str(path/'serial')+'\ncrlnumber='+str(path/'crlnumber')+'\ndefault_md=sha384\ndefault_crl_days=1\npolicy=policy\n[policy]\ncommonName=supplied\n')
        run(['openssl','ca','-gencrl','-config',path/'openssl.cnf','-out',path/'crl.pem'])
        run(['openssl','x509','-in',path/'cert.pem','-noout','-text']);run(['openssl','crl','-in',path/'crl.pem','-noout','-text'])
        authorities[name]=path;return path
    try:
        for layer in ['inner','outer']:
            root=newca(mode+'-'+layer+'-root') if mode!='local' else None
            for site in ['a','b']:
                ca=newca(mode+'-'+layer+'-'+site,root) if mode=='enterprise' else newca(mode+'-'+layer+'-'+site) if mode=='local' else root
                peers[layer+'-'+site]={'issuer':ca,'root':root or ca}
        for name,info in peers.items():
            path=private/name
            for folder in ['private','x509','x509ca','x509crl']: (path/folder).mkdir(parents=True)
            run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-384','-out',path/'private/key.pem'])
            run(['openssl','req','-new','-sha384','-key',path/'private/key.pem','-out',path/'request.pem','-subj','/CN='+name+'.msc.test'])
            (path/'extensions').write_text('basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=1.3.6.1.5.5.8.2.2,serverAuth,clientAuth\nsubjectAltName=DNS:'+name+'.msc.test\n')
            run(['openssl','x509','-req','-sha384','-in',path/'request.pem','-CA',info['issuer']/'cert.pem','-CAkey',info['issuer']/'key.pem','-CAcreateserial','-days','1','-extfile',path/'extensions','-out',path/'x509/cert.pem'])
            layer=name.split('-')[0]
            for authority,apath in authorities.items():
                if '-'+layer+'-' in authority:
                    shutil.copyfile(apath/'cert.pem',path/'x509ca'/(authority+'.pem'));shutil.copyfile(apath/'crl.pem',path/'x509crl'/(authority+'.pem'))
            run(['openssl','x509','-in',path/'x509/cert.pem','-noout','-text'])
        network='tcv2-ca-'+mode
        run(['docker','network','create','--driver','bridge','--subnet',f'172.29.{octet}.0/24',network])
        for idx,(name,info) in enumerate(peers.items()):
            peer=name[:-1]+('b' if name.endswith('a') else 'a');pidx=idx+1 if idx%2==0 else idx-1
            config=f"""connections {{
 peer {{
  version = 2
  local_addrs = 172.29.{octet}.{idx+10}
  remote_addrs = 172.29.{octet}.{pidx+10}
  proposals = aes256gcm16-prfsha384-ecp384
  reauth_time = 3h
  rekey_time = 0s
  local {{
   auth = pubkey
   certs = cert.pem
   id = {name}.msc.test
  }}
  remote {{
   auth = pubkey
   id = {peer}.msc.test
   revocation = strict
  }}
  children {{
   protected {{
    local_ts = 192.0.2.{idx+10}/32
    remote_ts = 192.0.2.{pidx+10}/32
    esp_proposals = aes256gcm16-ecp384
    rekey_time = 50m
    life_time = 1h
   }}
  }}
 }}
}}
"""
            (private/name/'swanctl.conf').write_text(config);(out/(name+'.swanctl.conf')).write_text(config)
            cname=network+'-'+name
            run(['docker','run','-d','--name',cname,'--network',network,'--ip',f'172.29.{octet}.{idx+10}','--cap-add','NET_ADMIN','-v',str(private/name)+':/etc/swanctl','twinet-msc:construction-v2'])
            run(['docker','exec',cname,'ip','addr','add',f'192.0.2.{idx+10}/32','dev','lo'])
            run(['docker','exec',cname,'sh','-ec','/usr/lib/ipsec/charon >/tmp/charon.log 2>&1 &']);time.sleep(.3)
            run(['docker','exec',cname,'swanctl','--load-all'])
        for layer,idx in [('inner',10),('outer',12)]:
            cname=network+'-'+layer+'-a';run(['docker','exec',cname,'swanctl','--initiate','--child','protected'])
            run(['docker','exec',cname,'ping','-n','-c','3','-W','1','-I',f'192.0.2.{idx}',f'192.0.2.{idx+1}'],False)
        for name in peers:
            cname=network+'-'+name
            for cmd in [['swanctl','--list-sas'],['swanctl','--list-certs','--utc'],['swanctl','--list-conns','--raw'],['cat','/tmp/charon.log'],['ip','-s','xfrm','state','list','nokeys']]:run(['docker','exec',cname,*cmd],False)
            run(['docker','inspect','--format','{{.Image}}',cname])
    except Exception as exc:error=str(exc)
    evidence={'schema_version':'csfc-authentication-events/v1','case_ids':[case],'mode':mode,'started_at':started,'ended_at':utc(),'records':records,'error':error,'authorities':list(authorities),'peer_issuer_mapping':{name:{key:path.name for key,path in info.items()} for name,info in peers.items()},'limitations':['These are separate actual PKI trust configurations and finite IKE authentication checks. Enterprise ownership, administrator authority, approved NPE issuance and physical CA placement cannot be inferred from generated certificates.','Certificate arrangements are tested on endpoint pairs; full nested data paths are supplied in separate topology evidence.']}
    (out/'events.json').write_text(json.dumps(evidence,indent=2)+'\n');files=[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in out.iterdir() if p.is_file()]
    (out/'manifest.json').write_text(json.dumps({'schema_version':'csfc-authentication-events/v1','code_sha256':CODE_SHA256,'files':files,'started_at':started,'ended_at':utc()},indent=2)+'\n');print(json.dumps({'mode':mode,'error':error,'records':len(records)}),flush=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args()
    for mode,octet,case in [('local',230,'NET-023-C01'),('enterprise',231,'NET-023-C02'),('central',232,'NET-023-C03')]:run_mode(Path(a.root),mode,octet,case)

if __name__=='__main__':main()
