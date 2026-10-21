#!/usr/bin/env python3
"""Exercise bounded HTTP CRL and OCSP exceptions on the Gray data path."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import time
from matrix_lab import Lab
from routing_variants import build
from utility_variants import pki,insert_bridge,process

CODE_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();base=Path(a.root)
 for mode in ['crl','ocsp']:
  lab=Lab(base/'exports','http-'+mode+'-v1');lab.prefix='tcv2r-';procs=[];error=None;private=base/'private'/('http-'+mode+'-v1')
  try:
   build(lab);insert_bridge(lab,'IA','gray','OA','gray','GF','10.11.0.1/30','10.11.0.2/30','gray')
   lab.route('IA','10.2.0.0/24','10.11.0.2');lab.route('IA','10.21.0.1/32','10.11.0.2')
   lab.node('SERVER','HTTP-'+mode.upper());lab.link('OA','service','SERVER','gray','10.12.0.1/24','10.12.0.2/24','gray-data')
   lab.run(['ip','addr','add','10.12.0.99/24','dev','gray'],'SERVER');lab.route('IA','10.12.0.0/24','10.11.0.2');lab.route('SERVER','10.11.0.0/30','10.12.0.1')
   lab.run(['ebtables','-A','FORWARD','-p','IPv4','--ip-proto','esp','-j','ACCEPT'],'GF')
   for src,dst,port,flag in [('10.11.0.1','10.12.0.2',80,'--ip-dport'),('10.12.0.2','10.11.0.1',80,'--ip-sport')]:
    lab.run(['ebtables','-A','FORWARD','-p','IPv4','--ip-proto','tcp','--ip-src',src,'--ip-dst',dst,flag,port,'-j','ACCEPT'],'GF')
    lab.run(['iptables','-A','FORWARD','-s',src,'-d',dst,'-p','tcp','--dport' if flag=='--ip-dport' else '--sport',port,'-j','ACCEPT'],'OA')
   pki(lab,private);(private/'newcerts').mkdir();(private/'serial').write_text('2000\n');(private/'crlnumber').write_text('2000\n')
   serial=lab.run(['openssl','x509','-in',str(private/'client.pem'),'-noout','-serial']).stdout.strip().split('=')[1]
   date=lab.run(['openssl','x509','-in',str(private/'client.pem'),'-noout','-enddate']).stdout.strip().split('=')[1];expiry=datetime.strptime(date,'%b %d %H:%M:%S %Y %Z').strftime('%y%m%d%H%M%SZ')
   (private/'index').write_text('V\t'+expiry+'\t\t'+serial+'\tunknown\t/CN=client.msc.test\n')
   cnf='[ca]\ndefault_ca=main\n[main]\ndatabase='+str(private/'index')+'\nnew_certs_dir='+str(private/'newcerts')+'\ncertificate='+str(private/'ca.pem')+'\nprivate_key='+str(private/'ca.key')+'\nserial='+str(private/'serial')+'\ncrlnumber='+str(private/'crlnumber')+'\ndefault_md=sha384\ndefault_crl_days=1\ncrl_extensions=crlext\npolicy=policy\n[crlext]\nauthorityKeyIdentifier=keyid:always\n[policy]\ncommonName=supplied\n';(private/'openssl.cnf').write_text(cnf)
   public=private/'public';public.mkdir()
   def start_ocsp():
    log=(private/'ocsp.log').open('a');proc=subprocess.Popen(['ip','netns','exec',lab.prefix+'SERVER','openssl','ocsp','-index',str(private/'index'),'-CA',str(private/'ca.pem'),'-rsigner',str(private/'ca.pem'),'-rkey',str(private/'ca.key'),'-port','80','-nmin','5','-ignore_err'],stdout=log,stderr=log);procs.append((proc,log));time.sleep(.3)
   if mode=='crl':
    lab.run(['openssl','ca','-gencrl','-config',str(private/'openssl.cnf'),'-out',str(public/'current.crl')]);process(lab,'SERVER','import http.server,sys;from functools import partial;http.server.HTTPServer(("0.0.0.0",80),partial(http.server.SimpleHTTPRequestHandler,directory=sys.argv[1])).serve_forever()',[public],procs)
   else:start_ocsp()
   for phase in ['good','revoked']:
    if phase=='revoked':
     lab.run(['openssl','ca','-config',str(private/'openssl.cnf'),'-revoke',str(private/'client.pem')])
     if mode=='crl':lab.run(['openssl','ca','-gencrl','-config',str(private/'openssl.cnf'),'-out',str(public/'current.crl')])
     else:
      proc,log=procs[-1];proc.terminate();proc.wait(timeout=3);log.close();procs.pop();start_ocsp()
    if mode=='crl':
     target=lab.root/(phase+'.crl');lab.run(['curl','--noproxy','*','--fail','--max-time','4','http://10.12.0.2/current.crl','-o',str(target)],'IA')
     lab.run(['openssl','crl','-in',str(target),'-noout','-text'])
     result=lab.run(['openssl','verify','-CAfile',str(private/'ca.pem'),'-CRLfile',str(target),'-crl_check',str(private/'client.pem')],'IA',False)
     lab.probes.append({'id':'CRL-'+phase,'expected_result':'valid' if phase=='good' else 'revoked','observed_result':'valid' if result.returncode==0 else 'revoked' if 'certificate revoked' in result.stderr else 'error','observation_id':lab.commands[-1]['id']})
    else:
     result=lab.run(['openssl','ocsp','-issuer',str(private/'ca.pem'),'-cert',str(private/'client.pem'),'-url','http://10.12.0.2','-CAfile',str(private/'ca.pem'),'-resp_text'],'IA',False)
     lab.probes.append({'id':'OCSP-'+phase,'expected_result':phase,'observed_result':'revoked' if 'Cert Status: revoked' in result.stdout and 'Response verify OK' in result.stderr else 'good' if 'Cert Status: good' in result.stdout and 'Response verify OK' in result.stderr else 'error','observation_id':lab.commands[-1]['id']})
   lab.run(['ebtables','-L','--Lc'],'GF');lab.run(['curl','--noproxy','*','--max-time','2','http://10.12.0.99/current.crl'],'IA',False);lab.run(['ebtables','-L','--Lc'],'GF')
   lab.ping('HA','10.2.0.2','delivered','nested-data-path-still-useful');lab.state('stable-after')
   for name in ['ca.pem','client.pem']:(lab.root/name).write_bytes((private/name).read_bytes())
  except Exception as exc:error=str(exc)
  finally:
   for proc,handle in procs:
    proc.terminate()
    try:proc.wait(timeout=3)
    except Exception:proc.kill();proc.wait()
    handle.close()
   if (private/'ocsp.log').exists():lab.run(['cat',str(private/'ocsp.log')],check=False)
   (lab.root/'case.json').write_text(json.dumps({'source_case_ids':['NET-025-C01' if mode=='crl' else 'NET-025-C02'],'code_sha256':CODE_SHA256,'limitations':['Finite HTTP revocation retrieval, signed response verification and bounded firewall exception. General certificate lifecycle, approved CA authority and all-time revocation checking remain unavailable.','Negative HTTP request records its actual timeout and bridge drop counters; timeout alone is not labeled successful blocking.']},indent=2)+'\n');lab.finish(error)

if __name__=='__main__':main()
