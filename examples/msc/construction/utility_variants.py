#!/usr/bin/env python3
"""Realize remaining structural and service alternatives with explicit limits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from matrix_lab import Lab
from routing_variants import build

SCRIPT_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
TLS_SERVER=r"""import http.server,ssl,sys
s=http.server.HTTPServer(('0.0.0.0',8443),http.server.SimpleHTTPRequestHandler)
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.minimum_version=ssl.TLSVersion.TLSv1_2;c.load_cert_chain(sys.argv[1]+'/server.pem',sys.argv[1]+'/server.key');c.load_verify_locations(sys.argv[1]+'/ca.pem');c.verify_mode=ssl.CERT_REQUIRED
s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()
"""
TLS_CLIENT=r"""import ssl,socket,json,sys
r={'authenticated_client':sys.argv[3]=='yes'}
try:
 c=ssl.create_default_context(cafile=sys.argv[1]+'/ca.pem')
 if r['authenticated_client']:c.load_cert_chain(sys.argv[1]+'/client.pem',sys.argv[1]+'/client.key')
 with socket.create_connection((sys.argv[2],8443),timeout=4) as sock:
  with c.wrap_socket(sock,server_hostname='server.msc.test') as ss:
   r.update({'version':ss.version(),'cipher':ss.cipher()});ss.sendall(b'GET / HTTP/1.0\r\n\r\n');r['response']=ss.recv(1024).decode();r['outcome']='delivered'
except Exception as exc:r.update({'outcome':'rejected','error':type(exc).__name__+': '+str(exc)})
print(json.dumps(r))
"""

def pki(lab,private):
    private.mkdir(parents=True,exist_ok=False);private.chmod(0o700)
    lab.run(["openssl","genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-384","-out",str(private/"ca.key")])
    lab.run(["openssl","req","-new","-x509","-sha384","-key",str(private/"ca.key"),"-out",str(private/"ca.pem"),"-days","1","-subj","/CN=Utility-Test-CA","-addext","basicConstraints=critical,CA:TRUE"])
    for name,eku in [("server","serverAuth"),("client","clientAuth")]:
        lab.run(["openssl","genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-384","-out",str(private/(name+".key"))])
        lab.run(["openssl","req","-new","-sha384","-key",str(private/(name+".key")),"-out",str(private/(name+".csr")),"-subj","/CN="+name+".msc.test"])
        ext=private/(name+".ext");ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage="+eku+"\nsubjectAltName=DNS:"+name+".msc.test\n")
        lab.run(["openssl","x509","-req","-sha384","-in",str(private/(name+".csr")),"-CA",str(private/"ca.pem"),"-CAkey",str(private/"ca.key"),"-CAcreateserial","-days","1","-extfile",str(ext),"-out",str(private/(name+".pem"))])
        lab.run(["openssl","x509","-in",str(private/(name+".pem")),"-noout","-text"])

def process(lab,node,program,args,processes):
    path=lab.root/(node+"-service.py");path.write_text(program)
    log=lab.root/(node+"-service.log");handle=log.open("w")
    proc=subprocess.Popen(["ip","netns","exec",lab.prefix+node,"python3","-u",str(path),*map(str,args)],stdout=handle,stderr=subprocess.STDOUT,cwd=lab.root)
    processes.append((proc,handle));time.sleep(.2)
    if proc.poll() is not None:raise RuntimeError("service exited at "+node)

def tls(lab,client,server,addr,private,processes):
    pki(lab,private);process(lab,server,TLS_SERVER,[private],processes)
    for authorized in [True,False]:
        r=lab.run(["python3","-c",TLS_CLIENT,str(private),addr,"yes" if authorized else "no"],client)
        value=json.loads(r.stdout)
        lab.probes.append({"id":"mtls-"+str(authorized),"source_device":client,"destination":addr,"expected_result":"delivered" if authorized else "rejected","observed_result":value['outcome'],"observation_id":lab.commands[-1]['id']})

def insert_bridge(lab,a,ai,b,bi,node,aa,ba,zone):
    lab.run(["ip","link","delete",ai],a)
    lab.links=[link for link in lab.links if a+":"+ai not in link['endpoints']]
    lab.node(node,"filtering-bridge",a[-1]);lab.link(a,ai,node,"p1",aa,None,zone);lab.link(node,"p2",b,bi,None,ba,zone)
    lab.run(["ip","link","add","br0","type","bridge"],node)
    for port in ["p1","p2"]:lab.run(["ip","link","set",port,"master","br0"],node)
    lab.run(["ip","link","set","br0","up"],node)
    lab.run(["ebtables","-P","FORWARD","DROP"],node);lab.run(["ebtables","-A","FORWARD","-p","ARP","-j","ACCEPT"],node)

def run_case(base,kind,cases):
    lab=Lab(base/"exports/utility-v1",kind);lab.prefix="tcv2u-";processes=[];error=None
    private=base/"private"/("utility-v1-"+kind);limits=[]
    try:
        if kind in ['central-management','screen-existing','screen-added','combined-inner','combined-gray','alternative-egress']:
            build(lab)
            if kind=='central-management':
                lab.nodes[0]['role']='central-red-administrative-workstation';lab.nodes[-1]['role']='remote-red-managed-component'
                tls(lab,'HA','HB','10.2.0.2',private,processes)
                limits.append('Red remote management crosses TLS and two ESP layers. Enterprise Gray Annex management and personnel administration are not established.')
            if kind=='screen-existing':
                for n in lab.nodes:
                    if n['id'] in ['FA','FB']:n['role']='existing-Black-screening-router'
            if kind=='screen-added':
                insert_bridge(lab,'OA','black','FA','inside','SCREEN','192.0.2.1/30','192.0.2.2/30','black')
                for proto in ['esp']:
                    lab.run(['ebtables','-A','FORWARD','-p','IPv4','--ip-proto',proto,'-j','ACCEPT'],'SCREEN')
                lab.route('OA','192.0.3.1/32','192.0.2.2');lab.route('OA','10.21.0.1/32','192.0.2.2')
                lab.run(['iptables','-F','FORWARD'],'FA');lab.run(['iptables','-P','FORWARD','ACCEPT'],'FA')
            if kind=='combined-inner':
                insert_bridge(lab,'HA','red','IA','red','INNERFW','10.1.0.2/24','10.1.0.1/24','red')
                for src,dst in [('10.1.0.0/24','10.2.0.0/24'),('10.2.0.0/24','10.1.0.0/24')]:lab.run(['ebtables','-A','FORWARD','-p','IPv4','--ip-src',src,'--ip-dst',dst,'-j','ACCEPT'],'INNERFW')
                lab.route('HA','10.2.0.0/24','10.1.0.1');limits.append('Software placement and filtering analogue only; other CP and its approved implementation requirements were not supplied.')
            if kind=='combined-gray':
                insert_bridge(lab,'IA','gray','OA','gray','GRAYFW','10.11.0.1/30','10.11.0.2/30','gray')
                lab.run(['ebtables','-A','FORWARD','-p','IPv4','--ip-proto','esp','-j','ACCEPT'],'GRAYFW')
                lab.route('IA','10.2.0.0/24','10.11.0.2');lab.route('IA','10.21.0.1/32','10.11.0.2')
                limits.append('Additional Gray firewall exists and filters traffic; companion CP compliance and approval remain unavailable.')
            if kind=='alternative-egress':
                for name,role in [('AA','software-alternative-encryptor'),('AB','software-alternative-encryptor'),('ALT','remote-alternative-site')]:lab.node(name,role)
                lab.link('HA','alternative','AA','inside','10.1.10.2/24','10.1.10.1/24','red')
                lab.link('AA','black','AB','black','198.19.0.1/30','198.19.0.2/30','black')
                lab.link('AB','inside','ALT','red','10.3.0.1/24','10.3.0.2/24','red')
                lab.route('HA','10.3.0.0/24','10.1.10.1');lab.route('AA','10.3.0.0/24','198.19.0.2');lab.route('AB','10.1.10.0/24','198.19.0.1');lab.route('ALT','10.1.10.0/24','10.3.0.1')
                lab.esp('AA','AB','198.19.0.1','198.19.0.2','10.1.10.0/24','10.3.0.0/24',300,'alternative-egress')
                lab.ping('HA','10.3.0.2','delivered','alternative-egress-traffic')
                tls(lab,'HA','ALT','10.3.0.2',private,processes)
                limits.append('The separate single-ESP egress is a software analogue. It is not an NSA-certified product or High Assurance encryptor; approval-dependent branches remain partial.')
            lab.ping('HA','10.2.0.2','delivered','nested-data-path-A-B');lab.ping('HB','10.1.0.2','delivered','nested-data-path-B-A')
            lab.state('stable-before');lab.run(['ip','xfrm','state','flush'],'IA');lab.ping('HA','10.2.0.2','no_reply','nested-inner-loss');lab.restore_inner();lab.ping('HA','10.2.0.2','delivered','restored-data-path');lab.state('stable-after')
        elif kind=='management-vlan':
            lab.node('AW','Gray-AW','A');lab.node('TARGET','Outer-management-interface','A');lab.link('AW','eth0','TARGET','eth0',zone='gray-management')
            for idx,node in enumerate(['AW','TARGET']):
                lab.run(['ip','link','add','link','eth0','name','mgmt100','type','vlan','id',100],node);lab.run(['ip','addr','add','10.96.0.%d/30'%(idx+1),'dev','mgmt100'],node);lab.run(['ip','link','set','mgmt100','up'],node)
            tls(lab,'AW','TARGET','10.96.0.2',private,processes);lab.state('stable-after');limits.append('Same-site VLAN plus mutual TLS is observed. The source exception is not interpreted as permission for plaintext management.')
        elif kind=='cds-log':
            for name,role in [('GRAY','Gray-log-producer'),('CDS','software-filtering-relay'),('SIEM','Red-SIEM')]:lab.node(name,role)
            lab.link('GRAY','logs','CDS','gray','10.93.0.1/30','10.93.0.2/30','gray-management');lab.link('CDS','red','SIEM','logs','10.94.0.1/30','10.94.0.2/30','red')
            lab.run(['sysctl','-qw','net.ipv4.ip_forward=0'],'CDS')
            recv="import socket,json;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.94.0.2',5514))\nwhile True:\n data,addr=s.recvfrom(4096);print(json.dumps({'source':addr,'event':json.loads(data)}),flush=True)\n"
            relay="import socket,json;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.93.0.2',5514));out=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\nwhile True:\n data,addr=s.recvfrom(4096)\n try:\n  event=json.loads(data);ok=set(event)=={'device','severity','event'} and event['severity'] in ['warning','critical'] and len(event['event'])<200\n except Exception:ok=False\n print(json.dumps({'accepted':ok,'source':addr}),flush=True)\n if ok:out.sendto(json.dumps(event).encode(),('10.94.0.2',5514))\n"
            process(lab,'SIEM',recv,[],processes);process(lab,'CDS',relay,[],processes)
            for event in [{'device':'Outer-A','severity':'warning','event':'unexpected packet dropped'},{'command':'unauthorized-management'}]:lab.run(['python3','-c','import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(sys.argv[1].encode(),("10.93.0.2",5514))',json.dumps(event)],'GRAY')
            time.sleep(.5);lab.route('SIEM','10.93.0.0/30','10.94.0.1');lab.ping('SIEM','10.93.0.1','no_reply','reverse-unrouted-path');lab.state('stable-after');limits.append('Functional one-way software filtering and Red event receipt do not establish an approved CDS, NCDSMO listing, DoDI8540.01 compliance, or Continuous Monitoring Annex compliance.')
        elif kind in ['time-red','time-gray']:
            zone='red' if kind.endswith('red') else 'gray-management'
            lab.node('CLIENT','Inner' if zone=='red' else 'Outer');lab.node('TIME','time-source');lab.link('CLIENT','inside','TIME','time','10.95.0.1/30','10.95.0.2/30',zone)
            server="import socket,struct,time;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.95.0.2',123))\nwhile True:\n data,addr=s.recvfrom(1024);now=time.time()+2208988800;stamp=struct.pack('!II',int(now),int((now%1)*2**32));r=bytearray(48);r[0]=36;r[1]=2;r[24:32]=data[40:48];r[32:40]=stamp;r[40:48]=stamp;s.sendto(r,addr);print('time response',flush=True)\n"
            process(lab,'TIME',server,[],processes)
            client="import socket,struct,time,json;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);t=time.time();v=t+2208988800;q=bytearray(48);q[0]=35;q[40:48]=struct.pack('!II',int(v),int((v%1)*2**32));s.sendto(q,('10.95.0.2',123));r,addr=s.recvfrom(1024);end=time.time();x,y=struct.unpack('!II',r[40:48]);print(json.dumps({'server':addr,'mode':r[0]&7,'stratum':r[1],'origin_matches':r[24:32]==q[40:48],'round_trip_seconds':end-t,'estimated_offset_seconds':x+y/2**32-2208988800-(t+end)/2,'system_clock_adjusted':False}))"
            for repeat in range(3):lab.run(['python3','-c',client],'CLIENT')
            lab.state('stable-after');limits.append('Finite NTP response and offset samples on the specified inside network. Shared-kernel clocks were not adjusted; trusted time authority and independent-clock synchronization remain unestablished.')
    except Exception as exc:error=str(exc)
    finally:
        for proc,handle in processes:
            proc.terminate()
            try:proc.wait(timeout=3)
            except Exception:proc.kill();proc.wait()
            handle.close()
        (lab.root/'case.json').write_text(json.dumps({'source_case_ids':cases,'script_sha256':SCRIPT_SHA256,'source_specific_limits':limits,'representative_scope':'Actual software structure and recorded traffic; external approval assertions remain unavailable'},indent=2)+'\n')
        lab.finish(error)

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();base=Path(a.root)
    cases={'central-management':['NET-004-C01','NET-027-C02'],'screen-existing':['NET-015-C01'],'screen-added':['NET-015-C02'],'combined-inner':['NET-019-C01'],'combined-gray':['NET-019-C02'],'alternative-egress':['NET-018-C01','NET-027-C01'],'management-vlan':['NET-017-C03'],'cds-log':['NET-014-C01'],'time-red':['NET-026-C01'],'time-gray':['NET-026-C02']}
    for kind,case in cases.items():run_case(base,kind,case)

if __name__=='__main__':main()
