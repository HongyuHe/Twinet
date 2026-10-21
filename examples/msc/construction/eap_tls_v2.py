#!/usr/bin/env python3
"""Central RADIUS EAP-TLS and negotiated MACsec, with reversed peer roles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import time
from matrix_lab import Lab

SCRIPT_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",required=True);a=p.parse_args();base=Path(a.root)
    for reverse in [False,True]:
        name="eap-tls-"+("reverse" if reverse else "forward")+"-v2"
        lab=Lab(base/"exports",name);lab.prefix="tcv2e-";procs=[];handles=[];error=None
        private=base/"private"/name;private.mkdir(parents=True,exist_ok=False);private.chmod(0o700)
        radius_secret=secrets.token_hex(24);lab.keyvalues.append(radius_secret)
        auth="P1" if reverse else "P0";supp="P0" if reverse else "P1"
        def launch(node,exe,conf):
            log=private/(node+".log");h=log.open("w");handles.append(h)
            proc=__import__("subprocess").Popen(["ip","netns","exec",lab.prefix+node,str(exe),str(conf)],stdout=h,stderr=__import__("subprocess").STDOUT)
            procs.append(proc);time.sleep(.5)
            if proc.poll() is not None:raise RuntimeError(node+" daemon exited "+str(proc.returncode))
        try:
            for n,r in [("P0","MACsec-peer"),("P1","MACsec-peer"),("AS","central-authentication-server")]:lab.node(n,r,"central" if n in [auth,"AS"] else "remote")
            lab.link("P0","eth0","P1","eth0",zone="gray-data")
            lab.link(auth,"control","AS","eth0","10.88.0.1/30","10.88.0.2/30",zone="gray-management")
            for n in [auth,supp,"AS"]:lab.run(["sysctl","-qw","net.ipv4.ip_forward=0"],n)
            lab.run(["openssl","genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-384","-out",str(private/"ca.key")])
            lab.run(["openssl","req","-new","-x509","-sha384","-key",str(private/"ca.key"),"-out",str(private/"ca.pem"),"-days","1","-subj","/CN=EAP-Test-CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign"])
            for who,eku in [("as","serverAuth"),("peer","clientAuth")]:
                lab.run(["openssl","genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-384","-out",str(private/(who+".key"))])
                lab.run(["openssl","req","-new","-sha384","-key",str(private/(who+".key")),"-out",str(private/(who+".csr")),"-subj","/CN="+who+".msc.test"])
                (private/(who+".ext")).write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage="+eku+"\nsubjectAltName=DNS:"+who+".msc.test\n")
                lab.run(["openssl","x509","-req","-sha384","-in",str(private/(who+".csr")),"-CA",str(private/"ca.pem"),"-CAkey",str(private/"ca.key"),"-CAcreateserial","-days","1","-extfile",str(private/(who+".ext")),"-out",str(private/(who+".pem"))])
                lab.run(["openssl","x509","-in",str(private/(who+".pem")),"-noout","-text"])
            (private/"clients").write_text("10.88.0.1 "+radius_secret+"\n");(private/"users").write_text('"peer.msc.test" TLS\n')
            server="driver=none\ninterface=eth0\nssid=eap-as\neap_server=1\neap_user_file="+str(private/"users")+"\nca_cert="+str(private/"ca.pem")+"\nserver_cert="+str(private/"as.pem")+"\nprivate_key="+str(private/"as.key")+"\nradius_server_clients="+str(private/"clients")+"\nradius_server_auth_port=1812\nlogger_stdout=-1\nlogger_stdout_level=1\n"
            host="driver=macsec_linux\ninterface=eth0\nssid=msc-auth\nieee8021x=1\nuse_pae_group_addr=1\neap_server=0\nown_ip_addr=10.88.0.1\nnas_identifier="+auth+"\nauth_server_addr=10.88.0.2\nauth_server_port=1812\nauth_server_shared_secret="+radius_secret+"\nmacsec_policy=1\nmacsec_integ_only=0\nmacsec_csindex=1\nmacsec_replay_protect=1\nmacsec_replay_window=0\nmka_priority=0\nlogger_stdout=-1\nlogger_stdout_level=1\n"
            client="ap_scan=0\neapol_version=3\nnetwork={\n key_mgmt=IEEE8021X\n eap=TLS\n identity=\"peer.msc.test\"\n ca_cert=\""+str(private/"ca.pem")+"\"\n client_cert=\""+str(private/"peer.pem")+"\"\n private_key=\""+str(private/"peer.key")+"\"\n domain_match=\"as.msc.test\"\n eapol_flags=0\n macsec_policy=1\n macsec_csindex=1\n macsec_replay_protect=1\n macsec_replay_window=0\n mka_priority=1\n}\n"
            for who,conf in [("AS",server),(auth,host),(supp,client)]:
                (private/(who+".conf")).write_text(conf)
                (lab.root/(who+".conf.public")).write_text(conf.replace(radius_secret,"[REDACTED_RADIUS_SECRET]"))
            hostap=base/"hostap/hostapd-2.12/hostapd/hostapd"
            launch("AS",hostap,private/"AS.conf");launch(auth,hostap,private/(auth+".conf"))
            log=private/(supp+".log");h=log.open("w");handles.append(h)
            proc=__import__("subprocess").Popen(["ip","netns","exec",lab.prefix+supp,str(base/"hostap/wpa_supplicant-2.12/wpa_supplicant/wpa_supplicant"),"-Dmacsec_linux","-ieth0","-c",str(private/(supp+".conf"))],stdout=h,stderr=__import__("subprocess").STDOUT);procs.append(proc)
            time.sleep(12)
            for idx,node in enumerate(["P0","P1"]):
                lab.run(["ip","-s","macsec","show"],node)
                ports=json.loads(lab.run(["ip","-j","-d","link"],node).stdout)
                iface=next((i["ifname"] for i in ports if i.get("linkinfo",{}).get("info_kind")=="macsec"),None)
                if not iface:raise RuntimeError("No MACsec interface at "+node)
                lab.run(["ip","addr","add","10.92.0.%d/30"%(idx+1),"dev",iface],node);lab.run(["ip","link","set",iface,"up"],node)
            lab.ping("P0","10.92.0.2","delivered","EAP-derived-MKA-traffic")
            lab.state("stable-after")
        except Exception as exc:error=str(exc)
        finally:
            for proc in procs:
                proc.terminate()
                try:proc.wait(timeout=3)
                except Exception:proc.kill();proc.wait()
            for h in handles:h.close()
            for log in private.glob("*.log"):lab.run(["cat",str(log)],check=False)
            (lab.root/"case.json").write_text(json.dumps({"source_case_id":"NET-023-C04","authentication":"EAP-TLS via central RADIUS AS with negotiated MKA","authenticator":auth,"supplicant":supp,"script_sha256":SCRIPT_SHA256,"limitations":["Roles are reversed in separate realizations; simultaneous dual-role operation remains unestablished","Test CA and RADIUS secret do not establish external PKI approval","AS has one Gray management attachment and no Red attachment"]},indent=2)+"\n")
            lab.finish(error)

if __name__=="__main__":main()
