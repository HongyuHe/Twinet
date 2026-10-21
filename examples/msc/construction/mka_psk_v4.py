#!/usr/bin/env python3
"""Collect negotiated MKA PSK behavior without exporting CAKs or SAKs."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time
import argparse

def utc():return datetime.now(timezone.utc).isoformat()

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--root",required=True);args=parser.parse_args()
    base=Path(args.root)
    for mode in ["matching","mismatched"]:
        started=utc();out=base/"exports"/("mka-psk-"+mode+"-v4");out.mkdir(parents=True,exist_ok=False)
        private=base/"private"/("mka-v4-"+mode);private.mkdir(parents=True,exist_ok=True);private.chmod(0o700)
        cak=secrets.token_hex(32);wrong=secrets.token_hex(32);ckn=secrets.token_hex(32)
        records=[];pids=[];nodes=[];error=None
        def run(cmd,check=True):
            begin=utc();r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=20)
            stdout=r.stdout.replace(cak,"[REDACTED_CAK]").replace(wrong,"[REDACTED_CAK]")
            stderr=r.stderr.replace(cak,"[REDACTED_CAK]").replace(wrong,"[REDACTED_CAK]")
            entry={"id":"mka-%03d"%len(records),"command":list(map(str,cmd)),"started_at":begin,"ended_at":utc(),"returncode":r.returncode,"stdout":stdout,"stderr":stderr}
            records.append(entry)
            if check and r.returncode:raise RuntimeError(json.dumps(entry))
            return r
        def ns(name,*cmd,check=True):return run(["ip","netns","exec",name,*cmd],check)
        try:
            for name in ["tcv2k-a","tcv2k-b"]:
                run(["ip","netns","add",name]);nodes.append(name)
                ns(name,"ip","link","set","lo","up")
            run(["ip","link","add","tcv2ka","type","veth","peer","name","tcv2kb"])
            for name,iface,idx in [("tcv2k-a","tcv2ka",0),("tcv2k-b","tcv2kb",1)]:
                run(["ip","link","set",iface,"netns",name]);ns(name,"ip","link","set",iface,"name","eth0");ns(name,"ip","link","set","eth0","up")
                ctrl=private/("ctrl"+str(idx));ctrl.mkdir(exist_ok=True)
                conf=private/("peer"+str(idx)+".conf")
                chosen=wrong if mode=="mismatched" and idx else cak
                conf.write_text(f"ctrl_interface={ctrl}\neapol_version=3\nap_scan=0\nnetwork={{\n key_mgmt=NONE\n eapol_flags=0\n macsec_policy=1\n macsec_integ_only=0\n macsec_replay_protect=1\n macsec_replay_window=0\n macsec_csindex=1\n mka_cak={chosen}\n mka_ckn={ckn}\n mka_priority={idx}\n}}\n")
                conf.chmod(0o600)
                pidfile=private/("peer"+str(idx)+".pid")
                ns(name,str(base/"hostap/wpa_supplicant-2.12/wpa_supplicant/wpa_supplicant"),"-B","-D","macsec_linux","-i","eth0","-c",str(conf),"-P",str(pidfile),"-f",str(private/("peer"+str(idx)+".log")))
                for attempt in range(20):
                    if pidfile.exists():break
                    time.sleep(.1)
                if not pidfile.exists():raise RuntimeError("wpa_supplicant did not create its expected PID file")
                pid=int(pidfile.read_text());os.kill(pid,0);pids.append(pid)
            time.sleep(7)
            for idx,name in enumerate(nodes):
                ns(name,"wpa_cli","-p",str(private/("ctrl"+str(idx))),"-i","eth0","status",check=False)
                ns(name,"ip","-s","macsec","show",check=False)
                ports=json.loads(ns(name,"ip","-j","-d","link").stdout)
                mac=next((p["ifname"] for p in ports if p.get("linkinfo",{}).get("info_kind")=="macsec"),None)
                if mac:
                    ns(name,"ip","addr","add",f"10.91.0.{idx+1}/30","dev",mac)
                    ns(name,"ip","link","set",mac,"up")
            if mode=="matching":ns(nodes[0],"ping","-n","-c","3","-W","1","10.91.0.2",check=False)
            else:ns(nodes[0],"ping","-n","-c","3","-W","1","10.91.0.2",check=False)
            for idx,name in enumerate(nodes):
                ns(name,"ip","-s","macsec","show",check=False)
                run(["cat",str(private/("peer"+str(idx)+".log"))],False)
        except Exception as exc:error=str(exc)
        finally:
            for idx in range(2):
                log=private/("peer"+str(idx)+".log")
                if log.exists():run(["cat",str(log)],False)
            for pid in pids:
                try:os.kill(pid,signal.SIGTERM)
                except ProcessLookupError:pass
            time.sleep(.2)
            for name in nodes:run(["ip","netns","delete",name],False)
        evidence={"schema_version":"csfc-authentication-events/v1","case_ids":["NET-023-C05"],"group_ids":["RG-024","RG-025","RG-027","RG-028"],"started_at":started,"ended_at":utc(),"authentication":"MKA PSK","mode":mode,"public_settings":{"cak_bits":256,"ckn_hex":ckn,"ckn_bits":256,"mka_priorities":[0,1],"macsec_cipher_requested":"GCM-AES-256","replay_window":0,"confidentiality_offset":0,"fallback_cak_configured":False},"records":records,"error":error,"limitations":["Test CAK generated by Python secrets, with no NSA KGS approval or physically secure provisioning evidence.","Standalone peer-authentication experiment; nested layering is established in separate layer-pairing runs."]}
        (out/"events.json").write_text(json.dumps(evidence,indent=2)+"\n")
        (out/"manifest.json").write_text(json.dumps({"schema_version":"csfc-authentication-events/v1","code_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"files":[{"path":"events.json","sha256":hashlib.sha256((out/"events.json").read_bytes()).hexdigest(),"bytes":(out/"events.json").stat().st_size}]},indent=2)+"\n")
        print(json.dumps({"mode":mode,"error":error,"records":len(records)}),flush=True)
if __name__=="__main__":main()
