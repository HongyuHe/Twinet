#!/usr/bin/env python3
"""Exercise routing alternatives through complete nested test data paths."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import time
from matrix_lab import Lab,CODE_SHA256

EXTENSION_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def build(lab):
    red=gray=black=4
    for n,r in [("HA","host"),("IA","inner"),("OA","outer"),("FA","outer-firewall"),("FB","outer-firewall"),("OB","outer"),("IB","inner"),("HB","host")]:
        lab.node(n,r,n[-1])
    rednets=["10.1.0.","10.2.0."] if red==4 else ["fd10:1::","fd10:2::"]
    graynets=["10.11.0.","10.21.0."] if gray==4 else ["fd20:1::","fd20:2::"]
    blacknets=["192.0.2.","192.0.3."] if black==4 else ["fd30:1::","fd30:2::"]
    rp=24 if red==4 else 64;gp=30 if gray==4 else 64;bp=30 if black==4 else 64
    middle="198.51.100." if black==4 else "fd30:3::"
    for site,idx in [("A",0),("B",1)]:
        rn=rednets[idx];gn=graynets[idx];bn=blacknets[idx];peer=1-idx
        lab.link("H"+site,"red","I"+site,"red",rn+"2/"+str(rp),rn+"1/"+str(rp),"red")
        lab.link("I"+site,"gray","O"+site,"gray",gn+"1/"+str(gp),gn+"2/"+str(gp),"gray")
        lab.link("O"+site,"black","F"+site,"inside",bn+"1/"+str(bp),bn+"2/"+str(bp),"black")
        lab.route("H"+site,rednets[peer]+"0/"+str(rp),rn+"1")
        lab.route("I"+site,rednets[peer]+"0/"+str(rp),gn+"2") if red==gray else lab.run(["ip","route","replace",rednets[peer]+"0/"+str(rp),"dev","gray"],"I"+site)
        lab.route("I"+site,graynets[peer]+"1/"+str(32 if gray==4 else 128),gn+"2")
        lab.route("O"+site,graynets[peer]+"1/"+str(32 if gray==4 else 128),bn+"2") if gray==black else lab.run(["ip","route","replace",graynets[peer]+"1/"+str(32 if gray==4 else 128),"dev","black"],"O"+site)
        lab.route("O"+site,blacknets[peer]+"1/"+str(32 if black==4 else 128),bn+"2")
    lab.link("FA","outside","FB","outside",middle+"1/"+str(bp),middle+"2/"+str(bp),"black")
    lab.route("FA",blacknets[1]+"0/"+str(bp),middle+"2")
    lab.route("FB",blacknets[0]+"0/"+str(bp),middle+"1")
    lab.esp("IA","IB",graynets[0]+"1",graynets[1]+"1",rednets[0]+"0/"+str(rp),rednets[1]+"0/"+str(rp),100,"inner")
    lab.esp("OA","OB",blacknets[0]+"1",blacknets[1]+"1",graynets[0]+"1/"+str(32 if gray==4 else 128),graynets[1]+"1/"+str(32 if gray==4 else 128),200,"outer")
    for node,family,inside,outside,reqid in [("IA",red,"red","gray",100),("IB",red,"red","gray",100),("OA",gray,"gray","black",200),("OB",gray,"gray","black",200)]:
        ipt="iptables" if family==4 else "ip6tables"
        lab.run([ipt,"-P","FORWARD","DROP"],node)
        lab.run([ipt,"-A","FORWARD","-i",inside,"-o",outside,"-m","policy","--dir","out","--pol","ipsec","--reqid",reqid,"-j","ACCEPT"],node)
        lab.run([ipt,"-A","FORWARD","-i",outside,"-o",inside,"-m","policy","--dir","in","--pol","ipsec","--reqid",reqid,"-j","ACCEPT"],node)
    for node in ["FA","FB"]:
        ipt="iptables" if black==4 else "ip6tables"
        lab.run([ipt,"-P","FORWARD","DROP"],node)
        for s,d in [(blacknets[0]+"1",blacknets[1]+"1"),(blacknets[1]+"1",blacknets[0]+"1")]:
            lab.run([ipt,"-A","FORWARD","-s",s,"-d",d,"-p","esp","-j","ACCEPT"],node)

def gre(lab,zone):
    ends=["FA","FB"] if zone=="black" else ["HA","HB"]
    addresses=["198.51.100.1","198.51.100.2"] if zone=="black" else ["10.1.0.2","10.2.0.2"]
    for idx,node in enumerate(ends):
        lab.run(["ip","tunnel","add","gre1","mode","gre","local",addresses[idx],"remote",addresses[1-idx],"ttl",64],node)
        lab.run(["ip","addr","add","198.18.0.%d/30"%(idx+1),"dev","gre1"],node)
        lab.run(["ip","link","set","gre1","mtu",1200,"up"],node)
    return ends

def exercise(root,protocol,zone):
    lab=Lab(root,"routing-"+protocol+"-"+zone);pids=[];error=None
    try:
        build(lab)
        ends=gre(lab,zone) if protocol=="gre" or zone=="red" else ["FA","FB"]
        if protocol=="gre":
            if zone=="black":
                lab.route("FA","192.0.3.0/30","198.18.0.2")
                lab.route("FB","192.0.2.0/30","198.18.0.1")
            else:lab.ping("HA","198.18.0.2","delivered","red-GRE-over-nested-ESP")
        if protocol=="mpls":
            for mod in ["mpls_router","mpls_iptunnel"]:lab.run(["modprobe",mod])
            for idx,node in enumerate(ends):
                iface="outside" if zone=="black" else "gre1"
                lab.run(["sysctl","-qw","net.mpls.platform_labels=1000","net.mpls.conf."+iface+".input=1"],node)
                destination="192.0.%d.0/30"%(3-idx) if zone=="black" else "172.16.%d.1/32"%(2-idx)
                via="198.51.100.%d"%(2-idx) if zone=="black" else "198.18.0.%d"%(2-idx)
                if zone=="red":lab.run(["ip","addr","add","172.16.%d.1/32"%(idx+1),"dev","lo"],node)
                lab.run(["ip","route","replace",destination,"encap","mpls",101+idx,"via",via,"dev",iface],node)
                if zone=="black":lab.run(["ip","-f","mpls","route","add",102-idx,"via","inet","192.0.%d.1"%(2+idx),"dev","inside"],node)
                else:lab.run(["ip","-f","mpls","route","add",102-idx,"dev","lo"],node)
                lab.run(["ip","-f","mpls","route"],node)
            if zone=="red":lab.ping("HA","172.16.2.1","delivered","red-MPLS-over-GRE-over-nested-ESP")
        if protocol=="ospf":
            for idx,node in enumerate(ends):
                directory=Path("/users/hy/tdn-evidence-v2/frr-runtime")/(lab.name+"-"+node);directory.mkdir(parents=True,exist_ok=True)
                ifname="outside" if zone=="black" else "gre1"
                network="198.51.100.0/30" if zone=="black" else "198.18.0.0/30"
                local="192.0.%d.0/30"%(2+idx) if zone=="black" else "172.16.%d.1/32"%(idx+1)
                remote="192.0.%d.0/30"%(3-idx)
                if zone=="black":lab.run(["ip","route","del",remote],node)
                else:lab.run(["ip","addr","add",local,"dev","lo"],node)
                config="hostname "+node+"\nlog stdout\ninterface "+ifname+"\n ip ospf network point-to-point\n ip ospf hello-interval 1\n ip ospf dead-interval 4\nrouter ospf\n ospf router-id 1.1.1.%d\n network %s area 0\n network %s area 0\n"%(idx+1,network,local)
                (directory/"ospfd.conf").write_text(config);(directory/"zebra.conf").write_text("hostname "+node+"\nlog stdout\n")
                (lab.root/("ospfd-"+node+".conf")).write_text(config)
                lab.run(["chown","-R","frr:frr",str(directory)])
                for daemon in ["zebra","ospfd"]:
                    pid=directory/(daemon+".pid")
                    lab.run(["/usr/lib/frr/"+daemon,"-d","-u","frr","-g","frr","-f",str(directory/(daemon+".conf")),"-i",str(pid),"-z",str(directory/"zserv.api"),"--vty_socket",str(directory)],node)
                    if pid.exists():pids.append(int(pid.read_text()))
            time.sleep(6)
            for node in ends:
                directory=Path("/users/hy/tdn-evidence-v2/frr-runtime")/(lab.name+"-"+node)
                lab.run(["vtysh","--vty_socket",str(directory),"-c","show ip ospf neighbor json"],node,False)
                lab.run(["vtysh","--vty_socket",str(directory),"-c","show ip route json"],node,False)
            if zone=="red":lab.ping("HA","172.16.2.1","delivered","OSPF-learned-Red-route")
        lab.ping("HA","10.2.0.2","delivered","nested-useful-traffic")
        lab.ping("HB","10.1.0.2","delivered","nested-reverse-traffic")
        lab.state("stable-before")
        lab.run(["ip","xfrm","state","flush"],"IA")
        lab.ping("HA","10.2.0.2","no_reply","nested-inner-loss")
        lab.restore_inner();lab.ping("HA","10.2.0.2","delivered","restored-nested-traffic")
        lab.state("stable-after")
    except Exception as exc:error=str(exc)
    finally:
        for pid in pids:
            try:os.kill(pid,signal.SIGTERM)
            except ProcessLookupError:pass
        (lab.root/"variant.json").write_text(json.dumps({"protocol":protocol,"zone":zone,"source_case_id":"NET-021-C%02d"%({"gre":0,"mpls":2,"ospf":4}[protocol]+(1 if zone=="black" else 2)),"extension_sha256":EXTENSION_SHA256,"base_sha256":CODE_SHA256,"limitations":["AO approval unavailable","GRE is an explicit MPLS/OSPF carrier for Red alternatives","All nodes share a physical host; routing protocols do not run on Outer encryptors"]},indent=2)+"\n")
        lab.finish(error)

def main():
    p=argparse.ArgumentParser();p.add_argument("--output",required=True);a=p.parse_args()
    for protocol in ["ospf"]:
        for zone in ["black","red"]:exercise(a.output,protocol,zone)

if __name__=="__main__":main()
