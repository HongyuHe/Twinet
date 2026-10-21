#!/usr/bin/env python3
"""Collect fresh, allowlisted MSC evidence without reading secret files."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import time


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--spec",required=True)
    p.add_argument("--output",required=True)
    p.add_argument("--configuration-id",required=True)
    p.add_argument("--case-ids",default="")
    p.add_argument("--deployer-sha256",default="unavailable")
    p.add_argument("--confirm-loaded-config",action="store_true")
    p.add_argument("--platform-interface-names",default="")
    p.add_argument("--probe-expectations")
    a=p.parse_args()
    spec=json.loads(Path(a.spec).read_text())
    probe_policy=json.loads(Path(a.probe_expectations).read_text()) if a.probe_expectations else {}
    root=Path(a.output)
    root.mkdir(parents=True,exist_ok=False)
    (root/"raw").mkdir()
    started=utc()
    sid=root.name
    observations=[]
    failures=[]
    devices={d["id"]:d for d in spec["devices"]}
    def container(d):
        return d["id"] if spec["version"]==2 else "twinet-"+spec["name"]+"-"+d["id"].lower()
    def observe(device,kind,command,timeout=20):
        oid="obs-%05d"%(len(observations)+1)
        cmd=["docker","exec",container(devices[device]),*command] if device else command
        begin=utc()
        try:
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
            rc=r.returncode
            body=r.stdout
            stderr=r.stderr
        except subprocess.TimeoutExpired as e:
            rc=124
            body=(e.stdout or b"").decode() if isinstance(e.stdout,bytes) else (e.stdout or "")
            stderr="collector timeout"
        if kind=="loaded-public-config" and re.search(r"secrets\s*\{",body):
            raise RuntimeError("Refused secret-bearing configuration")
        if "PRIVATE KEY-----" in body or "PRIVATE KEY-----" in stderr:
            raise RuntimeError("Refused secret material in allowlisted observation")
        raw={"stdout":body,"stderr":stderr}
        data=(json.dumps(raw,indent=2)+"\n").encode()
        path="raw/"+oid+".json"
        (root/path).write_bytes(data)
        ob={"id":oid,"collector":"construction-collect/v1","command":cmd,"device_id":device,"kind":kind,"started_at":begin,"ended_at":utc(),"returncode":rc,"raw_path":path,"raw_sha256":digest(data),"sanitizer":"xfrm-nokeys-and-public-allowlist","parse_status":"parsed" if rc==0 else "failed"}
        observations.append(ob)
        if rc:
            failures.append({"observation_id":oid,"kind":kind,"returncode":rc})
        return body,ob
    def parsed(body):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None
    def fact(oid,did,status="observed",**kw):
        return {"id":oid,"device_id":did,"status":status,**kw}
    snapshot={"schema_version":"csfc-evidence/v1","snapshot_id":sid,"scope":{"expected_device_ids":list(devices),"expected_interface_ids":[d["id"]+":"+i["name"] for d in spec["devices"] for i in d["interfaces"]]+[d["id"]+":lo" for d in spec["devices"]]+[d["id"]+":br0" for d in spec["devices"] if d["role"]=="switch"],"source_case_ids":a.case_ids.split(",") if a.case_ids else [],"management_applicability":"optional_disabled"},"devices":[],"interfaces":[],"links":[],"routes":[],"filters":[],"tunnels":[],"credentials":[],"probes":[],"management":{"profile":"none","applicability":"optional_disabled","records":[],"failures":[]},"observations":observations,"limitations":[]}
    snapshot["scope"]["expected_interface_ids"].extend(d["id"]+":"+name for d in spec["devices"] for name in a.platform_interface_names.split(",") if name)
    snapshot["scope"]["expected_interface_ids"].extend(d["id"]+":ovs-system" for d in spec["devices"] if spec["version"]==2 and d["role"]=="switch")
    snapshot["native_runtime"]=[]
    native_commands={}
    snapshot["scope"]["platform_interface_names"]=a.platform_interface_names.split(",") if a.platform_interface_names else []
    snapshot["scope"]["probe_policy_declaration"]=probe_policy
    _,hostob=observe(None,"software",["sh","-c","uname -a; docker version --format {{.Server.Version}}; date -u +%FT%TZ"])
    def stable(kind,body):
        if kind.startswith("filters"):
            return "\n".join(re.sub(r"\[\d+:\d+\]", "[COUNTERS]", line) for line in body.splitlines() if not line.startswith("#"))
        if kind in ["interfaces","bridge-links","bridge-vlans","namespace-peers"]:
            value=parsed(body)
            if kind=="interfaces" and isinstance(value,list):
                for interface in value:
                    data=interface.get("linkinfo",{}).get("info_data",{})
                    for timer in ["gc_timer","hello_timer","tcn_timer","topology_change_timer"]:data.pop(timer,None)
            if isinstance(value,list):return json.dumps(sorted(value,key=lambda item:json.dumps(item,sort_keys=True)),sort_keys=True)
        if kind.startswith("native-ovs-") or kind=="native-frr-running":
            value=parsed(body)
            if isinstance(value,dict) and "data" in value:
                value["data"]=sorted(value["data"],key=lambda row:json.dumps(row,sort_keys=True));return json.dumps(value,sort_keys=True)
            return "\n".join(line for line in body.splitlines() if not line.startswith(("OFPST_","OFPMP_")))
        if kind=="device-identity":
            value=parsed(body) or {}
            return json.dumps({"Id":value.get("Id"),"Image":value.get("Image"),"State":{k:value.get("State",{}).get(k) for k in ["Pid","StartedAt","Running"]}},sort_keys=True)
        return body
    inspected={}
    aliases={}
    nsids={}
    for did,d in devices.items():
        body,ob=observe(None,"container-inspect",["docker","inspect","--format","{{json .}}",container(d)])
        info=parsed(body) or {}
        inspected[did]=(info,ob)
        alias="tcobs-"+did
        if os.path.exists("/var/run/netns/"+alias):
            raise RuntimeError("Refusing existing namespace alias "+alias)
        _,attached=observe(None,"namespace-alias",["ip","netns","attach",alias,str(info.get("State",{}).get("Pid",0))])
        if attached["returncode"]==0:aliases[did]=alias
    for did in devices:
        body,ob=observe(None,"namespace-peer-identities",["nsenter","-t",str(inspected[did][0]["State"]["Pid"]),"-n","ip","-j","netns","list-id"])
        nsids[did]=(parsed(body) or [],ob)
    pre={}
    for did in devices:
        pre[did+"/device-identity"]=digest(stable("device-identity",json.dumps(inspected[did][0])).encode())
        pre[did+"/namespace-peers"]=digest(stable("namespace-peers",json.dumps(nsids[did][0])).encode())
    observed={}
    commands={"interfaces":["ip","-j","-d","address","show"],"routes4":["ip","-j","-4","route","show","table","all"],"routes6":["ip","-j","-6","route","show","table","all"],"filters4":["iptables-save","-t","filter"],"filters6":["ip6tables-save","-t","filter"],"policies":["ip","xfrm","policy","list"],"states":["ip","-s","xfrm","state","list","nokeys"],"forwarding":["sysctl","net.ipv4.ip_forward","net.ipv6.conf.all.forwarding"],"bridge-links":["bridge","-j","link","show"],"bridge-vlans":["bridge","-j","vlan","show"]}
    for did,d in devices.items():
        rows={}
        for kind,cmd in commands.items():
            body,ob=observe(did,kind,cmd)
            rows[kind]=(body,ob)
            if kind in ["routes4","routes6","filters4","filters6","policies","interfaces","bridge-links","bridge-vlans"]:
                pre[did+"/"+kind]=digest(stable(kind,body).encode())
        keys=["net.ipv6.conf."+name+"."+setting for name in ["all","default","lo"]+[i["name"] for i in d["interfaces"]] for setting in ["disable_ipv6","forwarding"]]
        rows["ipv6-settings"]=observe(did,"ipv6-settings",["sysctl",*keys])
        rows["nft-hooks"]=observe(None,"nft-hooks",["nsenter","-t",str(inspected[did][0]["State"]["Pid"]),"-n","nft","-j","list","ruleset"])
        if spec["version"]==2:
            cmds={}
            if d["role"]=="switch":
                for table,columns in {"Bridge":"_uuid,name,ports,controller,fail_mode,datapath_type,other_config","Port":"_uuid,name,interfaces,tag,trunks,vlan_mode,bond_mode,other_config","Interface":"_uuid,name,type,ofport,options,external_ids,admin_state,link_state,mtu,mtu_request,ifindex,mac_in_use,error","Controller":"_uuid,target,is_connected,connection_mode"}.items():cmds["native-ovs-"+table.lower()]=["ovs-vsctl","--format=json","--columns="+columns,"list",table]
                cmds.update({"native-ovs-flows":["ovs-ofctl","-O","OpenFlow13","--no-stats","dump-flows","br0"],"native-ovs-groups":["ovs-ofctl","-O","OpenFlow13","dump-groups","br0"],"native-ovs-meters":["ovs-ofctl","-O","OpenFlow13","dump-meters","br0"]})
            if d["role"] in ["transport","firewall","gray-firewall"]:
                cmds.update({"native-frr-running":["vtysh","-c","show running-config"],"native-frr-routes":["vtysh","-c","show ip route json"],"native-frr-ospf-neighbors":["vtysh","-c","show ip ospf neighbor json"],"native-frr-ospf-interfaces":["vtysh","-c","show ip ospf interface json"]})
                control,control_ob=observe(None,"native-control-inspect",["docker","inspect","--format","{{json .}}",container(d)+"-frr"])
                cinfo=parsed(control) or {};cpid=str(cinfo.get("State",{}).get("Pid",0));dpid=str(inspected[did][0]["State"]["Pid"])
                identity,identity_ob=observe(None,"native-control-network-namespace",["readlink","/proc/"+dpid+"/ns/net","/proc/"+cpid+"/ns/net"])
                snapshot["native_runtime"].append({"device_id":did,"kind":"FRR control namespace association","control_container_id":cinfo.get("Id"),"network_namespace_identities":identity.splitlines(),"observation_ids":[control_ob["id"],identity_ob["id"]]})
            native_commands[did]=cmds
            for kind,cmd in cmds.items():
                body,ob=observe(did,kind,cmd);rows[kind]=(body,ob)
                snapshot["native_runtime"].append({"device_id":did,"kind":kind,"raw_value":parsed(body) if parsed(body) is not None else body,"observation_ids":[ob["id"]],"status":"observed" if ob["returncode"]==0 else "failed"})
                if kind.startswith("native-ovs-") or kind=="native-frr-running":pre[did+"/"+kind]=digest(stable(kind,body).encode())
        observed[did]=rows
        info,ob=inspected[did]
        snapshot["devices"].append(fact(did,did,role=d["role"],site=d.get("site"),security_level_id=d.get("level"),network_id=probe_policy.get("network_ids",{}).get(did),trust_domain_id=d.get("tunnel",{}).get("trust"),implementation="Linux container",namespace=container(d),host_id=platform.node(),virtualization_kind="container-shared-kernel",physical_independence="unavailable",image_id=info.get("Image"),observed_running=info.get("State",{}).get("Running"),ipv6_settings=rows["ipv6-settings"][0],observation_ids=[ob["id"],rows["ipv6-settings"][1]["id"]]))
        for port in parsed(rows["interfaces"][0]) or []:
            declared=next((i for i in d["interfaces"] if i["name"]==port["ifname"]),{})
            snapshot["interfaces"].append(fact(did+":"+port["ifname"],did,name=port["ifname"],zone=declared.get("zone","local"),addresses=port.get("addr_info",[]),address_family=sorted({i["family"] for i in port.get("addr_info",[])}),link_kind=port.get("linkinfo",{}).get("info_kind",port.get("link_type")),parent_interface=port.get("link"),mtu=port.get("mtu"),observed_up="UP" in port.get("flags",[]),security_level_id=d.get("level"),observation_ids=[rows["interfaces"][1]["id"]]))
        for family in [4,6]:
            key="routes"+str(family)
            for j,r in enumerate(parsed(rows[key][0]) or []):
                snapshot["routes"].append(fact(did+":"+key+":"+str(j),did,family=family,table=r.get("table","main"),destination=r.get("dst","default"),gateway=r.get("gateway"),output_interface=r.get("dev"),priority=r.get("metric"),protocol=r.get("protocol"),type=r.get("type","unicast"),raw=r,observation_ids=[rows[key][1]["id"]]))
            key="filters"+str(family)
            chains={}
            for line in rows[key][0].splitlines():
                if line.startswith(":"):
                    tok=line.split()
                    chains[tok[0][1:]]={"policy":tok[1].lower(),"ordered_rules":[]}
                elif line.startswith("-A "):
                    tok=shlex.split(line)
                    rule={"ordinal":len(chains[tok[1]]["ordered_rules"]),"matches":{"iptables_tokens":tok[2:tok.index("-j")] if "-j" in tok else tok[2:]},"action":tok[tok.index("-j")+1].lower() if "-j" in tok else "unsupported","raw_text":line,"observation_ids":[rows[key][1]["id"]]}
                    chains[tok[1]]["ordered_rules"].append(rule)
            for name,ch in chains.items():
                snapshot["filters"].append(fact(did+":"+key+":"+name,did,family=family,table="filter",chain=name,hook=name.lower(),priority=0,observation_ids=[rows[key][1]["id"]],**ch))
        if d.get("tunnel"):
            t=d["tunnel"]
            public_config,pc=observe(did,"loaded-public-config",["cat","/etc/swanctl/swanctl.conf"])
            load_result=None
            if a.confirm_loaded_config:
                load_body,lc=observe(did,"public-connection-load-confirmation",["swanctl","--load-conns","--file","/etc/swanctl/swanctl.conf"])
                load_result={"observation_id":lc["id"],"returncode":lc["returncode"],"output":load_body,"loaded_file_sha256":digest(public_config.encode())}
            raw_conns,rc=observe(did,"connections-raw",["swanctl","--list-conns","--raw"])
            sas,so=observe(did,"sas",["swanctl","--list-sas"])
            conns,co=observe(did,"connections",["swanctl","--list-conns"])
            certs,ce=observe(did,"public-certificates",["swanctl","--list-certs","--utc"])
            snapshot["tunnels"].append(fact(did+":tunnel",did,peer_device_id=t["peer"],layer=d["role"],mechanism="IPsec",endpoints={"local":t["local"],"remote":t["remote"]},traffic_selectors={"local":t["local_ts"],"remote":t["remote_ts"]},mode="tunnel",algorithms={"raw_sas":sas},authentication={"configured":"pubkey","observed_connections":conns},replay_protection={"raw_states":rows["states"][0]},lifetimes={"raw_connections":conns},observed_state=sas,policies=rows["policies"][0],statistics=rows["states"][0],encapsulation=None,loaded_public_configuration=public_config,loaded_configuration_sha256=digest(public_config.encode()),load_confirmation=load_result,all_runtime_connections=raw_conns,observation_ids=[pc["id"],rc["id"],so["id"],co["id"],rows["states"][1]["id"],rows["policies"][1]["id"]]))
            snapshot["credentials"].append(fact(did+":credentials",did,layer=d["role"],authentication_kind="certificate",public_certificate_listing=certs,chain_validation="unavailable from listing alone",revocation_evidence="local CRL details in public listing",observation_ids=[ce["id"]]))
    for j,l in enumerate(spec["links"]):
        aid=l["a"]["device"]+":"+l["a"]["interface"]
        bid=l["b"]["device"]+":"+l["b"]["interface"]
        ad=l["a"]["device"];bd=l["b"]["device"]
        ai=next((p for p in parsed(observed[ad]["interfaces"][0]) if p["ifname"]==l["a"]["interface"]),{})
        bi=next((p for p in parsed(observed[bd]["interfaces"][0]) if p["ifname"]==l["b"]["interface"]),{})
        amap={v.get("nsid"):v.get("name") for v in nsids[ad][0]}
        bmap={v.get("nsid"):v.get("name") for v in nsids[bd][0]}
        matched=ai.get("link_index")==bi.get("ifindex") and bi.get("link_index")==ai.get("ifindex") and amap.get(ai.get("link_netnsid"))==aliases.get(bd) and bmap.get(bi.get("link_netnsid"))==aliases.get(ad)
        snapshot["links"].append({"id":"link-%03d"%j,"status":"observed" if matched else "configured","endpoint_interface_ids":[aid,bid],"relation":"veth","physical_claim_supported":False,"runtime_peer_check":{"reciprocal_ifindex":ai.get("link_index")==bi.get("ifindex") and bi.get("link_index")==ai.get("ifindex"),"namespace_a_peer":amap.get(ai.get("link_netnsid")),"namespace_b_peer":bmap.get(bi.get("link_netnsid")),"verified":matched},"observation_ids":[observed[ad]["interfaces"][1]["id"],observed[bd]["interfaces"][1]["id"],nsids[ad][1]["id"],nsids[bd][1]["id"]]})
    for did,d in devices.items():
        if d["role"]=="switch":
            for port in parsed(observed[did]["bridge-links"][0]) or []:
                if port.get("master")=="br0":
                    snapshot["links"].append({"id":"bridge-"+did+"-"+port["ifname"],"status":"observed","endpoint_interface_ids":[did+":"+port["ifname"],did+":br0"],"relation":"bridge_attachment","physical_claim_supported":False,"observation_ids":[observed[did]["bridge-links"][1]["id"]]})
    if spec["version"]==2:
        def table_rows(body):
            table=parsed(body) or {};return [dict(zip(table.get("headings",[]),r)) for r in table.get("data",[])]
        def ovs_ids(v):return [x[1] for x in (v[1] if v and v[0]=="set" else [v]) if x and x[0]=="uuid"]
        for did,d in devices.items():
            if d["role"]!="switch":continue
            rows=observed[did];bridges=table_rows(rows["native-ovs-bridge"][0]);ports={x['_uuid'][1]:x for x in table_rows(rows["native-ovs-port"][0])};interfaces={x['_uuid'][1]:x for x in table_rows(rows["native-ovs-interface"][0])}
            for bridge in bridges:
                for pid in ovs_ids(bridge['ports']):
                    port=ports.get(pid,{})
                    for iid in ovs_ids(port.get('interfaces',[])):
                        interface=interfaces.get(iid,{});name=interface.get('name')
                        if name and name!=bridge['name'] and did+':'+name in {i['id'] for i in snapshot['interfaces']}:
                            snapshot['links'].append({'id':'ovs-'+did+'-'+name,'status':'observed','endpoint_interface_ids':[did+':'+name,did+':'+bridge['name']],'relation':'ovs_bridge_membership','physical_claim_supported':False,'ovs_bridge_uuid':bridge['_uuid'][1],'ovs_port_uuid':pid,'ovs_interface_uuid':iid,'observation_ids':[rows['native-ovs-bridge'][1]['id'],rows['native-ovs-port'][1]['id'],rows['native-ovs-interface'][1]['id']]})
    hosts=[d for d in spec["devices"] if d["role"]=="host"]
    for src in hosts:
        for dst in hosts:
            if src["id"]==dst["id"]:
                continue
            addr=next(i["address"].split("/")[0] for i in dst["interfaces"] if i.get("address"))
            same=src.get("level")==dst.get("level")
            if probe_policy:same=probe_policy["outcomes"][src["id"]+"/"+dst["id"]]=="delivered"
            probe_program="import json,subprocess,sys; r=subprocess.run([\"ping\",\"-n\",\"-c\",\"2\",\"-W\",\"1\",sys.argv[1]],capture_output=True,text=True,timeout=5); print(json.dumps({\"returncode\":r.returncode,\"stdout\":r.stdout,\"stderr\":r.stderr}))"
            body,ob=observe(src["id"],"probe",["python3","-c",probe_program,addr],timeout=7)
            probe_result=parsed(body) or {}
            probe_rc=probe_result.get("returncode",124)
            outcome="delivered" if probe_rc==0 else "no_reply" if probe_rc==1 else "collection_error"
            snapshot["probes"].append({"id":"probe-"+ob["id"],"status":"observed" if outcome!="collection_error" else "failed","source_device":src["id"],"destination":addr,"destination_device":dst["id"],"family":4,"protocol":"icmp","source_case_ids":snapshot["scope"]["source_case_ids"],"purpose":("within-network useful traffic" if same else "cross-network denial") if probe_policy else ("same-level useful traffic" if same else "cross-level denial"),"expected_result":"delivered" if same else "no_reply","observed_result":outcome,"command":ob["command"],"started_at":ob["started_at"],"ended_at":ob["ended_at"],"returncode":probe_rc,"observation_ids":[ob["id"]]})
    managed=[d for d in spec["devices"] if d.get("admin")]
    if managed:
        snapshot["scope"]["management_applicability"]="optional_enabled"
        snapshot["management"]={"profile":"independent_management","applicability":"optional_enabled","records":[],"failures":[]}
        tls_program=r"""import ssl,socket,json,sys
r={"client_certificate":sys.argv[2]=="yes"}
try:
 c=ssl.create_default_context(cafile='/run/msc-tls/x509ca/ca.pem')
 if r['client_certificate']:c.load_cert_chain('/run/msc-tls/x509/cert.pem','/run/msc-tls/private/key.pem')
 with socket.create_connection((sys.argv[1],8443),timeout=4) as sock:
  with c.wrap_socket(sock,server_hostname=sys.argv[1]) as ss:
   r.update({'tls_version':ss.version(),'cipher':ss.cipher(),'peer':ss.getpeercert()})
   ss.sendall(b'GET / HTTP/1.0\r\n\r\n');r['response']=ss.recv(4096).decode();r['result']='delivered'
except Exception as e:r.update({'result':'rejected','error':type(e).__name__+': '+str(e)})
print(json.dumps(r))"""
        for d in managed:
            aw=next(x for x in spec["devices"] if x["role"]=="admin" and any(i.get("address","").split("/")[0]==d["admin"] for i in x["interfaces"]))
            addr=next(i["address"].split("/")[0] for i in d["interfaces"] if i["name"]=="mgmt")
            for authorized in [True,False]:
                body,ob=observe(aw["id"],"management-tls-probe",["python3","-c",tls_program,addr,"yes" if authorized else "no"])
                result=parsed(body) or {}
                snapshot["management"]["records"].append(fact("management-"+ob["id"],d["id"],"observed" if ob["returncode"]==0 else "failed",source_device_id=aw["id"],target_device_id=d["id"],profile="mutual_tls",client_certificate=authorized,expected_result="delivered" if authorized else "rejected",result=result,observation_ids=[ob["id"]]))
    post={}
    for did in devices:
        for kind in ["routes4","routes6","filters4","filters6","policies","interfaces","bridge-links","bridge-vlans"]:
            body,ob=observe(did,"convergence-"+kind,commands[kind])
            post[did+"/"+kind]=digest(stable(kind,body).encode())
    for did,d in devices.items():
        body,ob=observe(None,"convergence-device-identity",["docker","inspect","--format","{{json .}}",container(d)])
        post[did+"/device-identity"]=digest(stable("device-identity",body).encode())
        pid=str((parsed(body) or {}).get("State",{}).get("Pid",0))
        body,ob=observe(None,"convergence-namespace-peers",["nsenter","-t",pid,"-n","ip","-j","netns","list-id"])
        post[did+"/namespace-peers"]=digest(stable("namespace-peers",body).encode())
    for did,cmds in native_commands.items():
        for kind,cmd in cmds.items():
            if kind.startswith("native-ovs-") or kind=="native-frr-running":
                body,ob=observe(did,"convergence-"+kind,cmd);post[did+"/"+kind]=digest(stable(kind,body).encode())
    changed=[k for k in pre if pre[k]!=post[k]]
    for did,alias in aliases.items():
        observe(None,"namespace-alias-release",["ip","netns","delete",alias])
    failures=[f for f in failures if not (f["kind"]=="probe" and f["returncode"]==1)]
    snapshot["limitations"].append({"id":"virtual-appliances","affected_case_ids":snapshot["scope"]["source_case_ids"],"classification":"physical_capability","reason":"Containers and veth links share one Linux host; the capture does not establish physical separation, product independence, secure facilities or formal approval.","actionable_change":"Supply external physical and organizational records."})
    (root/"snapshot.json").write_text(json.dumps(snapshot,indent=2)+"\n")
    (root/"spec.json").write_text(json.dumps(spec,indent=2)+"\n")
    files=[]
    for path in sorted(root.rglob("*")):
        if path.is_file():
            files.append({"path":str(path.relative_to(root)),"sha256":digest(path.read_bytes()),"bytes":path.stat().st_size,"category":"raw" if path.parent.name=="raw" else "normalized"})
    manifest={"schema_version":"csfc-evidence/v1","snapshot_id":sid,"run_id":"construction-v2","configuration_id":a.configuration_id,"emulation_id":spec["name"],"source_case_ids":snapshot["scope"]["source_case_ids"],"requirement_group_ids":[],"started_at":started,"ended_at":utc(),"host":platform.node(),"software":{"kernel":platform.release(),"python":platform.python_version()},"code_hashes":{"collector":digest(Path(__file__).read_bytes()),"deployer":a.deployer_sha256},"configuration_hashes":{"spec":digest(Path(a.spec).read_bytes())},"files":files,"collection_failures":failures,"sanitization":{"private_files_read":False,"xfrm_key_export":False},"inventory_complete":{k:{"complete":not failures,"reason":"Explicit expected inventory and every command result retained."} for k in ["devices","interfaces","links","routes","filters","tunnels","credentials","probes","management"]},"convergence":{"before":pre,"after":post,"selected_fields":["IPv4 and IPv6 routes","IPv4 and IPv6 ordered filters","XFRM policies","device ID/image/PID/start state","interface identities and addresses","namespace peer IDs","bridge port and VLAN membership","OVS UUID membership/options/flow/group/meter inventories and FRR running configuration"],"consistent":not changed,"changed":changed,"interpretation":"Finite sequential before/after observation, not atomic. Counter values and bridge countdown timers are excluded from identity comparisons; IDs, configuration, membership and state remain checked."}}
    (root/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps({"snapshot_id":sid,"observations":len(observations),"failures":len(failures),"converged":not changed,"probes":len(snapshot["probes"]),"unexpected_probes":[q["id"] for q in snapshot["probes"] if q["expected_result"]!=q["observed_result"]]}))

if __name__=="__main__":
    main()
