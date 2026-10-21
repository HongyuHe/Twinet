import sys
if "--historical-unsafe" not in sys.argv:
    raise SystemExit("Historical generator contains the preserved shared-Outer Gray bypass. Use committed shared-four-levels.json and redundant-four-levels.json. Reproduce the failed layout only with --historical-unsafe.")
import copy
import json
from pathlib import Path
root=Path(__file__).resolve().parent
base=json.loads((root/"ipsec-baseline.json").read_text())
s=copy.deepcopy(base)
s["name"]="shared-v2"
by={d["id"]:d for d in s["devices"]}
removed={"O_A2","O_B2","OF_A2","OF_B2"}
for site in ["A","B"]:
    port=copy.deepcopy(by["O_"+site+"2"]["interfaces"][0]);port["name"]="gray2"
    by["O_"+site+"1"]["interfaces"].append(port)
for link in s["links"]:
    for end in [link["a"],link["b"]]:
        if end["device"] in ["O_A2","O_B2"] and end["interface"]=="gray":
            end["device"]=end["device"][:-1]+"1";end["interface"]="gray2"
s["devices"]=[d for d in s["devices"] if d["id"] not in removed]
s["links"]=[l for l in s["links"] if not any(l[k]["device"] in removed for k in ["a","b"])]
by["BLACK"]["interfaces"]=[p for p in by["BLACK"]["interfaces"] if p["name"] not in ["p12","p22"]]
by["BLACK"]["routes"]=[r for r in by["BLACK"]["routes"] if not any(net in r["prefix"] for net in ["172.20.12.","172.20.22."])]
def third(value):
    raw=json.dumps(value)
    for a,b in [("A2","A3"),("B2","B3"),("10.1.2.","10.1.3."),("10.2.2.","10.2.3."),("10.100.2.","10.100.3."),("10.200.2.","10.200.3."),("S2","UNCLASSIFIED"),("inner-s2","inner-unclassified")]:raw=raw.replace(a,b)
    return json.loads(raw)
for site in ["A","B"]:
    for prefix in ["R_","I_","G_"]:
        d=third(by[prefix+site+"2"])
        if d.get("tunnel"):d["tunnel"]["reqid"]=103
        s["devices"].append(d)
    for link in list(s["links"]):
        if any(l["device"] in ["R_"+site+"2","I_"+site+"2","G_"+site+"2"] for l in [link["a"],link["b"]]):
            l=third(link)
            for end in [l["a"],l["b"]]:
                if end["device"]=="O_"+site+"1":end["interface"]="gray3"
                if end["device"]=="GF_"+site:end["interface"]="s3"
            s["links"].append(l)
    outer=by["O_"+site+"1"]
    port=third(next(p for p in outer["interfaces"] if p["name"]=="gray2"));port["name"]="gray3";outer["interfaces"].append(port)
    gf=by["GF_"+site]
    port=third(next(p for p in gf["interfaces"] if p["name"]=="s2"));port["name"]="s3";gf["interfaces"].append(port)
    n=100 if site=="A" else 200;peer=300-n
    outer["level"]="shared"
    outer["tunnel"]["local_ts"]=f"10.{n}.0.0/16"
    outer["tunnel"]["remote_ts"]=f"10.{peer}.0.0/16"
    outer["tunnel"]["flows"]=[{"inside":"gray" if lev==1 else "gray"+str(lev),"local":f"10.{n}.{lev}.2/32","remote":f"10.{peer}.{lev}.2/32"} for lev in [1,2,3]]
    for route in outer["routes"]:
        if route["prefix"].startswith(f"10.{peer}."):route["prefix"]=f"10.{peer}.0.0/16"
(root/"shared-three-level.json").write_text(json.dumps(s,indent=2)+"\n")
same=copy.deepcopy(s);same["name"]="samelevel-v2"
removed={d["id"] for d in same["devices"] if d["id"].endswith("3")}
same["devices"]=[d for d in same["devices"] if d["id"] not in removed]
same["links"]=[l for l in same["links"] if not any(l[k]["device"] in removed for k in ["a","b"])]
for d in same["devices"]:
    d["interfaces"]=[p for p in d["interfaces"] if p["name"] not in ["gray3","s3"]]
    if d.get("level") in ["S1","S2"]:d["level"]="SECRET-US-only"
    if d.get("tunnel",{}).get("flows"):d["tunnel"]["flows"]=d["tunnel"]["flows"][:2]
(root/"shared-same-level.json").write_text(json.dumps(same,indent=2)+"\n")
redundant=copy.deepcopy(s);redundant["name"]="redundant-v2"
rby={d["id"]:d for d in redundant["devices"]};bby={d["id"]:d for d in base["devices"]}
for site,idx in [("A",1),("B",2)]:
    outer=copy.deepcopy(rby["O_"+site+"1"])
    outer["id"]="O_"+site+"2";outer["tunnel"]["peer"]="O_"+("B" if site=="A" else "A")+"2";outer["tunnel"]["reqid"]=202
    outer["tunnel"]["local"]=f"172.20.{idx}2.1";outer["tunnel"]["remote"]=f"172.20.{3-idx}2.1"
    for p in outer["interfaces"]:
        if p["zone"]=="gray":p["address"]=p["address"].replace(".1/",".3/")
        if p["zone"]=="black":p["address"]=f"172.20.{idx}2.1/30"
    for r in outer["routes"]:
        r["via"]=f"172.20.{idx}2.2"
        if r["prefix"].startswith("172.20."):r["prefix"]=outer["tunnel"]["remote"]+"/32"
    redundant["devices"].append(outer)
    redundant["devices"].append(copy.deepcopy(bby["OF_"+site+"2"]))
    rby["BLACK"]["interfaces"].append(copy.deepcopy(next(p for p in bby["BLACK"]["interfaces"] if p["name"]==f"p{idx}2")))
    rby["BLACK"]["routes"].extend(copy.deepcopy([r for r in bby["BLACK"]["routes"] if f"172.20.{idx}2." in r["prefix"]]))
    for level in [1,2,3]:
        sw=rby[f"G_{site}{level}"];port=copy.deepcopy(next(p for p in sw["interfaces"] if p["name"]=="outer"));port["name"]="outer2";sw["interfaces"].append(port)
        redundant["links"].append({"a":{"device":outer["id"],"interface":"gray" if level==1 else "gray"+str(level)},"b":{"device":sw["id"],"interface":"outer2"}})
    redundant["links"].extend(copy.deepcopy([l for l in base["links"] if any(l[k]["device"]=="OF_"+site+"2" for k in ["a","b"])]))
(root/"redundant-three-level.json").write_text(json.dumps(redundant,indent=2)+"\n")
print([(p.name,len(json.loads(p.read_text())["devices"])) for p in root.glob("*level.json")])
