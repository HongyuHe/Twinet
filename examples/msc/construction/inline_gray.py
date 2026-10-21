import copy
import json
from pathlib import Path
root=Path(__file__).resolve().parent
for base,name in [("shared-three-level","shared3-v3"),("redundant-three-level","redun3-v3")]:
    s=json.loads((root/(base+".json")).read_text());s["name"]=name
    by={d["id"]:d for d in s["devices"]}
    for site,n,peer in [("A",100,200),("B",200,100)]:
        gf=by["GF_"+site];gf["boundary_flows"]=[];gf["routes"]=[]
        for lev in [1,2,3]:
            subnet=n+10
            gf["interfaces"].append({"name":"g"+str(lev),"address":f"10.{subnet}.{lev}.254/24","zone":"gray","mtu":1400})
            gf["routes"].append({"prefix":f"10.{peer}.{lev}.2/32","via":f"10.{subnet}.{lev}.1"})
            for ins,outs,src,dst in [("s"+str(lev),"g"+str(lev),f"10.{n}.{lev}.2/32",f"10.{peer}.{lev}.2/32"),("g"+str(lev),"s"+str(lev),f"10.{peer}.{lev}.2/32",f"10.{n}.{lev}.2/32")]:
                gf["boundary_flows"].append({"ingress":ins,"egress":outs,"source":src,"destination":dst})
            for link in s["links"]:
                for end,other in [(link["a"],link["b"]),(link["b"],link["a"])]:
                    if end["device"]==f"G_{site}{lev}" and end["interface"]=="inner":
                        end["device"]="GF_"+site;end["interface"]="s"+str(lev)
                    elif end["device"]=="GF_"+site and end["interface"]=="s"+str(lev) and other["device"]==f"G_{site}{lev}":
                        end["interface"]="g"+str(lev)
            sw=by[f"G_{site}{lev}"];sw["interfaces"]=[p for p in sw["interfaces"] if p["name"]!="inner"]
            inner=by[f"I_{site}{lev}"]
            for route in inner["routes"]:route["via"]=f"10.{n}.{lev}.254"
            for outer in [d for d in s["devices"] if d.get("site")==site and d["role"]=="outer"]:
                port=next(p for p in outer["interfaces"] if p["name"]==("gray" if lev==1 else "gray"+str(lev)))
                port["address"]=port["address"].replace(f"10.{n}.",f"10.{subnet}.")
                outer["routes"].append({"prefix":f"10.{n}.{lev}.2/32","via":f"10.{subnet}.{lev}.254"})
    (root/(base+"-inline.json")).write_text(json.dumps(s,indent=2)+"\n")
