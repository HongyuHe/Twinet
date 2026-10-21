#!/usr/bin/env python3
"""Add ordinary Gray routers as explicitly drawn in Figure9."""
import json
from pathlib import Path
base=Path(__file__).parent
s=json.loads((base/"redundant-three-level-inline.json").read_text());s["name"]="redun4-v4"
for site,local,remote,outer in [("A",100,200,110),("B",200,100,210)]:
    gf=next(d for d in s["devices"] if d["id"]=="GF_"+site)
    router={"id":"GR_"+site,"role":"transport","site":site,"interfaces":[],"routes":[]}
    for level in [1,2,3]:
        lower=outer+10
        for interface in gf["interfaces"]:
            if interface["name"]=="g"+str(level):interface["address"]=f"10.{lower}.{level}.254/24"
        for route in gf["routes"]:
            if route["prefix"]==f"10.{remote}.{level}.2/32":route["via"]=f"10.{lower}.{level}.1"
        router["interfaces"].extend([{"name":f"g{level}","address":f"10.{lower}.{level}.1/24","zone":"gray","mtu":1400},{"name":f"o{level}","address":f"10.{outer}.{level}.254/24","zone":"gray","mtu":1400}])
        router["routes"].extend([{"prefix":f"10.{local}.{level}.2/32","via":f"10.{lower}.{level}.254"},{"prefix":f"10.{remote}.{level}.2/32","via":f"10.{outer}.{level}.1"}])
        for link in s["links"]:
            for endpoint in ["a","b"]:
                if link[endpoint]=={"device":"GF_"+site,"interface":f"g{level}"}:link[endpoint]={"device":"GR_"+site,"interface":f"o{level}"}
        s["links"].append({"a":{"device":"GF_"+site,"interface":f"g{level}"},"b":{"device":"GR_"+site,"interface":f"g{level}"}})
    s["devices"].append(router)
(base/"redundant-router.json").write_text(json.dumps(s,indent=2)+"\n")
