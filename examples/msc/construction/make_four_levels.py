#!/usr/bin/env python3
"""Retain all three Figure6 levels and a separate unclassified alternative."""
import copy
import json
from pathlib import Path
base=Path(__file__).parent

def fourth(value):
    text=json.dumps(value)
    for old,new in [('A3','A4'),('B3','B4'),('gray3','gray4'),('"s3"','"s4"'),('"g3"','"g4"'),('"o3"','"o4"')]+[(f'10.{n}.3.',f'10.{n}.4.') for n in [1,2,100,200,110,210,120,220]]:text=text.replace(old,new)
    return json.loads(text)

for source,name,outname in [('shared-three-level-inline.json','shared4-v5','shared-four-levels.json'),('redundant-router.json','redun5-v6','redundant-four-levels.json')]:
    s=json.loads((base/source).read_text());s['name']=name
    by={d['id']:d for d in s['devices']}
    for site in ['A','B']:
        for prefix in ['R_','I_','G_']:
            d=fourth(by[prefix+site+'3']);d['level']='UNCLASSIFIED'
            if d.get('tunnel'):d['tunnel']['reqid']=104;d['tunnel']['trust']='inner-unclassified'
            s['devices'].append(d)
        for d in s['devices']:
            if d.get('site')!=site or d['id'].endswith('4'):continue
            d['interfaces'].extend(fourth(i) for i in list(d['interfaces']) if i['name'] in ['s3','g3','o3','gray3'])
            if d.get('routes') and d['role'] in ['outer','transport','gray-firewall']:d['routes'].extend(fourth(r) for r in list(d['routes']) if any(f'10.{n}.3.' in r.get('prefix','') for n in [100,200]))
            if d.get('boundary_flows'):d['boundary_flows'].extend(fourth(f) for f in list(d['boundary_flows']) if f['ingress'] in ['s3','g3'])
            if d.get('tunnel',{}).get('flows'):d['tunnel']['flows'].extend(fourth(f) for f in list(d['tunnel']['flows']) if f['inside']=='gray3')
        for link in list(s['links']):
            ends=[link['a'],link['b']]
            if any(e['device'] in ['R_'+site+'3','I_'+site+'3','G_'+site+'3'] for e in ends) or any(e['device'] in ['GF_'+site,'GR_'+site] and e['interface'] in ['s3','g3','o3'] for e in ends):s['links'].append(fourth(link))
    for d in s['devices']:
        if d['id'].startswith(('I_','R_','G_')) and d['id'][-1] in '123':d['level']={'1':'TOP_SECRET','2':'SECRET_US_ONLY','3':'SECRET_COALITION'}[d['id'][-1]]
        if d['id'].startswith('I_') and d['id'].endswith('3'):d['tunnel']['trust']='inner-secret-coalition'
    (base/outname).write_text(json.dumps(s,indent=2)+'\n')
