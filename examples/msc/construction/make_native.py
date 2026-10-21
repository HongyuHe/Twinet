import copy,json
from pathlib import Path
root=Path(__file__).resolve().parent
profiles={'ipsec-baseline':'NB','shared-same-level':'NT','shared-four-levels':'NF','redundant-four-levels':'NR','management-independent':'NM'}
for profile,prefix in profiles.items():
 s=json.loads((root/(profile+'.json')).read_text());s['version']=2;s['name']='native-'+prefix.lower();s['router_image']='twinet-msc-router:construction-v2';s['switch_image']='twinet-msc-switch:construction-v2'
 mapping={d['id']:prefix+'_'+d['id'] for d in s['devices']}
 for d in s['devices']:
  if profile=='shared-same-level' and d['role'] in ['host','inner']:d['network']='NETWORK-'+d['id'][-1]
  d['id']=mapping[d['id']]
  if d.get('tunnel'):d['tunnel']['peer']=mapping[d['tunnel']['peer']]
  if d['role'] in ['transport','firewall'] and any(p['zone']=='black' for p in d['interfaces']):d.pop('routes',None)
 for link in s['links']:
  for endpoint in [link['a'],link['b']]:endpoint['device']=mapping[endpoint['device']]
 (root/('native-'+profile+'.json')).write_text(json.dumps(s,indent=2)+'\n')
 (root/('native-'+profile+'-mapping.json')).write_text(json.dumps({'source_profile':profile,'native_profile':'native-'+profile,'device_id_mapping':mapping,'routing_change':'Black FRR routers and Outer Firewalls use OSPF; Gray FRR routers and Gray Firewalls retain explicit static forwarding routes; encryptors run no routing daemon'},indent=2)+'\n')
 if profile=='shared-same-level':
  policy=json.loads((root/'same-level-probe-policy.json').read_text())
  for key in ['network_ids']:
   policy[key]={mapping.get(k,k):v for k,v in policy[key].items()}
  policy['outcomes']={'/'.join(mapping.get(x,x) for x in k.split('/')):v for k,v in policy['outcomes'].items()}
  raw=json.dumps(policy)
  for old,new in sorted(mapping.items(),key=lambda x:-len(x[0])):raw=raw.replace('"'+old+'"','"'+new+'"')
  (root/'native-same-level-probe-policy.json').write_text(raw+'\n')
