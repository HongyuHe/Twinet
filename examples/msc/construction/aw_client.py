#!/usr/bin/env python3
"""Report bounded authenticated management use from the current execution placement."""
from datetime import datetime,timezone
import json
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import sys
base=Path(sys.argv[1]);host=sys.argv[2];identity=sys.argv[3];authorized=sys.argv[4]=='yes'
r={'started_at':datetime.now(timezone.utc).isoformat(),'hostname':platform.node(),'kernel':platform.release(),'virtualization':subprocess.run(['systemd-detect-virt'],capture_output=True,text=True).stdout.strip(),'identity':identity,'client_certificate':authorized}
try:
 c=ssl.create_default_context(cafile=base/'ca.pem')
 if authorized:c.load_cert_chain(base/(identity+'.pem'),base/(identity+'.key'))
 with socket.create_connection((host,18443),timeout=4) as sock:
  with c.wrap_socket(sock,server_hostname='server.msc.test') as ss:
   r.update({'tls_version':ss.version(),'cipher':ss.cipher()});ss.sendall(b'GET / HTTP/1.0\r\n\r\n');r['response']=ss.recv(1024).decode();r['outcome']='delivered'
except Exception as exc:r.update({'outcome':'rejected','error':type(exc).__name__+': '+str(exc)})
r['ended_at']=datetime.now(timezone.utc).isoformat();print(json.dumps(r))
