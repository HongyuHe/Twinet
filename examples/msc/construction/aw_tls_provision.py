#!/usr/bin/env python3
"""Prepare a persistent test management service and unique AW client identities."""
from pathlib import Path
import subprocess
import json
from matrix_lab import Lab
from utility_variants import pki
base=Path('/users/hy/tdn-evidence-v2');private=base/'private/aw-pki';lab=Lab(base/'exports','aw-tls-provision-v1');pki(lab,private)
lab.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-384','-out',private/'vm.key'])
lab.run(['openssl','req','-new','-sha384','-key',private/'vm.key','-out',private/'vm.csr','-subj','/CN=vm-aw.msc.test'])
lab.run(['openssl','x509','-req','-sha384','-in',private/'vm.csr','-CA',private/'ca.pem','-CAkey',private/'ca.key','-CAcreateserial','-days','1','-extfile',private/'client.ext','-out',private/'vm.pem'])
server=r"""import http.server,ssl,sys
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'owned management service\n')
s=http.server.HTTPServer(('127.0.0.1',18443),Handler);c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(sys.argv[1]+'/server.pem',sys.argv[1]+'/server.key');c.load_verify_locations(sys.argv[1]+'/ca.pem');c.verify_mode=ssl.CERT_REQUIRED;s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()
"""
(private/'server.py').write_text(server);log=(private/'server.log').open('w');proc=subprocess.Popen(['python3',str(private/'server.py'),str(private)],stdout=log,stderr=log,start_new_session=True);(private/'server.pid').write_text(str(proc.pid));log.close()
for name in ['ca.pem','server.pem','client.pem','vm.pem']:(lab.root/name).write_bytes((private/name).read_bytes())
(lab.root/'placement.json').write_text(json.dumps({'server_host':'clnode176.clemson.cloudlab.us','server_bind':'127.0.0.1:18443','physical_AW_host':'clnode159.clemson.cloudlab.us','virtual_AW':'KVM guest csfc-aw-vm on clnode159','transport':'SSH port forwarding carries mutual TLS; a functional AW-placement experiment, not a CSfC-approved management solution'},indent=2)+'\n');lab.finish()
