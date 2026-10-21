#!/usr/bin/env python3
"""Persist only IPv4, UDP, IKE and EF header fields from a finite exchange."""
from datetime import datetime,timezone
import json
import socket
import struct
import sys
iface=sys.argv[1]
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((iface,0))
while True:
    frame,source=s.recvfrom(65535)
    if len(frame)<42 or frame[12:14]!=b"\x08\x00":continue
    ip=frame[14:];ihl=(ip[0]&15)*4
    if len(ip)<ihl+8 or ip[9]!=17:continue
    offset=struct.unpack("!H",ip[6:8])[0];udp=ip[ihl:];sport,dport,length=struct.unpack("!HHH",udp[:6])
    if sport not in [500,4500] and dport not in [500,4500]:continue
    r={"timestamp":datetime.now(timezone.utc).isoformat(),"interface":iface,"packet_type":source[2],"source":socket.inet_ntoa(ip[12:16]),"destination":socket.inet_ntoa(ip[16:20]),"ip_total_length":struct.unpack("!H",ip[2:4])[0],"ip_header_length":ihl,"ip_id":struct.unpack("!H",ip[4:6])[0],"dont_fragment":bool(offset&0x4000),"more_fragments":bool(offset&0x2000),"fragment_offset_bytes":(offset&8191)*8,"udp_source":sport,"udp_destination":dport,"udp_length":length}
    data=udp[8:]
    if sport==4500 or dport==4500:
        if data[:4]!=b"\x00\x00\x00\x00":continue
        data=data[4:]
    if len(data)>=28:
        r.update({"ike_initiator_spi":data[:8].hex(),"ike_responder_spi":data[8:16].hex(),"ike_next_payload":data[16],"ike_version":data[17],"ike_exchange_type":data[18],"ike_flags":data[19],"ike_message_id":struct.unpack("!I",data[20:24])[0],"ike_length":struct.unpack("!I",data[24:28])[0]})
        if data[16]==53 and len(data)>=36:r.update({"ef_fragment_number":struct.unpack("!H",data[32:34])[0],"ef_total_fragments":struct.unpack("!H",data[34:36])[0],"ef_payload_length":struct.unpack("!H",data[30:32])[0]})
    if len(data)>=28 and data[18]==34:
        payload=data[16];pos=28;notifies=[]
        while payload and pos+4<=len(data):
            next_payload=data[pos];plen=struct.unpack("!H",data[pos+2:pos+4])[0]
            if plen<4 or pos+plen>len(data):break
            if payload==41 and plen>=8:
                spi_size=data[pos+5];kind=struct.unpack("!H",data[pos+6:pos+8])[0]
                if kind==16431:
                    hashes=data[pos+8+spi_size:pos+plen]
                    notifies.append({"notify_type":kind,"signature_hash_algorithm_ids":[struct.unpack("!H",hashes[i:i+2])[0] for i in range(0,len(hashes)-1,2)]})
            payload=next_payload;pos+=plen
        r["signature_hash_notifies"]=notifies
    print(json.dumps(r),flush=True)
