#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

struct metadata_t {}

parser ParserImpl(packet_in packet, out headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control VerifyChecksumImpl(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

control IngressImpl(inout headers_t hdr, inout metadata_t meta,
                    inout standard_metadata_t standard_metadata) {
    register<bit<32>>(1) detection_threshold;
    action ipv4_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action drop() {
        mark_to_drop(standard_metadata);
    }
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; }
        size = 1024;
        default_action = drop();
    }
    apply {
        bit<32> threshold;
        detection_threshold.read(threshold, 0);
        if (hdr.ipv4.isValid()) {
            if (threshold <= 1) {
                mark_to_drop(standard_metadata);
            } else if (hdr.ipv4.dstAddr == 0xe0000005 || hdr.ipv4.dstAddr == 0xe0000006) {
                // OSPF is link-local multicast. It is a control-plane
                // broadcast-domain packet, not a unicast table lookup.
                if (standard_metadata.ingress_port == 1) {
                    standard_metadata.egress_spec = 2;
                } else {
                    standard_metadata.egress_spec = 1;
                }
            } else {
                ipv4_lpm.apply();
            }
        } else {
            if (standard_metadata.ingress_port == 1) {
                standard_metadata.egress_spec = 2;
            } else {
                standard_metadata.egress_spec = 1;
            }
        }
    }
}

control EgressImpl(inout headers_t hdr, inout metadata_t meta,
                   inout standard_metadata_t standard_metadata) {
    apply {}
}

control ComputeChecksumImpl(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(ParserImpl(), VerifyChecksumImpl(), IngressImpl(), EgressImpl(),
         ComputeChecksumImpl(), DeparserImpl()) main;
