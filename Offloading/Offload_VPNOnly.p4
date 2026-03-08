#include <core.p4>
#include <v1model.p4>

const bit<16> VPN_TH  = 1100;
const bit<16> DROP_TH = 1500;

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16>    etherType;
}

header ipv4_t {
    bit<4>     version;
    bit<4>     ihl;
    bit<8>     diffserv;
    bit<16>    totalLen;
    bit<16>    identification;
    bit<3>     flags;
    bit<13>    fragOffset;
    bit<8>     ttl;
    bit<8>     protocol;
    bit<16>    hdrChecksum;
    ipv4_addr_t srcAddr;
    ipv4_addr_t dstAddr;
}

header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_len;
    bit<8>  proto_len;
    bit<16> opcode;
    mac_addr_t sender_hw_addr;
    ipv4_addr_t sender_proto_addr;
    mac_addr_t target_hw_addr;
    ipv4_addr_t target_proto_addr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    arp_t      arp;
    tcp_t      tcp;
    udp_t      udp;
}

struct metadata_t {
    bit<1> use_vpn;
    bit<1> allowed;
}

parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.use_vpn = 0;
        meta.allowed = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action allow_pair() {
        meta.allowed = 1;
    }

    action set_use_vpn(bit<1> v) {
        meta.use_vpn = v;
    }

    action ipv4_forward(mac_addr_t dst, mac_addr_t src, bit<9> port) {
        hdr.ethernet.dstAddr = dst;
        hdr.ethernet.srcAddr = src;
        standard_metadata.egress_spec = port;
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
    }

    action arp_flood(bit<16> gid) {
        standard_metadata.mcast_grp = gid;
    }

    table whitelist {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            allow_pair;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table flow_policy {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            hdr.tcp.dstPort  : exact;
        }
        actions = {
            set_use_vpn;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table fwd_normal {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table fwd_vpn {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.arp.isValid()) {
            arp_flood(1);
            return;
        }

        if (!hdr.ipv4.isValid()) {
            drop();
            return;
        }

        whitelist.apply();
        if (meta.allowed == 0) {
            drop();
            return;
        }

        if (hdr.tcp.isValid()) {
            flow_policy.apply();
        }

        if ((bit<16>) standard_metadata.packet_length >= DROP_TH) {
            drop();
            return;
        }

        // VPN-only baseline:
        // first hop from hosts goes to VPN,
        // packets returning from hgw go direct.
        if (standard_metadata.ingress_port == 3) {
            meta.use_vpn = 0;
        } else {
            meta.use_vpn = 1;
        }

        if (meta.use_vpn == 1) {
            fwd_vpn.apply();
        } else {
            fwd_normal.apply();
        }
    }
}

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;