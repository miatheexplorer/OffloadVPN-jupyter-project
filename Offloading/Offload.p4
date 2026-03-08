#include <core.p4>
#include <v1model.p4>

/* ========= User thresholds (bytes) =========
 * Note: uses standard_metadata.packet_length (whole packet length).
 */
const bit<16> VPN_TH  = 1100;
const bit<16> DROP_TH = 1500;

/* ========= ARP rate limiting ========= */
const bit<32> ARP_RATE_LIMIT = 100;  // Max ARP packets per second
                                     // (will be enforced by controller)

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
    bit<16> hw_type;          // Hardware type (1 for Ethernet)
    bit<16> proto_type;       // Protocol type (0x0800 for IP)
    bit<8>  hw_len;           // Hardware address length (6 for MAC)
    bit<8>  proto_len;        // Protocol address length (4 for IPv4)
    bit<16> opcode;           // 1=request, 2=reply
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
    bit<9>  flags;     // includes SYN/ACK bits (BMv2 example style)
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
    bit<1>  use_vpn;          // 1 => send to VPN gateway port, 0 => normal path
    bit<1>  allowed;          // whitelist result
    bit<1>  is_arp;           // Flag to identify ARP packets
}

/* ========= Parser ========= */

parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.use_vpn = 0;
        meta.allowed = 0;
        meta.is_arp = 0;
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
        meta.is_arp = 1;
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;   // TCP
            17: parse_udp;  // UDP
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

/* ========= Verify/Compute checksum (no-op here) ========= */
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/* ========= Ingress ========= */

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    /* ---- Actions ---- */

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
    }

    action arp_forward(bit<9> port) {
        // Forward ARP packet to specified port without modification
        standard_metadata.egress_spec = port;
    }

    action arp_broadcast() {
        // Broadcast ARP requests to all ports except incoming
        // For BMv2, we need to use multicast or simply drop and let controller handle
        // For simplicity, we'll forward to port 2 (normal path)
        standard_metadata.egress_spec = 2;
    }

    action rate_limit_arp() {
        // Drop ARP packet if rate limit exceeded
        mark_to_drop(standard_metadata);
    }

    /* ---- Tables ---- */

    // ARP rate limiting table (to be populated by controller)
    table arp_rate_limit {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            arp_forward;
            arp_broadcast;
            rate_limit_arp;
            NoAction;
        }
        size = 64;
        default_action = NoAction(); // Allow ARP, let arp_forwarding set port
    }

    // ARP forwarding table
    table arp_forwarding {
        key = {
            hdr.arp.target_proto_addr : exact;
        }
        actions = {
            arp_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop(); // Drop ARP for unknown targets
    }

    // Whitelist only known (src,dst) address pairs
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

    // Optional explicit per-flow override from controller (highest priority)
    table flow_policy {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            hdr.tcp.srcPort  : exact;
            hdr.tcp.dstPort  : exact;
        }
        actions = {
            set_use_vpn;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // Normal forwarding (to h2)
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

    // VPN forwarding (to VPN gateway host)
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
        // Handle ARP packets with rate limiting
        if (hdr.arp.isValid()) {
            // Apply rate limiting based on ingress port
            arp_rate_limit.apply();
            
            // If not dropped by rate limiter, forward based on target IP
            // Note: We can't check standard_metadata.drop directly
            // Instead, we'll always apply arp_forwarding, and if it fails, 
            // the rate_limit action already set the egress port
            arp_forwarding.apply();
            return;
        }

        // Only IPv4 traffic handled beyond this point
        if (!hdr.ipv4.isValid()) {
            drop();
            return;
        }

        // 1) Whitelist gate
        whitelist.apply();
        if (meta.allowed == 0) {
            drop();
            return;
        }

        // 2) "New flow / handshake" logic
        if (hdr.tcp.isValid()) {
            bit<1> syn = (bit<1>)((hdr.tcp.flags & 0x002) != 0);
            bit<1> ack = (bit<1>)((hdr.tcp.flags & 0x010) != 0);
            if (syn == 1 && ack == 0) {
                meta.use_vpn = 1;
            }
        }

        // 3) Controller override (if controller installs exact 5-tuple entries)
        if (hdr.tcp.isValid()) {
            flow_policy.apply();
        }

        // 4) DDoS / size steering based on packet length
        bit<16> plen = (bit<16>) standard_metadata.packet_length;

        if (plen >= DROP_TH) {
            drop();
            return;
        } else if (meta.use_vpn == 0 && plen >= VPN_TH) {
            meta.use_vpn = 1;
        }

        // 5) Forward based on chosen path
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

/* ========= Deparser ========= */
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/* ========= Main ========= */
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;