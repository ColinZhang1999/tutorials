/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;
typedef bit<9> egressSpec_t;

const bit<48> srcMacAddr = 0x080000000111;

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header count_t {
    bit<32> S2ByteCount;
    bit<32> S3ByteCount;
}

struct metadata {
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    count_t   count;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ethernet.srcAddr){
            srcMacAddr: parse_count;
            default: accept;
	    }
    }
    state parse_count{
        packet.extract(hdr.count);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(4) portCounter;
    register<bit<48>>(1) lastPktTime;
    register<bit<9>>(1) curPort;

    action set_curPort() {
        bit<48> lastTime;
        lastPktTime.read(lastTime, 0);
        bit<48> timeDiff = standard_metadata.ingress_global_timestamp - lastTime;
        bit<9> prevPort;
        curPort.read(prevPort, 0);
        bit<9> nextPort; 

        if (timeDiff > 200000) {
            nextPort = (prevPort + 1) % (bit<9>)2 + 2;
            lastTime = standard_metadata.ingress_global_timestamp;
        } else {
            nextPort = prevPort;
        }
        curPort.write(0, nextPort);
        lastPktTime.write(0, lastTime);
        standard_metadata.egress_spec = nextPort;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_ecmp_forward(macAddr_t dstAddr) {
	    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        bit<32> value;
        portCounter.read(value,(bit<32>)standard_metadata.egress_spec);
        value=value+(bit<32>)hdr.ipv4.totalLen;
        portCounter.write((bit<32>)standard_metadata.egress_spec,value);
    }

    action update_count(){
        portCounter.read(hdr.count.S2ByteCount,(bit<32>)2);
        portCounter.read(hdr.count.S3ByteCount,(bit<32>)3);
    }

    table ecmp_forward {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            drop;
            set_ecmp_forward;
        }
        size = 32;
    }

    action set_ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            drop;
            set_ipv4_forward;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            if (hdr.ethernet.srcAddr==srcMacAddr) {
                set_curPort();
                ecmp_forward.apply();
                update_count();
            } else{
                ipv4_forward.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
              hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.count);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
