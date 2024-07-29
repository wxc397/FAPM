#ifndef __HEADERS__
#define __HEADERS__


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_VLAN = 0x8100;// VLAN-tagged frame
const bit<8>    PROTO_TCP=6;
const bit<8>    PROTO_UDP=17;
const bit<16> TYPE_CLONE=0x1234;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;




header ethernet_t {//14
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}



header vlan_wxc_t{
	bit<3>  pcp;        // priority code point 
    bit<1>  dei;        // drop eligible indicator
    bit<12> vid;        // VLAN identifier
    bit<16> etherType;
}


header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen; //used
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr; //used
    ip4Addr_t dstAddr; //used
}


header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}




struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    vlan_wxc_t   vlan_wxc;
    tcp_t tcp;
    udp_t udp;
    
}



#endif
