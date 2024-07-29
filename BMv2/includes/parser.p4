

#include "headers.p4"


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
            TYPE_IPV4: parse_ipv4;
            TYPE_VLAN: parse_vlan_wxc;
            default: accept;
        }
    }

   
    state parse_vlan_wxc{
		packet.extract(hdr.vlan_wxc);
		transition parse_ipv4;
	
	}
    
    
   // state parse_vlan_wxc{
    
    	//packet.extract(hdr.vlan_wxc);
    	//transition select(hdr.vlan_wxc.etherType){
    		//TYPE_IPV4:parse_ipv4;
    	
    	//}
   // }
    
     state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.protocol=hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol){
        	PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
        }

    }
    
    state parse_udp{
    	packet.extract(hdr.udp);
    	meta.srcport=hdr.udp.srcPort;
    	meta.dstport=hdr.udp.dstPort;
    	transition accept;
    
    }
    
    state parse_tcp{
    	packet.extract(hdr.tcp);
    	meta.srcport=hdr.tcp.srcPort;
    	meta.dstport=hdr.tcp.dstPort;
    	transition accept;
    }
    
    
    

}

