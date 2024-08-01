/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>



#include "includes/headers.p4"
#include "includes/metadatas.p4"
#include "includes/parser.p4"



/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/




/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/



/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    
    
    table mitigation{
    	key={
    		meta.ip1:exact;
    		meta.ip2:exact;
    	
    	}
    	actions={
    		drop;
    		NoAction;    	
    	}
    	size=200;
    	default_action=NoAction;
    
    
    }
    
    
    
    
    action set_direction(){
    	meta.direction=1w1; //default forward
    	
    	meta.totallen=((bit<48>)hdr.ipv4.totalLen)<<24;
    	meta.ip1=hdr.ipv4.srcAddr;
    	meta.ip2=hdr.ipv4.dstAddr;
    	meta.port1=meta.srcport;
    	meta.port2=meta.dstport;
    	
    	if(hdr.ipv4.srcAddr>hdr.ipv4.dstAddr) //backward
    	{
    		meta.direction=1w0;
    		meta.totallen=(bit<48>) hdr.ipv4.totalLen;
    		
    		meta.ip1=hdr.ipv4.dstAddr;
    		meta.ip2=hdr.ipv4.srcAddr;
    		meta.port1=meta.dstport;
    		meta.port2=meta.srcport;
    		
    	}
    }
    
    action get_index(){
    //extern void hash<O, T, D, M>(out O result, in HashAlgorithm algo, in T base, in D data, in M max);
    	hash(meta.index_h1,HashAlgorithm.crc32,32w0,{meta.ip1,meta.ip2,meta.port1,meta.port2,meta.protocol},32w100);
    	hash(meta.index_h2,HashAlgorithm.csum16,32w0,{meta.ip1,meta.ip2,meta.port1,meta.port2,meta.protocol},32w100);  
    }
    
    action get_last_wind_end(){
    
    	last_wind_end.read(meta.last_wind_end,0); 
    }

	action store_in_x(){
		hash1_x.read(meta.length_h1,meta.index_h1);
		hash2_x.read(meta.length_h2,meta.index_h2);
		hash1_x.write(meta.index_h1,meta.length_h1+meta.totallen);
		hash2_x.write(meta.index_h2,meta.length_h2+meta.totallen);
		
		
		//indicator_x.read(meta.pointer_x,0);
		//indicator_x.write(0,meta.pointer_x+1);
		//index1_x.write(meta.pointer_x,meta.index_h1);
		//index2_x.write(meta.pointer_x,meta.index_h2);
	}
	
	
	action store_in_y(){
		hash1_y.read(meta.length_h1,meta.index_h1);
		hash2_y.read(meta.length_h2,meta.index_h2);
		hash1_y.write(meta.index_h1,meta.length_h1+meta.totallen);
		hash2_y.write(meta.index_h2,meta.length_h2+meta.totallen);
	
		//indicator_y.read(meta.pointer_y,0);
		//indicator_y.write(0,meta.pointer_y+1);
		//index1_y.write(meta.pointer_y,meta.index_h1);
		//index2_y.write(meta.pointer_y,meta.index_h2);
	}
    
    
    
    action set_r_multiple(bit<32> x){
    
    	meta.r_multiple=x;
    	multiple_vector.read(meta.temp,x);	
    	multiple_vector.write(x,meta.temp+1);
    	
    	//if(x==32w10){
    		//meta.o1=meta.c[48:25];
    		//meta.o2=meta.c[24:1];
    	//}
    }
    action set_r_multiple_huge(){
    
    	meta.r_multiple=32w10;//1024
    	multiple_vector.read(meta.temp,10);
    	multiple_vector.write(10,meta.temp+1);
    	
    	//test_1024.write(0,24w2001);
    	//test_1024.write(0,24w223);
    }
    table divide{
    
    	key={
    	
    		meta.o1:ternary;
    		meta.o2:ternary;
    	}
		actions={
			set_r_multiple;
			set_r_multiple_huge;
		
		}
		size=1000;
		default_action=set_r_multiple_huge;
		    
    }
        
    action get_two_flag(){
    	flag_x_y.read(meta.flag_x_y,0);
    	flag_t_n1_n2.read(meta.flag_t_n1_n2,0);
    
    }
     

      
    
    action get_order_update(){
    	order.read(meta.order,0);
    	order.write(0,meta.order+1);
    	
    }
    
//six swapping modes 

	//1.action x_t()
	//2.action x_n1()
	//3.action x_n2()
	//4.action y_t()
	//5.action y_n1()
	//6.action y_n2()
	action x_t(){//collect
		//set_direction();
		get_index();
		store_in_x();
		
		last_wind_end.read(meta.last_wind_end,0); 
		meta.next_flag_x_y=0;
		meta.next_flag_t_n1_n2=0;
		 if(standard_metadata.ingress_global_timestamp-meta.last_wind_end>=WINDOW) //Wt end
    	 {
    	 	meta.next_flag_x_y=0;
    	 	meta.next_flag_t_n1_n2=1; //从Wt-->Wn1
    	 }
	
	}
	
	
	action y_t(){//collect
		//set_direction();
		get_index();
		store_in_y();
		
		last_wind_end.read(meta.last_wind_end,0); 
		meta.next_flag_x_y=1;
		meta.next_flag_t_n1_n2=0;
		 if(standard_metadata.ingress_global_timestamp-meta.last_wind_end>=WINDOW) //Wt end
    	 {
    	 	meta.next_flag_x_y=1;
    	 	meta.next_flag_t_n1_n2=1;// 从Wt-->Wn1
    	 }
		
	
	}
	
	
	action x_n1(){ //compute
		//set_direction();
		get_index();
		store_in_x();
		
		get_order_update();
		meta.next_flag_x_y=0;
		meta.next_flag_t_n1_n2=1;
		if(meta.order==LENGTH-1){
			meta.next_flag_x_y=0;
    		meta.next_flag_t_n1_n2=2;
		}

	}
	
	action y_n1(){ //compute
		//set_direction();
		get_index();
		store_in_y();
		
		
		get_order_update();
		meta.next_flag_x_y=1;
		meta.next_flag_t_n1_n2=1;
		if(meta.order==LENGTH-1){
			meta.next_flag_x_y=1;
    		meta.next_flag_t_n1_n2=2;
		}
			
	}
	
	action x_n2(){ //clear
		//set_direction();
		get_index();
		store_in_x();
		
		get_order_update();
		hash1_y.write((bit<32>)meta.order,48w0);
    	hash2_y.write((bit<32>)meta.order,48w0);
    	meta.next_flag_x_y=0;
		meta.next_flag_t_n1_n2=2;
    	if(meta.order==LENGTH-1){
			meta.next_flag_x_y=1;
    		meta.next_flag_t_n1_n2=0;
		}
		
		
	}
	
	action y_n2(){ //clear
		//set_direction();
		get_index();
		store_in_y();
		
		get_order_update();
		hash1_x.write((bit<32>)meta.order,48w0);
    	hash2_x.write((bit<32>)meta.order,48w0);
    	meta.next_flag_x_y=1;
		meta.next_flag_t_n1_n2=2;
		if(meta.order==LENGTH-1){
			meta.next_flag_x_y=0;
    		meta.next_flag_t_n1_n2=0;
		}
		
		
	}
	

 
    
    table what_todo{
    
    	key={
    		meta.flag_x_y:exact;
    		meta.flag_t_n1_n2:exact;
    	}
    	actions={
    		x_t;
    		x_n1;
    		x_n2;
    		y_t;
    		y_n1;
    		y_n2;
    		NoAction;
    	}
    	size=6;
    	default_action=NoAction();
    
    }
    

    
apply {
   if (hdr.ipv4.isValid()){
    	
    	set_direction();
    	if(mitigation.apply().hit==false){ //the packet belongs to benign flows
    	
    	
    	
    	get_two_flag();
    	what_todo.apply();
    	
    	state_flag.read(meta.light_or_heavy,0);
    	if(meta.length_h1==0 || meta.length_h2==0){ //only the new flow needs to be recorded the index
    		
    		
    		if(meta.flag_x_y==0){
    			indicator_x.read(meta.pointer_x,0);
				indicator_x.write(0,meta.pointer_x+1);
				index1_x.write(meta.pointer_x,meta.index_h1);
				index2_x.write(meta.pointer_x,meta.index_h2);
				if(meta.light_or_heavy==1){//还要记录flow_ID
					ip1_x.write(meta.pointer_x,meta.ip1);
					ip2_x.write(meta.pointer_x,meta.ip2);
					
				}
    		
    		}else{
    			indicator_y.read(meta.pointer_y,0);
				indicator_y.write(0,meta.pointer_y+1);
				index1_y.write(meta.pointer_y,meta.index_h1);
				index2_y.write(meta.pointer_y,meta.index_h2);
				if(meta.light_or_heavy==1){//还要记录flow_ID
					ip1_y.write(meta.pointer_y,meta.ip1);
					ip2_y.write(meta.pointer_y,meta.ip2);
					
				
				}
    		
    		}
    	
    	
    	}
    	
    	
    	
    	
    	if(meta.flag_t_n1_n2==1) //assisting computing the flows in the reserving sketch
    	{
    		if(meta.flag_x_y==0){
    			indicator_y.read(meta.pointer_y,0);
    			if(meta.pointer_y>0)
    			{
    				indicator_y.write(0,meta.pointer_y-1);
    				index1_y.read(meta.reserving_flowindex_h1,meta.pointer_y-1);
					index2_y.read(meta.reserving_flowindex_h2,meta.pointer_y-1);
    				hash1_y.read(meta.reserving_length_h1,meta.reserving_flowindex_h1);
					hash2_y.read(meta.reserving_length_h2,meta.reserving_flowindex_h2);	
					if(meta.light_or_heavy==1){
						ip1_y.read(meta.ip1_heavy,meta.pointer_y-1);
						ip2_y.read(meta.ip2_heavy,meta.pointer_y-1);
					
					}		
					
    			}
    			
    		}else {
    			indicator_x.read(meta.pointer_x,0);
    			if(meta.pointer_x>0)
    			{
    				indicator_x.write(0,meta.pointer_x-1);
    				index1_x.read(meta.reserving_flowindex_h1,meta.pointer_x-1);
					index2_x.read(meta.reserving_flowindex_h2,meta.pointer_x-1);
    				hash1_x.read(meta.reserving_length_h1,meta.reserving_flowindex_h1);
					hash2_x.read(meta.reserving_length_h2,meta.reserving_flowindex_h2);	
					if(meta.light_or_heavy==1){
						ip1_x.read(meta.ip1_heavy,meta.pointer_x-1);
						ip2_x.read(meta.ip2_heavy,meta.pointer_x-1);
						
					
					}				
					
    			}
    		}
    		
			if((meta.flag_x_y==0 && meta.pointer_y>0)||(meta.flag_x_y==1 && meta.pointer_x>0)){
			
    			if(meta.reserving_length_h1<meta.reserving_length_h2)
				{
					meta.o1=meta.reserving_length_h1[23:0];
					meta.o2=meta.reserving_length_h1[47:24];
		
				}else{
					meta.o1=meta.reserving_length_h2[23:0];
					meta.o2=meta.reserving_length_h2[47:24];
		
				}
				divide.apply();
				//upload heavy_info
				if(meta.light_or_heavy==1){
					clone_preserving_field_list(CloneType.I2E,5,100);
				}
			}
    		
    		
    	}

    		
		if(meta.flag_x_y!=meta.next_flag_x_y || meta.flag_t_n1_n2!=meta.next_flag_t_n1_n2){
		
			flag_x_y.write(0,meta.next_flag_x_y);
			flag_t_n1_n2.write(0,meta.next_flag_t_n1_n2);
			if(meta.next_flag_t_n1_n2==2){
				order.write(0,10w0);
				
				multiple_vector.read(meta.flows_0,0);multiple_vector.write(0,0);
    			multiple_vector.read(meta.flows_1,1);multiple_vector.write(1,0);
    			multiple_vector.read(meta.flows_2,2);multiple_vector.write(2,0);
    			multiple_vector.read(meta.flows_3,3);multiple_vector.write(3,0);
    			multiple_vector.read(meta.flows_4,4);multiple_vector.write(4,0);
    			multiple_vector.read(meta.flows_5,5);multiple_vector.write(5,0);
    			multiple_vector.read(meta.flows_6,6);multiple_vector.write(6,0);
    			multiple_vector.read(meta.flows_7,7);multiple_vector.write(7,0);
    			multiple_vector.read(meta.flows_8,8);multiple_vector.write(8,0);
    			multiple_vector.read(meta.flows_9,9);multiple_vector.write(9,0);
    			multiple_vector.read(meta.flows_10,10);multiple_vector.write(10,0);
				
				
				if(meta.flag_x_y==0){
					indicator_y.write(0,0);
				}else{
					indicator_x.write(0,0);
				}
				
				
				clone_preserving_field_list(CloneType.I2E,5,100);
				
				
				
			}else if(meta.next_flag_t_n1_n2==0){
				order.write(0,10w0);
				last_wind_end.write(0,standard_metadata.ingress_global_timestamp);

			}
		
		
		}
		
		
       	ipv4_lpm.apply();
       	test_order.read(meta.test,0);
       	test_order.write(0,meta.test+1);
        //clone_preserving_field_list(CloneType.I2E,5,100);     
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
    
        // If ingress clone
       if (standard_metadata.instance_type == 1 && meta.next_flag_t_n1_n2==2){//cloneType.I2E
            hdr.cpu.setValid();
            hdr.cpu.test=meta.test;
            
            
            hdr.cpu.flows_0=meta.flows_0;
            hdr.cpu.flows_1=meta.flows_1;
            hdr.cpu.flows_2=meta.flows_2;
            hdr.cpu.flows_3=meta.flows_3;
            hdr.cpu.flows_4=meta.flows_4;
            hdr.cpu.flows_5=meta.flows_5;
            hdr.cpu.flows_6=meta.flows_6;
            hdr.cpu.flows_7=meta.flows_7;
            hdr.cpu.flows_8=meta.flows_8;
            hdr.cpu.flows_9=meta.flows_9;
            hdr.cpu.flows_10=meta.flows_10;
            
            hdr.cpu.light_or_heavy=(bit<8>) meta.light_or_heavy;
		
            hdr.ethernet.etherType = TYPE_CLONE;
            
            
            truncate((bit<32>)34);//14+2+6+2+2=33
        
    }else if(standard_metadata.instance_type == 1 && meta.next_flag_t_n1_n2==1){
    	hdr.heavy_info.setValid();
    	hdr.heavy_info.ip1=meta.ip1_heavy;
    	hdr.heavy_info.ip2=meta.ip2_heavy;
    	
    	hdr.heavy_info.r_multiple=meta.r_multiple;
    	
    	hdr.heavy_info.light_or_heavy=(bit<8>)meta.light_or_heavy;
    	
    	hdr.ethernet.etherType=TYPE_HEAVY;
    	
    	truncate((bit<32>)27);//14+4+4+2+2+4+1=27  14+4+4+4+1
    
    }
        
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu);
        packet.emit(hdr.heavy_info);
        packet.emit(hdr.ipv4);
       	packet.emit(hdr.udp);
       	packet.emit(hdr.tcp);
        
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
