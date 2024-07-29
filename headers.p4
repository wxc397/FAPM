#ifndef __HEADERS__
#define __HEADERS__


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_VLAN = 0x8100;// VLAN-tagged frame
const bit<8>    PROTO_TCP=6;
const bit<8>    PROTO_UDP=17;
const bit<16> TYPE_CLONE=0x1234;
const bit<16> TYPE_HEAVY=0x4321;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

#define WINDOW 100000  //单位微秒
#define LENGTH 100 //寄存器长度====一个窗口后半部分的固定包数大小


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


header cpu_t{

	bit<64> test;
	//bit<32> srcip;
	//bit<32> dstip;
	
   	//bit<8> flag_x_y;
   	//bit<8> flag_t_n1_n2;
   	//bit<16> order;
   	
   	//bit<24> o1;
   	//bit<24> o2;
    //bit<32> r_multiple;
   	 	
   	//bit<48> totallen;
   //bit<48> length_h1;
    //bit<48> length_h2; 
  
    //bit<32> index_h1;
    //bit<32> index_h2;
    //bit<48> reserving_length_h1;
    //bit<48> reserving_length_h2;
   	
   	//bit<32> pointer_x;
   	//bit<32> pointer_y;
   	
   	
    bit<8> flows_0;
    bit<8> flows_1;
    bit<8> flows_2;
    bit<8> flows_3;
    bit<8> flows_4;
    bit<8> flows_5;
    bit<8> flows_6;
    bit<8> flows_7;
    bit<8> flows_8;  
    bit<8> flows_9;
    bit<8> flows_10;
    
    
    
	//bit<24> pac_length;
	//bit<24> h1_f;
	//bit<24> h1_b;
	//bit<24> h2_f;
	//bit<24> h2_b;
	
	bit<8> light_or_heavy;
	
}

header heavy_info_t{
	
	bit<32> ip1;
	bit<32> ip2;
	
	bit<32> r_multiple;
	bit<8> light_or_heavy;

}


struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    vlan_wxc_t   vlan_wxc;
    tcp_t tcp;
    udp_t udp;
    cpu_t cpu;
    heavy_info_t heavy_info;
}



//定义寄存器
//假设现在有两个哈系函数
//两套寄存器结构

register<bit<48>>(LENGTH) hash1_x;//最低一位表示一个flag,是否已处理过该flow上一个窗口的信息
register<bit<48>>(LENGTH) hash2_x;
register<bit<48>>(LENGTH) hash1_y;
register<bit<48>>(LENGTH) hash2_y;


register<bit<32>>(LENGTH) index1_x;
register<bit<32>>(LENGTH) index2_x;
register<bit<32>>(LENGTH) index1_y;
register<bit<32>>(LENGTH) index2_y;

register<bit<32>>(1) indicator_x;//即counter
register<bit<32>>(1) indicator_y;
 
register<bit<1>> (1)flag_x_y;//0:x 1:y
register<bit<2>> (1)flag_t_n1_n2;//0:t 1:n1 2:n2


register<bit<48>> (1) last_wind_end;
register<bit<10>> (1) order;//Wn1,Wn2中进入窗口的次序

register<bit<8>>(11) multiple_vector;//特征向量

register<bit<64>>(1) test_order;

register<bit<1>>(1) state_flag;//0:lightweight 1:heavyweight
//heavyweight状态下需要记录的东西
register<bit<32>>(LENGTH) ip1_x;
register<bit<32>>(LENGTH) ip2_x;



register<bit<32>>(LENGTH) ip1_y;
register<bit<32>>(LENGTH) ip2_y;


//register<bit<8>>(11) flows_multiple;//记录每个窗口1～1024倍分别对应的流数目


//register<bit<24>>(2) test_1024;

#endif
