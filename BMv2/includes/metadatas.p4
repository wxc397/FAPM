struct metadata {
    /* empty */
    
    bit<1> direction;//0:forward   1:background
    //5-tuple
    
    bit<16> srcport;
    bit<16> dstport;
    
    bit<32> ip1;
    bit<32> ip2;
    bit<16> port1;
    bit<16> port2;   
    bit<8> protocol;
    
    @field_list(100)
    bit<32> ip1_heavy;
    @field_list(100)
    bit<32> ip2_heavy;
    @field_list(100)
    bit<16> port1_heavy;
    @field_list(100)
    bit<16> port2_heavy;   
    @field_list(100)
    bit<8> protocol_heavy;
    
    
    
    
    @field_list(100)
    bit<48> totallen;
    @field_list(100)
    bit<48> length_h1;
    @field_list(100)
    bit<48> length_h2; 
    @field_list(100)  
    bit<32> index_h1;
    @field_list(100)
    bit<32> index_h2;
    
    @field_list(100)
    bit<1> flag_x_y;
    @field_list(100)
    bit<2> flag_t_n1_n2;
    @field_list(100)
    bit<1> next_flag_x_y;
    @field_list(100)
    bit<2> next_flag_t_n1_n2;
    
    @field_list(100)
	bit<32> pointer_x;
	@field_list(100)
	bit<32> pointer_y;
	bit<32> reserving_flowindex_h1;
	bit<32> reserving_flowindex_h2;
	@field_list(100)
	bit<48> reserving_length_h1;
	@field_list(100)
	bit<48> reserving_length_h2;
    @field_list(100) 
    bit<24> o1;
    @field_list(100) 
    bit<24> o2;
  	
  	@field_list(100)  
    bit<48> last_wind_end;//the end timepoint of last window
    @field_list(100)
    bit<10> order;
    

    
    @field_list(100)
    bit<32> r_multiple; //2^x(0 1 2 3 4 5 6 7 8 9 10)
    bit<8> temp;
   

    
    @field_list(100)
    bit<8> flows_0;
    
    @field_list(100)
    bit<8> flows_1;
    
    @field_list(100)
    bit<8> flows_2;
    
    @field_list(100)
    bit<8> flows_3;
    
    @field_list(100)
    bit<8> flows_4;
    
    @field_list(100)
    bit<8> flows_5;
    
    @field_list(100)
    bit<8> flows_6;
    
    @field_list(100)
    bit<8> flows_7;
    
    @field_list(100)
    bit<8> flows_8;
    
    @field_list(100)  
    bit<8> flows_9;
    
    @field_list(100)
   	bit<8> flows_10;
    

	@field_list(100)
	bit<24> pac_length;
	@field_list(100)
	bit<24> h1_f;
	@field_list(100)
	bit<24> h1_b;
	@field_list(100)
	bit<24> h2_f;
	@field_list(100)
	bit<24> h2_b;

    @field_list(100)
    bit<64> test;
    
    
    @field_list(100)
    bit<32> srcip;
    @field_list(100)
    bit<32> dstip;

	@field_list(100)
    bit<1> light_or_heavy; 
    
    
    
}
