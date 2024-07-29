#!/usr/bin/env python3
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import *
import socket, struct, pickle, os, time

from scapy.all import Ether, sniff, Packet, BitField, raw
import sys
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '/home/lbr/.local/lib/python3.8/site-packages'))
import scipy.stats


class CpuHeader(Packet):
    name='CpuPacket'
    fields_desc=[BitField('test',0,64),BitField('flows_0',0,8),BitField('flows_1',0,8),BitField('flows_2',0,8),BitField('flows_3',0,8),
                 BitField('flows_4',0,8),BitField('flows_5',0,8),BitField('flows_6',0,8),BitField('flows_7',0,8),
                 BitField('flows_8',0,8),BitField('flows_9',0,8),BitField('flows_10',0,8),BitField('light_or_heavy',0,8)]

class HeavyinfoHeader(Packet):
    name='HeavyinfoPacket'
    fields_desc=[BitField('ip1',0,32),BitField('ip2',0,32),BitField('r_multiple',0,32),BitField('light_or_heavy',0,8)]


class WXCController(object):

    def __init__(self, num_hashes=3):

        self.topo = load_topo('topology.json')
        self.controllers = {}
        # gets a controller API for each switch: {"s1": controller, "s2": controller...}
        self.connect_to_switches()

        # initializes the switch
        # resets all registers, configures the 3 x 2 hash functions
        # reads the registers
        # populates the tables and mirroring id
        self.init()
        self.registers = {}
        self.order=0
        self.count=0
        self.buffer={}

    def init(self):
        #self.reset_all_registers()
        
        self.read_registers()
        #self.configure_switches()
        self.add_clone_session()
        self.set_forward_rules()
        

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def configure_switches(self):

        for sw, controller in self.controllers.items():
            # ads cpu port
            controller.mirroring_add(100, 3)

            # set the basic forwarding rules
            controller.table_add("forwarding", "set_egress_port", ["1"], ["2"])
            controller.table_add("forwarding", "set_egress_port", ["2"], ["1"])

            # set the remove header rules when there is a host in a port
            direct_hosts = self.topo.get_hosts_connected_to(sw)
            for host in direct_hosts:
                port = self.topo.node_to_node_port_num(sw,host)
                controller.table_add("remove_loss_header", "remove_header", [str(port)], [])

    #不能这样直接用，要改一下 
    def add_clone_session(self):
        #for p4rtswitch,controller in self.controllers.items():

            #cpu_port =  self.topo.get_cpu_port_index(p4rtswitch)#得到交换机的cpu_port
            #if cpu_port:
                #controller.mirroring_add(5,[cpu_port])
        self.controllers['s3'].mirroring_add(5,4)
        #print (p4rtswitch,cpu_port)






    def set_forward_rules(self):


        
        self.controllers['s1'].table_add("MyIngress.ipv4_lpm","ipv4_forward",['10.0.1.1/32'],['00:00:0a:00:01:01','1'])
        self.controllers['s1'].table_add("MyIngress.ipv4_lpm","ipv4_forward",['10.0.2.1/24'],['00:00:0a:00:03:00','2'])
        self.controllers['s1'].table_add("MyIngress.ipv4_lpm","ipv4_forward",['10.0.3.1/24'],['00:00:0a:00:03:00','2'])
        
        self.controllers['s2'].table_add("MyIngress.ipv4_lpm","ipv4_forward",['10.0.2.2/32'],['00:00:0a:00:02:02','1'])
        self.controllers['s2'].table_add("MyIngress.ipv4_lpm","ipv4_forward",['10.0.1.1/24'],['00:00:0a:00:03:00','2'])
        self.controllers['s2'].table_add("MyIngress.ipv4_lpm","ipv4_forward",['10.0.3.1/24'],['00:00:0a:00:03:00','2'])


        self.controllers['s3'].table_add("MyIngress.ipv4_lpm","ipv4_forward",['10.0.3.3/32'],['00:00:0a:00:03:03','3'])
        self.controllers['s3'].table_add("MyIngress.ipv4_lpm","ipv4_forward",['10.0.2.2/24'],['00:00:0a:00:02:00','2'])
        self.controllers['s3'].table_add("MyIngress.ipv4_lpm","ipv4_forward",['10.0.1.1/24'],['00:00:0a:00:01:00','1'])
        
        
        self.controllers['s3'].table_add("MyIngress.what_todo","x_t",['0','0'],[])
        self.controllers['s3'].table_add("MyIngress.what_todo","x_n1",['0','1'],[])
        self.controllers['s3'].table_add("MyIngress.what_todo","x_n2",['0','2'],[])
        self.controllers['s3'].table_add("MyIngress.what_todo","y_t",['1','0'],[])
        self.controllers['s3'].table_add("MyIngress.what_todo","y_n1",['1','1'],[])
        self.controllers['s3'].table_add("MyIngress.what_todo","y_n2",['1','2'],[])
        

#23
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x800000&&&0x800000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x400000&&&0xc00000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x200000&&&0xe00000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x100000&&&0xf00000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x080000&&&0xf80000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x040000&&&0xfc0000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x020000&&&0xfe0000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x010000&&&0xff0000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x008000&&&0xff8000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x004000&&&0xffc000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x800000&&&0x800000','0x002000&&&0xffe000'],['10'],1)


        #22
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x800000&&&0x800000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x400000&&&0xc00000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x200000&&&0xe00000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x100000&&&0xf00000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x080000&&&0xf80000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x040000&&&0xfc0000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x020000&&&0xfe0000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x010000&&&0xff0000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x008000&&&0xff8000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x004000&&&0xffc000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x002000&&&0xffe000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x400000&&&0xc00000','0x001000&&&0xfff000'],['10'],1)


        #21
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x800000&&&0x800000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x400000&&&0xc00000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x200000&&&0xe00000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x100000&&&0xf00000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x080000&&&0xf80000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x040000&&&0xfc0000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x020000&&&0xfe0000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x010000&&&0xff0000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x008000&&&0xff8000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x004000&&&0xffc000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x002000&&&0xffe000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x001000&&&0xfff000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x200000&&&0xe00000','0x000800&&&0xfff800'],['10'],1)


        #20 
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x800000&&&0x800000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x400000&&&0xc00000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x200000&&&0xe00000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x100000&&&0xf00000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x080000&&&0xf80000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x040000&&&0xfc0000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x020000&&&0xfe0000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x010000&&&0xff0000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x008000&&&0xff8000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x004000&&&0xffc000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x002000&&&0xffe000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x001000&&&0xfff000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x000800&&&0xfff800'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x100000&&&0xf00000','0x000400&&&0xfffc00'],['10'],1)

        #19
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x800000&&&0x800000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x400000&&&0xc00000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x200000&&&0xe00000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x100000&&&0xf00000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x080000&&&0xf80000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x040000&&&0xfc0000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x020000&&&0xfe0000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x010000&&&0xff0000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x008000&&&0xff8000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x004000&&&0xffc000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x002000&&&0xffe000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x001000&&&0xfff000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x000800&&&0xfff800'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x000400&&&0xfffc00'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x080000&&&0xf80000','0x000200&&&0xfffe00'],['10'],1)

        #18
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x800000&&&0x800000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x400000&&&0xc00000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x200000&&&0xe00000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x100000&&&0xf00000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x080000&&&0xf80000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x040000&&&0xfc0000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x020000&&&0xfe0000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x010000&&&0xff0000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x008000&&&0xff8000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x004000&&&0xffc000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x002000&&&0xffe000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x001000&&&0xfff000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x000800&&&0xfff800'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x000400&&&0xfffc00'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x000200&&&0xfffe00'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x040000&&&0xfc0000','0x000100&&&0xffff00'],['10'],1)

        #17
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x800000&&&0x800000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x400000&&&0xc00000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x200000&&&0xe00000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x100000&&&0xf00000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x080000&&&0xf80000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x040000&&&0xfc0000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x020000&&&0xfe0000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x010000&&&0xff0000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x008000&&&0xff8000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x004000&&&0xffc000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x002000&&&0xffe000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x001000&&&0xfff000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x000800&&&0xfff800'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x000400&&&0xfffc00'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x000200&&&0xfffe00'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x000100&&&0xffff00'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x020000&&&0xfe0000','0x000080&&&0xffff80'],['10'],1)


        #16
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x800000&&&0x800000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x400000&&&0xc00000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x200000&&&0xe00000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x100000&&&0xf00000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x080000&&&0xf80000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x040000&&&0xfc0000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x020000&&&0xfe0000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x010000&&&0xff0000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x008000&&&0xff8000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x004000&&&0xffc000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x002000&&&0xffe000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x001000&&&0xfff000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x000800&&&0xfff800'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x000400&&&0xfffc00'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x000200&&&0xfffe00'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x000100&&&0xffff00'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x000080&&&0xffff80'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x010000&&&0xff0000','0x000040&&&0xffffc0'],['10'],1)

        #15
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x800000&&&0x800000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x400000&&&0xc00000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x200000&&&0xe00000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x100000&&&0xf00000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x080000&&&0xf80000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x040000&&&0xfc0000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x020000&&&0xfe0000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x010000&&&0xff0000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x008000&&&0xff8000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x004000&&&0xffc000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x002000&&&0xffe000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x001000&&&0xfff000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x000800&&&0xfff800'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x000400&&&0xfffc00'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x000200&&&0xfffe00'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x000100&&&0xffff00'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x000080&&&0xffff80'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x000040&&&0xffffc0'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x008000&&&0xff8000','0x000020&&&0xffffe0'],['10'],1)


        #14
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x800000&&&0x800000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x400000&&&0xc00000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x200000&&&0xe00000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x100000&&&0xf00000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x080000&&&0xf80000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x040000&&&0xfc0000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x020000&&&0xfe0000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x010000&&&0xff0000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x008000&&&0xff8000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x004000&&&0xffc000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x002000&&&0xffe000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x001000&&&0xfff000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x000800&&&0xfff800'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x000400&&&0xfffc00'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x000200&&&0xfffe00'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x000100&&&0xffff00'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x000080&&&0xffff80'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x000040&&&0xffffc0'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x000020&&&0xffffe0'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x004000&&&0xffc000','0x000010&&&0xfffff0'],['10'],1)

        #13
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x800000&&&0x800000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x400000&&&0xc00000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x200000&&&0xe00000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x100000&&&0xf00000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x080000&&&0xf80000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x040000&&&0xfc0000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x020000&&&0xfe0000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x010000&&&0xff0000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x008000&&&0xff8000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x004000&&&0xffc000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x002000&&&0xffe000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x001000&&&0xfff000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x000800&&&0xfff800'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x000400&&&0xfffc00'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x000200&&&0xfffe00'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x000100&&&0xffff00'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x000080&&&0xffff80'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x000040&&&0xffffc0'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x000020&&&0xffffe0'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x000010&&&0xfffff0'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x002000&&&0xffe000','0x000008&&&0xfffff8'],['10'],1)

        #12
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x400000&&&0xc00000'],['10'],1) 
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x200000&&&0xe00000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x100000&&&0xf00000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x080000&&&0xf80000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x040000&&&0xfc0000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x020000&&&0xfe0000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x010000&&&0xff0000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x008000&&&0xff8000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x004000&&&0xffc000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x002000&&&0xffe000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x001000&&&0xfff000'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000800&&&0xfff800'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000400&&&0xfffc00'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000200&&&0xfffe00'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000100&&&0xffff00'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000080&&&0xffff80'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000040&&&0xffffc0'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000020&&&0xffffe0'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000010&&&0xfffff0'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000008&&&0xfffff8'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x001000&&&0xfff000','0x000004&&&0xfffffc'],['10'],1)

        #11
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x200000&&&0xe00000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x100000&&&0xf00000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x080000&&&0xf80000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x040000&&&0xfc0000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x020000&&&0xfe0000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x010000&&&0xff0000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x008000&&&0xff8000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x004000&&&0xffc000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x002000&&&0xffe000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x001000&&&0xfff000'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000800&&&0xfff800'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000400&&&0xfffc00'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000200&&&0xfffe00'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000100&&&0xffff00'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000080&&&0xffff80'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000040&&&0xffffc0'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000020&&&0xffffe0'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000010&&&0xfffff0'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000008&&&0xfffff8'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000004&&&0xfffffc'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000800&&&0xfff800','0x000002&&&0xfffffe'],['10'],1)

        #10
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x100000&&&0xf00000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x080000&&&0xf80000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x040000&&&0xfc0000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x020000&&&0xfe0000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x010000&&&0xff0000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x008000&&&0xff8000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x004000&&&0xffc000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x002000&&&0xffe000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x001000&&&0xfff000'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000800&&&0xfff800'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000400&&&0xfffc00'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000200&&&0xfffe00'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000100&&&0xffff00'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000080&&&0xffff80'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000040&&&0xffffc0'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000020&&&0xffffe0'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000010&&&0xfffff0'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000008&&&0xfffff8'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000004&&&0xfffffc'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000002&&&0xfffffe'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000400&&&0xfffc00','0x000001&&&0xffffff'],['10'],1)

        #9
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x080000&&&0xf80000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x040000&&&0xfc0000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x020000&&&0xfe0000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x010000&&&0xff0000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x008000&&&0xff8000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x004000&&&0xffc000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x002000&&&0xffe000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x001000&&&0xfff000'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000800&&&0xfff800'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000400&&&0xfffc00'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000200&&&0xfffe00'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000100&&&0xffff00'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000080&&&0xffff80'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000040&&&0xffffc0'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000020&&&0xffffe0'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000010&&&0xfffff0'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000008&&&0xfffff8'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000004&&&0xfffffc'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000002&&&0xfffffe'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000001&&&0xffffff'],['9'],1)

        #8
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x040000&&&0xfc0000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x020000&&&0xfe0000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x010000&&&0xff0000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x008000&&&0xff8000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x004000&&&0xffc000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x002000&&&0xffe000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x001000&&&0xfff000'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000800&&&0xfff800'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000400&&&0xfffc00'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000200&&&0xfffe00'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000100&&&0xffff00'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000080&&&0xffff80'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000040&&&0xffffc0'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000020&&&0xffffe0'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000010&&&0xfffff0'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000008&&&0xfffff8'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000004&&&0xfffffc'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000002&&&0xfffffe'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000001&&&0xffffff'],['8'],1)

        #7
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x020000&&&0xfe0000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x010000&&&0xff0000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x008000&&&0xff8000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x004000&&&0xffc000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x002000&&&0xffe000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x001000&&&0xfff000'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000800&&&0xfff800'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000400&&&0xfffc00'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000200&&&0xfffe00'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000100&&&0xffff00'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000080&&&0xffff80'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000040&&&0xffffc0'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000020&&&0xffffe0'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000010&&&0xfffff0'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000008&&&0xfffff8'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000004&&&0xfffffc'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000002&&&0xfffffe'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000001&&&0xffffff'],['7'],1)

        #6
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x010000&&&0xff0000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x008000&&&0xff8000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x004000&&&0xffc000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x002000&&&0xffe000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x001000&&&0xfff000'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000800&&&0xfff800'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000400&&&0xfffc00'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000200&&&0xfffe00'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000100&&&0xffff00'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000080&&&0xffff80'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000040&&&0xffffc0'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000020&&&0xffffe0'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000010&&&0xfffff0'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000008&&&0xfffff8'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000004&&&0xfffffc'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000002&&&0xfffffe'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000001&&&0xffffff'],['6'],1)







#5


        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x008000&&&0xff8000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x004000&&&0xffc000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x002000&&&0xffe000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x001000&&&0xfff000'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000800&&&0xfff800'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000400&&&0xfffc00'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000200&&&0xfffe00'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000100&&&0xffff00'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000080&&&0xffff80'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000040&&&0xffffc0'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000020&&&0xffffe0'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000010&&&0xfffff0'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000008&&&0xfffff8'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000004&&&0xfffffc'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000002&&&0xfffffe'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000020&&&0xffffe0','0x000001&&&0xffffff'],['5'],1)

        #4
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x004000&&&0xffc000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x002000&&&0xffe000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x001000&&&0xfff000'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000800&&&0xfff800'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000400&&&0xfffc00'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000200&&&0xfffe00'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000100&&&0xffff00'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000080&&&0xffff80'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000040&&&0xffffc0'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000020&&&0xffffe0'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000010&&&0xfffff0'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000008&&&0xfffff8'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000004&&&0xfffffc'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000002&&&0xfffffe'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000010&&&0xfffff0','0x000001&&&0xffffff'],['4'],1)

        #3
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x002000&&&0xffe000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x001000&&&0xfff000'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000800&&&0xfff800'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000400&&&0xfffc00'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000200&&&0xfffe00'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000100&&&0xffff00'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000080&&&0xffff80'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000040&&&0xffffc0'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000020&&&0xffffe0'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000010&&&0xfffff0'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000008&&&0xfffff8'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000004&&&0xfffffc'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000002&&&0xfffffe'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000008&&&0xfffff8','0x000001&&&0xffffff'],['3'],1)

        #2
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x001000&&&0xfff000'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000800&&&0xfff800'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000400&&&0xfffc00'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000200&&&0xfffe00'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000100&&&0xffff00'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000080&&&0xffff80'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000040&&&0xffffc0'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000020&&&0xffffe0'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000010&&&0xfffff0'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000008&&&0xfffff8'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000004&&&0xfffffc'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000002&&&0xfffffe'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000004&&&0xfffffc','0x000001&&&0xffffff'],['2'],1)


        #1
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000800&&&0xfff800'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000400&&&0xfffc00'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000200&&&0xfffe00'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000100&&&0xffff00'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000080&&&0xffff80'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000040&&&0xffffc0'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000020&&&0xffffe0'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000010&&&0xfffff0'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000008&&&0xfffff8'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000004&&&0xfffffc'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000002&&&0xfffffe'],['0'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000002&&&0xfffffe','0x000001&&&0xffffff'],['1'],1)

        #0
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000400&&&0xfffc00'],['10'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000200&&&0xfffe00'],['9'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000100&&&0xffff00'],['8'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000080&&&0xffff80'],['7'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000040&&&0xffffc0'],['6'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000020&&&0xffffe0'],['5'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000010&&&0xfffff0'],['4'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000008&&&0xfffff8'],['3'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000004&&&0xfffffc'],['2'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000002&&&0xfffffe'],['1'],1)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000001&&&0xffffff','0x000001&&&0xffffff'],['0'],1)

        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000000&&&0xffffff','0x000000&&&0x000000'],['10'],2)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000000&&&0x000000','0x000000&&&0xffffff'],['10'],2)


        #即单向流 不是双向流
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000000&&&0xffffff','0x000200&&&0xfffe00'],['0'],3)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000000&&&0xffffff','0x000100&&&0xffff00'],['0'],3)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000000&&&0xffffff','0x000080&&&0xffff80'],['0'],3)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000000&&&0xffffff','0x000040&&&0xffffc0'],['0'],3)


        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000200&&&0xfffe00','0x000000&&&0xffffff'],['0'],3)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000100&&&0xffff00','0x000000&&&0xffffff'],['0'],3)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000080&&&0xffff80','0x000000&&&0xffffff'],['0'],3)
        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000040&&&0xffffc0','0x000000&&&0xffffff'],['0'],3)




        self.controllers['s3'].table_add("MyIngress.divide","set_r_multiple",['0x000000&&&0xffffff','0x000000&&&0xffffff'],['0'],4)

        #经测试 数字越大表示优先级越高




    def reset_all_registers(self):
        for sw, controller in self.controllers.items():
            for register in controller.get_register_arrays():
                controller.register_reset(register)

    def reset_registers(self, sw, stream, port, batch_id):
        start = (batch_id * REGISTER_BATCH_SIZE) + ((port-1) * REGISTER_PORT_SIZE)
        end = start + REGISTER_PORT_SIZE

        for register in self.controllers[sw].get_register_arrays():
            if stream in register:
                self.controllers[sw].register_write(register, [start, end], 0)

    def flow_to_bytestream(self, flow):
        # flow fields are: srcip , dstip, srcport, dstport, protocol, ip id
        return socket.inet_aton(flow[0]) + socket.inet_aton(flow[1]) + struct.pack(">HHBH",flow[2], flow[3], flow[4], flow[5])

    def read_registers(self):
        # reads all the registers
        self.registers = {sw: {} for sw in self.controllers.keys()}
        for sw, controller in self.controllers.items():
            for register in controller.get_register_arrays():
                self.registers[sw][register] = (controller.register_read(register))
                print(register)

    def extract_register_information(self, sw, stream, port, batch_id):
        # reads the region of a um or dm register: uses port, batch id.
        start = (batch_id * REGISTER_BATCH_SIZE) + ((port-1) * REGISTER_PORT_SIZE)
        end = start + REGISTER_PORT_SIZE
        res = {}
        for name, values in self.registers[sw].items():
            if stream in name:
                res[name] = values[start:end]

        return res

    def EMD(self,point1,point2):#计算距离（wasserstein距离）
        #dists = [i for i in range(len(point1))]
        dists=[0,2,4,8,16,32,64,128,256,512,1024]
        #dists=[0,1,4,9,16,25,36,49,64,81,100]
        D = scipy.stats.wasserstein_distance(dists, dists, point1, point2)
        return D



    def recv_msg_cpu(self,pkt):#试着加了一个参数switch_name  看能不能行:不能行
        
        packet=Ether(raw(pkt))
        if packet.type==0x1234 and self.order!=0:
            cpu_header = CpuHeader(bytes(packet.load))     
            #print('test',cpu_header.test)
            #print(cpu_header.flows_0,cpu_header.flows_1,cpu_header.flows_2,cpu_header.flows_3,
            #      cpu_header.flows_4,cpu_header.flows_5,cpu_header.flows_6,cpu_header.flows_7,
            #      cpu_header.flows_8,cpu_header.flows_9,cpu_header.flows_10,cpu_header.light_or_heavy)
        

            sum_flows=cpu_header.flows_0+cpu_header.flows_1+cpu_header.flows_2+cpu_header.flows_3+cpu_header.flows_4+cpu_header.flows_5+cpu_header.flows_6+cpu_header.flows_7+cpu_header.flows_8+cpu_header.flows_9+cpu_header.flows_10
            curr_wind=[float(cpu_header.flows_0/sum_flows),float(cpu_header.flows_1/sum_flows),float(cpu_header.flows_2/sum_flows),
                    float(cpu_header.flows_3/sum_flows),float(cpu_header.flows_4/sum_flows),float(cpu_header.flows_5/sum_flows),
                    float(cpu_header.flows_6/sum_flows),float(cpu_header.flows_7/sum_flows),float(cpu_header.flows_8/sum_flows),
                    float(cpu_header.flows_9/sum_flows),float(cpu_header.flows_10/sum_flows)]
            center_1=[0.187,0.003,0.001,0.001,0.001,0.003,0.002,0.021,0,0,0.781]
            center_0=[0.406,0.216,0.1,0.054,0.034,0.031,0.021,0.05,0,0,0.088]
            #print("curr_wind",curr_wind)
            D0=self.EMD(center_0,curr_wind)
            D1=self.EMD(center_1,curr_wind)
            if D0>D1:#说明是异常窗口
                self.count+=1
                if self.count==1:
                    self.controllers['s3'].register_write('state_flag', [0, 1], 1)
                elif self.count>=3:#就说明攻击发生了 该缓解了
                    #下发缓解表项
                    key_record=[]
                    for key,value in self.buffer.items():
                        if value>=3:
                            print("key",key)
                            #self.controllers['s3'].table_add("MyIngress.mitigation","drop",[str(key[0]),str(key[1])],[])
                            key_record.append(key)
                    for i in range(len(key_record)):
                        del(self.buffer[key_record[i]])
                    #self.controllers['s3'].register_write('state_flag',[0,1],0)
                    #self.count=0#这句话应该也删掉
                    #self.buffer.clear()#buffer不应该清空
            elif self.count>0:
                self.controllers['s3'].register_write('state_flag', [0, 1], 0)
                self.count=0
                self.buffer.clear()

            #print("emd_center0",self.EMD(center_0,curr_wind))
            #print("emd_center1",self.EMD(center_1,curr_wind))
        #else:
            #print("not 1234!")
        self.order=self.order+1
        #定位反射流
        if packet.type==0x4321:
            heavyinfo_header=HeavyinfoHeader(bytes(packet.load))
            flow_ID=(heavyinfo_header.ip1,heavyinfo_header.ip2)
            if heavyinfo_header.r_multiple>=9:
                if flow_ID not in self.buffer:
                    self.buffer[flow_ID]=1
                else:
                    self.buffer[flow_ID]+=1
                #print('buffer[flowID]',self.buffer[flow_ID])
            #print(heavyinfo_header.ip1,heavyinfo_header.ip2,heavyinfo_header.light_or_heavy)
        


    def run_cpu_port_loop(self):
        cpu_port_intf=str(self.topo.get_cpu_port_intf("s3").replace("eth0","eth1"))
        sniff(iface=cpu_port_intf,prn=self.recv_msg_cpu)


if __name__ == '__main__':
    #controller = WXCController()
    
    controller = WXCController().run_cpu_port_loop()

    '''
    print(len(list0))
    for i in range(0,len(list0)):
        with open('benign0-150.csv', 'a+', newline='') as file:
        #with open('attack-test.csv', 'a+', newline='') as file:
        #with open('drdos-attack-out.csv', 'a+', newline='') as file:
            writer = csv.writer(file) 
            writer.writerow(list0[i])
    '''
