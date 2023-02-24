#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import (
    IP,
    TCP,
    Ether,
    get_if_hwaddr,
    get_if_list,
    sendp,
    Packet,
    IntField,
    bind_layers
)

class Count(Packet):
	name="Count"
	fields_desc=[  IntField("S2ByteCount",0), IntField("S3ByteCount",0) ]
bind_layers(TCP, Count)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    for i in range(100):
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535), seq=i) / Count(S2ByteCount=0,S3ByteCount=0) / ("a"*(i+1))
        sendp(pkt, iface=iface, verbose=False)



if __name__ == '__main__':
    main()
