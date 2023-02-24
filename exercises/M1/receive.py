#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff,
    Packet,
    TCP,
    bind_layers
)
from scapy.layers.inet import _IPOption_HDR

class Count(Packet):
    name="Count"
    fields_desc=[  IntField("S2ByteCount",0), IntField("S3ByteCount",0) ]
bind_layers(TCP, Count)

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234:
        print("got a packet")
        pkt.show2()
    print("Total Bytes = {0}".format(pkt[Count].S2ByteCount+pkt[Count].S3ByteCount))
    print("Lower path (via S2) = {0} bytes and upper path (via S3) = {1} bytes!".format(pkt[Count].S2ByteCount, pkt[Count].S3ByteCount))
    sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="tcp", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
