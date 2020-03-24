#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print scapy_packet.show()
    #print packet.get_payload()
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0 , process_packet)
queue.run()
