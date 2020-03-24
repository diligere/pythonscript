#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    #scapy_packet.show()
    if scapy_packet.haslayer(scapy.Raw):
        #print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80:
            print "http request"
            print scapy_packet.show()
        elif scapy_packet[scapy.TCP].sport == 80:
            print "http response"
            print scapy_packet.show() 
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
