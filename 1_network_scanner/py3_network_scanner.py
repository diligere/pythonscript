#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def in_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t" , "--target" , dest = "target" , help = "Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
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
    info_list = []
    for item in resp_list:
        info_dict = {"ip":item[1].psrc , "mac":item[1].hwsrc}
        info_list.append(info_dict)
        #print item[1].show()
        #print "-------------------------------------------------"
        #print item[1].psrc + "\t\t" + item[1].hwsrc
        #print item[1].hwsrc
        #print "--------------------------------------------------"
    return info_list

def print_result(result_list):
    print ("IP\t\t\tMAC Address\n------------------------------------------")
    #print result_list
    for info in result_list:
        #print info
        print (info["ip"] + "\t\t" + info["mac"])

options = in_arguments()
scan_result = scan(options.target)
print_result(scan_result)
