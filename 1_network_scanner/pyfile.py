#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    scapy.arping(ip)

scan("192.168.244.1/24")
