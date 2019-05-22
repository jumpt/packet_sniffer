#!/usr/bin/env python

import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # store means we are not storing packets in memory we are just printing them on screen


def process_sniffed_packet(packet):
    print(packet)


sniff("eth0")
