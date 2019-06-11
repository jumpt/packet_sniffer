#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # store means we are not storing packets in memory we are just printing them on screen
    #  filter= can contain "tcp" or "udp" or "port 80" its standard Berkeley Packet Filter (BPF) syntax, however this
    #  does not allow the capture of http, so we need a 3rd party app


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # the reason we use http here instead of Scapy.HTTPRequest is because scapy does not have ths function
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)
            # scapy.Raw just shows the Raw section of the packet and 'load' is the field we are interested in.
            # print(packet.show())
            # this will show all the packet layers, so we can find the layer that contains the info we want


sniff("eth0")
