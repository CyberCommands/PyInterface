#!/usr/bin/env python3
import os
import sys
import time
import pandas
from scapy.all import *
from threading import Thread

# Initialize the networks dataframe that will contain all access points nearby.
networks = pandas.DataFrame(colums=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)   # Set the index BSSID (MAC address of the AP).

def call_back(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode()

        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)

def print_all():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(networks)
        time.sleep(0.5)

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        ch = ch % 14 + 1
        time.sleep(0.5)

if __name__ == "__main__":
    interface = sys.argv[1]     # Interface name, check using iwconfig.
    printer = Thread(target=print_all)  # Start the thread that prints all the networks.
    printer.daemon = True
    printer.start()

    channel_changer = Thread(target=change_channel)     # Start the channel changer.
    channel_changer.daemon = True
    channel_changer.start()
    # Start sniffing.
    sniff(prn=call_back, iface=interface)