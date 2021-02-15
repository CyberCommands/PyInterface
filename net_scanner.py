#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp

# IP Address for the destination.
target_ip = "192.168.1.1/24"

arp = ARP(pdst=target_ip)   # Create ARP packet.
ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Create the Ether broadcast packet.
packet = ether / arp

result = srp(packet, timeout=3, verbose=0)[0]

clients = []

for sent, received in result:
    # For each response, append ip and mac address to `clients` list.
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

print("Available devices in the network")
print("IP" + " "*18+"MAC")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))
