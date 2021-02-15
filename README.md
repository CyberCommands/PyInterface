# Python for Network Interface
* Scripts for test network interface written in Python 3.

## Disclaimer
* All the provided tools are for testing and educational purposes only. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. The author assumes no liability and are not responsible for any misuse or damage caused by these tools.

## Description
| Script            | Description |
|-------------------|-------------|
| arper.py          | ARP Spoofing attack using Scapy to be able to be a man in the middle to monitor, intercept and modify packets in the network.|
| deauth.py         | Forcing devices to disconnect from a network by sending deauthentication frames continuously, this is called deauthentication attack.|
| dhcp_listener.py  | Listening for new Connected Devices in the Network using DHCP. |
| dnser.py          | DNS Spoofing attack to successfully change DNS cache of a target machine in the same network. **This script is designed to work on Linux because netfilterqueue library supported on Linux only.**|
| fake_access.py    | Fake access points and fooling nearby devices by sending valid beacon frames to the air. |
| net_scanner.py    | A simple network scanner using ARP requests and monitor the network. |
| wifi_scanner.py   | Finds and displays available nearby wireless networks and their MAC address, dBm signal, channel and encryption type.|


## Installation
```
git clone https://github.com/CyberCommads/PyInterface.git
```
```
cd PyInterface/
```
```
python3 setup.py
```

Example of usage:
```
sudo python3 arper.py -h
```
```
sudo python3 deauth -h
```
```
sudo python3 dhcp_listener.py
```

_Run `arper.py` then run this script.:_
```
sudo python3 dnser.py
```
and etc.