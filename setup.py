#!/usr/bin/env python3
import sys
from subprocess import run

print("\033[1;47;41m[!] Do not quit while the package is being installed.")
print("\033[m")

run(["sudo", "pip", "install", "scapy"])
run(["sudo", "pip", "install", "scapy_http"])
run(["pip", "install", "-r", "requirements.txt"])
print()

sys.exit()