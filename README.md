PyLanDiscovery
===

Discover the Computers in your LAN, thanks to ARP and ICMP multithreading!
Version 0.1a

<p align="center">
  <img src="http://imagizer.imageshack.us/v2/1280x1200q90/822/7p8t.png" alt="Version 0.1a" />
</p>

This script let you discover all Computers in your subnet, thanks to the
classic ICMP ping multithreading, to the ARP ping, and, in near future, to
sniffing in promiscuous mode.
The script requires to be run as Administrator, because scapy needs it.

Dependencies
---
The GUI is written in GTK3, and the script runs in Python + Scapy
On Ubuntu:

    sudo apt-get install python-scapy

FAQ
---
Why doesn't it work?
- Did you install python-scapy ?
- Did you run the script with sudo ? You should.
- Is your subnet "192.168.1.*" ? If not, correct it editing the script.
A feature to fix this will come soon.

Why I need it to run with sudo ?
- Because scapy, a module used, needs it to interact with low-level net.

But it is full of bugs!
- It's not a question :) And yes, it is an alpha.

Changelog
---
See CHANGELOG.md file :)
