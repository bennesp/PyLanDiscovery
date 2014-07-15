PyLanDiscovery
===

Discover the Computers in your LAN, thanks to Sniffing (Passive scan),
ARP and ICMP multithreading!

Version 0.3a

<p align="center">
  <img src="http://imageshack.com/a/img674/82/e32a51.png" alt="v.0.3a" />
</p>

This script let you discover all computers in your subnet, thanks to the
classic ICMP ping multithreading, to the ARP ping, and to the sniffing
of all packets on LAN, in promiscuous mode, in completely passive mode.
The script requires to be run as Administrator, because scapy needs it.

Dependencies
---
The GUI is written in GTK3, and the script runs in Python + Scapy

On Ubuntu:

    sudo apt-get install python-scapy

FAQ
---
Why it doesn't work?

- Did you install python-scapy ?
- Did you run the script with sudo ? You should.

Why I need it to run with sudo ?

- Because scapy, a module used, needs it to interact with low-level net.

But it is full of bugs!

- It's not a question :) And yes, it is an alpha. Anyway, if you would,
you can report a bug here, I will be happy to fix it.

Changelog
---
See CHANGELOG.md file :)
