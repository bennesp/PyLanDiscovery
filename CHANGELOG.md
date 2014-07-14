Version 0.2a, 15 July 2014
---
- Added a new scan method completely passive and very fast: Sniff
- Added a "Packets" column to the GUI, to show how many packets are captured
- Bugfix: Now it discovers the subnet in its own
- Bugfix: Unified multiple IP, that before were shown many times,
due to different scan methods
- Bugfix: Added locks for the multithreading, because, before, it
rarely crashed updating the GUI

Version 0.1a, 14 July 2014
---
- First Version
- Supported scan: ICMP mutlithreading, ARP
- Tiny GUI with GTK3