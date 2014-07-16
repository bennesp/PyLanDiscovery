Version 0.4a, 16 July 2014
---
- Added vendor column
- Code completely rewritten: ordered in classes and modules
- Improved order and performance of code deleting many useless
variables and threads
- Bugfix: auto-detect subnet also in adding to liststore
- Bugfix: buttons reaction fixed, first was too asynchronous

Version 0.3a, 16 July 2014
---
- Added two ProgressBar to the GUI, one for ICMP (slower) and one for
ARP+sniff modes.
- Added buttons to enable/disable ICMP, ARP, and sniff
- Methods ARP and ICMP disabled by default (they are too invasive)
- Added statically "This PC" to the list, colored of green
- Bugfix: auto-detect the interface, previously it was only "wlan0"
- Removed debug useless comments

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