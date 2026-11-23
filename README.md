# portscan.py

A lightweight, standard-library-only TCP port scanner for Linux. Uses bounded multithreading to check open ports, grab service banners, and export results to CSV.

## Requirements

* Python 3.10+
* Linux (uses `/etc/services` via `socket.getservbyport` for service name lookup)

No external dependencies required.
