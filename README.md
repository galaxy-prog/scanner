# Port Scanner

A multithreaded TCP/UDP port scanner with a graphical interface built in Python with Tkinter.

---

## Features

- Multithreaded TCP scan over a custom port range
- Full scan of all 65 536 ports (0-65535) in one click
- Preset buttons to quickly scan well-known, registered, dynamic or common ports
- UDP probe on a single port
- Automatic service name resolution (HTTP, SSH, FTP, etc.)
- Hostname resolution (accepts domain names in addition to IP addresses)
- Configurable connection timeout
- Option to show or hide closed ports in the report
- Real-time progress bar and status label
- Stop button to cancel a running scan at any time
- Export the scan report as a .txt file
- Scrollable interface that adapts to any screen size

---

## Requirements

Python 3.8 or higher is required. This project uses only Python standard library modules, so no external packages need to be installed.

See requirements.txt for the full list.

---

## Installation

```bash
git clone https://github.com/galaxy-prog/port-scanner.git
cd port-scanner
python port_scanner.py
```

No virtual environment or pip install is needed.

---

## Usage

1. Enter the target IP address or hostname in the Host field.
2. Set the connection timeout (default is 1.0 second, lower it for faster scans).
3. Choose a scan method:
   - Type a start and end port manually, then click Scan TCP.
   - Click one of the preset buttons to fill the range and start automatically.
   - Click Scan ALL ports to scan every port from 0 to 65535.
   - Enter a port number and click Scan UDP for a single UDP probe.
4. Use the Stop button to cancel at any time.
5. Toggle Show closed ports to include or exclude them from the report.
6. Click Export .txt to save the report to a file.

---

## Preset ranges

| Button | Range | Description |
|---|---|---|
| Well-known | 0 - 1023 | System ports (HTTP, SSH, FTP, DNS...) |
| Registered | 1024 - 49151 | Application ports |
| Dynamic | 49152 - 65535 | Ephemeral / private ports |
| Common | 20 - 443 | Most frequently used ports |

---

## Performance tips

- Lower the timeout to 0.3 or 0.2 seconds for faster scans on a local network.
- On a slow or remote network, keep the timeout at 1.0 second to avoid false negatives.
- A full scan (65 536 ports) with a 1.0 s timeout can take several minutes.
- With a 0.3 s timeout it typically completes in 2 to 4 minutes.

---

## UDP scanning

UDP is a connectionless protocol, so results are less reliable than TCP.

| Status | Meaning |
|---|---|
| open | A response was received on the port |
| closed | An ICMP port-unreachable message was received |
| open/filtered | No response (timeout) - port may be open or blocked by a firewall |

---

## Project structure

```
port-scanner/
├── port_scanner.py   # Main application
├── requirements.txt  # Dependency list
└── README.md         # This file
```

---

## Legal disclaimer

This tool is intended for educational purposes and for scanning systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction. The author assumes no responsibility for misuse of this software.

---

## License

MIT License - free to use, modify and distribute.
