Scanning

This package covers:
- Service Version Detection
- Web App Vulnerability Scanner
- Vulnerability DB

### Port Scanning

The `Scanning` manager now includes built-in helpers for network port
scanning:

* **`tcp_scan`** – Performs a TCP connect scan.
* **`udp_scan`** – Probes UDP ports.
* **`stealth_scan`** – Runs a TCP SYN "stealth" scan (requires Scapy and
  elevated privileges).

#### Usage Examples

```python
from core.scanning import Scanning

scan = Scanning()

# TCP connect scan of common ports
scan.tcp_scan("192.168.0.10", ports="22,80,443")

# UDP scan of DNS and SNMP
scan.udp_scan("192.168.0.10", ports="53,161")

# SYN stealth scan of the first 1000 ports
scan.stealth_scan("scanme.nmap.org", ports="1-1000")
```

