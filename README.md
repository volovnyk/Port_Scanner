Advanced Port Scanner
Advanced Port Scanner is a Python-based network reconnaissance tool that scans TCP ports on remote hosts, identifies active services, and collects service banners.

The tool performs concurrent scanning using multi-threading, supports custom port ranges, generates TXT and JSON reports, and provides detailed information about discovered network services.

Features
Concurrent TCP port scanning

Service identification

Banner grabbing

SSL/TLS service detection

IPv4 and IPv6 support

Custom port range scanning

Host availability verification

JSON report export

TXT report generation

Command-line interface (CLI)

Cross-platform support

Fully self-contained, no external services required

Detection Capabilities
Open port discovery

Network service identification

HTTP service probing

HTTPS service probing

SSH detection

FTP detection

Database service detection

Banner collection

Host connectivity verification

Technologies
Python

Sockets

ThreadPoolExecutor

JSON

SSL/TLS

TCP/IP

Network Reconnaissance

Multi-threading

Example Usage
python scanner.py scanme.nmap.org

python scanner.py example.com -p 20-1024

python scanner.py 192.168.1.10 --json report.json

Output
scan_report.txt
scan_results.json
Future Improvements
UDP scanning

OS fingerprinting

CIDR range scanning

Vulnerability detection

HTML reports

Web dashboard

Author
Sviatoslav Volovnyk

GitHub: github.com/volovnyk
