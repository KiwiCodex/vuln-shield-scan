# vuln-shield-scan
Legal Disclaimer: This tool is for educational purposes only. The author is not responsible for any misuse or damage caused by this program. Users are strictly advised to only scan targets they own or have explicit written permission to test.

# VulnShield: Automated Network & Web Security Auditor

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview
VulnShield is a modular security scanning tool designed for automated reconnaissance and risk assessment. Developed with a **Civil Engineering** mindset, the project emphasizes modular architecture, robust error handling, and professional reporting. 

It audits web infrastructure by analyzing HTTP security headers, verifying SSL/TLS certificate integrity, and identifying exposed services through socket-based port scanning.

## Key Features
- **Network Reconnaissance:** Multi-threaded port scanning using Python `socket` library to identify common service entry points.
- **Web Security Auditing:** In-depth analysis of HTTP response headers against OWASP security standards (HSTS, CSP, X-Frame-Options, etc.).
- **Cryptographic Verification:** SSL/TLS certificate validation, including issuer verification and expiration countdown.
- **Automated Reporting:** Generates professional, timestamped PDF reports for executive or technical review.

## Engineering Decisions
* **Modular Design:** The project follows the *Separation of Concerns* principle, isolating scanning logic from reporting and CLI handling.
* **Resilience:** Implemented comprehensive exception handling to manage connection timeouts and network-level failures without system crashes.
* **CLI UX:** Integrated `argparse` and `colorama` to provide a professional Command Line Interface experience.

## Installation & Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/KiwiCodex/vuln-shield-scan.git

2. Required libraries
   ```bash
   pip install -r requirements.txt
3. Command:
   ```bash
   python main.py -t [page] 
#Avoid using "https://", just the "domain name".com
