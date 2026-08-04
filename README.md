# 🛡️ ULTRA-DAST v12.0 – The Unstoppable Pentester Platform

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: Custom](https://img.shields.io/badge/License-All%20Rights%20Reserved-red.svg)](https://opensource.org/licenses)
[![Security](https://img.shields.io/badge/Security-Research%20Only-orange.svg)](https://owasp.org/)

**ULTRA-DAST** is an enterprise-grade, all-in-one Dynamic Application Security Testing (DAST) framework. Built for professional penetration testers and red teams, it combines high-speed asynchronous scanning with advanced evasion techniques, business logic testing (race conditions, OAuth flows), API fuzzing (GraphQL/gRPC), genetic fuzzing, and local privilege escalation checks—all wrapped in a feature-rich PyQt5 GUI.

> **LEGAL WARNING:** Unauthorized scanning of networks or applications you do not own is **illegal** and constitutes a federal crime. This tool is intended for **authorized security testing**, bug bounty programs, and educational research only. The author assume no liability for misuse.

---

## Key Features

### Core Web Vulnerability Detection
- **Extensive Payload Library**: Covers XSS (Reflected/DOM/Blind), SQLi (Error/Time/Boolean/Union/2nd Order), SSTI, SSRF, XXE, Command Injection, Log4j, Spring4Shell, Text4Shell, and more.
- **Intelligent AST Parsing**: Uses Abstract Syntax Trees to detect SQL errors and small differences in responses, drastically reducing false positives.
- **3x Validation Engine**: Confirms findings with original, alternative, and manual-exploitation payloads, including remediation testing (CSP bypass, stacked queries).

### Advanced Evasion & Anti-Detection
- **Traffic Shaping**: Mimics human behavior with randomized request intervals, header order/casing, JA3 fingerprint rotation, and browser simulations (prefetch, favicon, CSS/JS).
- **Dynamic Payloads**: Auto-detects the target environment (OS, Web Server, Framework, WAF) and generates OS/framework-specific payloads with optional AES/XOR encryption and staged delivery.
- **IDS/IPS Throttling**: Token-bucket rate limiter with adaptive backoff (automatically slows down on 429/503 responses) to avoid rate-limiting blocks.

### Protocol & API Testing
- **GraphQL**: Full schema introspection, sensitive-field discovery, batching attacks (nested/mixed/resource-exhaustion), alias attacks (circular/combinatorial), and depth-bomb variations (deep nesting, circular fragments, directive abuse).
- **gRPC**: Service reflection analysis, message-type enumeration, and structured fuzzing (field mutation, type confusion, boundary testing).
- **WebSocket**: Fuzzing with injection payloads and reflection detection.

### Business Logic & Workflow Automation
- **Race Condition Testing**: Concurrent requests, timing analysis, inventory oversell (double-spend), token validation windows, and two-phase transaction races.
- **OAuth Flow Automation**: Tests authorization-code flows, implicit flows, token-race conditions, state-parameter validation, redirect manipulation, and PKCE enforcement.
- **Complex Purchase Sequences**: Cart manipulation, price tampering, coupon stacking, and payment-bypass testing.

### Local Privilege Escalation (Linux/Windows)
- Kernel vulnerability checks, SUID/SGID binaries, misconfigured services (systemd, cron), weak file/folder permissions, PATH/DLL hijacking, container escape vectors (Docker socket, K8s tokens), and password policy audits.

### Advanced Fuzzing & Taint Tracking
- **Genetic Fuzzer**: AFL++/libFuzzer-inspired byte-level fuzzing with mutation (bit-flips, insertions, arithmetic) and coverage-guided evolution.
- **Request Template Fuzzer**: Evolves HTTP templates (method, path, headers, body) to discover unexpected application behavior.
- **Taint Tracking & Symbolic Execution**: Dynamically tracks user-controlled inputs through the application and uses symbolic path exploration to predict sink contamination (SQL, Command, XSS).

### Out-Of-Band (OOB) Detection
- Built-in HTTP, HTTPS (self-signed TLS), DNS, ICMP, and SMTP callback servers to confirm blind vulnerabilities (Blind XSS, Blind SSRF, Log4j, Command Injection).

### Reporting & Exploitation
- **PoC Generation**: Auto-generates proof-of-concept exploits in **cURL**, **Python**, **PowerShell**, and **Metasploit** module formats.
- **Export Formats**: Burp XML, JUnit XML, SARIF, PDF, and full JSON reports.
- **Alerting**: Native integration with JIRA and Slack webhooks for real-time critical vulnerability notifications.

---

## GUI Overview

The tool runs via a multi-tabbed **PyQt5** desktop interface:

- **Scan Tab**: Configure target URL, depth, concurrency, dynamic payloads, traffic shaping, and taint tracking.
- **Repeater Tab**: Manually craft and send HTTP requests to test payloads interactively.
- **Proxy Tab**:
  - **MITM Proxy**: Intercept and inspect traffic.
  - **Proxy Pool**: Manage HTTP/HTTPS/SOCKS4/SOCKS5 proxies with health checks, geo-diverse rotation, and failure thresholds.
  - **IDS/IPS Throttling**: Fine-tune rate limits and burst capacities.
  - **Dynamic Payloads**: Toggle adaptive payload generation and environment detection.

---

##Installation

### Prerequisites
- **Python 3.8+**
- **Google Chrome** (for JS rendering)
- **ChromeDriver** (must be in your system `PATH`)

### Setup
# Clone or download the script
git clone https://github.com/LeonardoParchao/UltraDAST.git
cd ultra-dast

# Install dependencies
pip install -r requirements.txt

# Verify ChromeDriver compatibility
chromedriver --version

**`requirements.txt`:**

aiohttp
beautifulsoup4
selenium
pyyaml
graphql-core
pyjwt
dnspython
html5lib
websockets
grpcio
grpcio-reflection
cvss
PyQt5
reportlab
cryptography
```

---

## Quick Start

1.  **Run the GUI**:
    ```bash
    python random_scanner.py
    ```

2.  **Configure a Scan**:
    - Enter your target URL (e.g., `http://testphp.vulnweb.com`).
    - Adjust depth, threads, and delay as needed.
    - Enable **Traffic Shaping** and **Dynamic Payloads** for maximum evasion.

3.  **Start Scanning**:
    - Click the *Start* button.
    - Monitor the log and progress bar. Vulnerabilities will populate the Findings table in real-time.

4.  **Export Results**:
    - Right-click a finding to view evidence or the remediation guide.
    - Use the *File* menu to export reports in your preferred format (PDF, JSON, Burp XML, etc.).

---

##  Advanced Configuration Examples

### Proxy Pool Configuration
Configure rotating proxies with geo-diversity and health checks directly in the GUI's **Proxy Pool** tab, or pass a JSON configuration:

```json
{
    "proxy_pool": {
        "enable_rotation": true,
        "rotation_interval": 100,
        "proxies": [
            {"url": "proxy1.com:8080", "type": "http", "country": "US", "is_residential": false},
            {"url": "proxy2.com:1080", "type": "socks5", "country": "GB", "is_residential": true}
        ]
    }
}
```

### IDS/IPS Throttling
Prevent detection by shaping traffic patterns:

```json
{
    "ids_ips_throttling": {
        "enabled": true,
        "max_requests_per_second": 10,
        "burst_capacity": 20,
        "min_requests_per_second": 0.1
    }
}
```

### Dynamic Payload Generation
Adapt payloads to the target environment:

```json
{
    "dynamic_payloads_enabled": true,
    "environment_detection_enabled": true,
    "use_encrypted_payloads": true,
    "use_staged_payloads": false
}
```

---

## Command-Line Usage (Headless Mode)

While primarily GUI-driven, the core scanning engine can be invoked programmatically:

```python
from random_scanner import OmegaDAST
import asyncio

config = {
    'depth': 3,
    'threads': 50,
    'delay': 0.2,
    'js_render': True,
    'confidence_threshold': 75
}

scanner = OmegaDAST('http://target.com', config, signals=None)
asyncio.run(scanner.scan())
```

---

##  Architecture Overview

- **Crawler Engine**: Asynchronously discovers URLs, extracts parameters, and stores page hashes for deduplication.
- **Injection Engine**: Manages baseline caching, payload delivery, and detection via a pluggable `Detector` class.
- **Validation Engine**: Performs 3x validation (original, alternative, manual) and remediation testing.
- **Reporting Engine**: Handles CVSS scoring, PoC generation, and multi-format exports.
- **Session Manager**: Integrates traffic shaping, proxy pools, IDS throttling, and taint tracking.
- **OOB Manager**: Spin up HTTP/HTTPS/DNS/SMTP/ICMP callback listeners.

---

## Contributing

We welcome contributions from the security community! To contribute:

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes (`git commit -m 'Add some amazing feature'`).
4.  Push to the branch (`git push origin feature/amazing-feature`).
5.  Open a Pull Request.

**Please ensure**:
- All new payloads include detection logic in `Detector`.
- Complex logic includes unit tests (if applicable).
- You adhere to the existing code style (PEP 8 with async-first design).

---

## Disclaimer

**ULTRA-DAST** is a powerful security tool. With great power comes great responsibility.

- The developer do not endorse or support illegal activities.
- Users are solely responsible for ensuring they have explicit written permission to test any target.
- The software is provided "AS IS", without warranty of any kind.

---

## License

This project is proprietary and **All Rights Reserved**. Unauthorized copying, distribution, or modification of this software is strictly prohibited without prior written consent from the author.

---

## Acknowledgments

- Open-source libraries: `aiohttp`, `BeautifulSoup`, `Selenium`, `PyQt5`.
- Security research community for continuous payload and vulnerability discoveries.
- OWASP for maintaining industry standards.

---

**Made with love by me.**  
*Stay curious. Stay legal.*
```
