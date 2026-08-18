# ULTRA-DAST v17.3 – Dynamic Application Security Testing Platform

**UltraDAST** is a comprehensive, open‑source DAST tool written in Python. It combines a powerful automated scanner, a Burp‑style intercepting proxy, a request repeater, and an intuitive GUI – all in a single executable script. It is designed to test modern web applications, REST/GraphQL/gRPC APIs, and microservices with a focus on **business logic flaws**, **race conditions**, and **advanced evasion**.

---

## Key Features (as implemented)

- **Full‑featured automated scanner** – Crawls SPAs (including Shadow DOM), extracts parameters, and injects thousands of payloads for 30+ vulnerability classes.
- **Business‑logic testing** – Finite State Machine (FSM) models user journeys (cart → checkout → payment) to test race conditions, inventory oversell, price tampering, and coupon stacking.
- **Modern API testing** – Native support for **GraphQL** (introspection, alias attacks, batching, depth‑bomb, IDOR via alias brute‑force), **gRPC** (reflection enumeration, protobuf fuzzing, type confusion), and **WebSockets**.
- **Intelligent verification pipeline** – 3‑stage validation (original → alternative → manual/OOB) with Surgical Mode: high‑confidence findings skip redundant checks, duplicates are suppressed, and gray‑zone issues are flagged for manual review.
- **Out‑of‑Band (OOB) detection** – Built‑in HTTP(S), DNS, and SMTP callback servers to detect blind vulnerabilities (e.g., Log4j, Blind XSS, SSRF).
- **Advanced evasion & obfuscation** – Semantic polyglots, Unicode homoglyphs, null‑byte interpolation, fullwidth characters, JA3 fingerprint rotation, and WAF‑specific bypasses (Cloudflare, AWS WAF, Sucuri).
- **Dynamic payload generation** – Environment detection (OS, web server, framework, WAF) to generate OS‑, framework‑, and WAF‑specific payloads, including encrypted and staged variants.
- **Proxy & Repeater** – Intercept and modify HTTP/S requests; replay requests with custom headers/body and view raw HTTP exchanges.
- **Rich GUI** – Multi‑tab interface with live log, endpoint progress tree, and an interactive findings table. Supports dark/light theme, config import/export, and PoC generation (cURL, Python, PowerShell, Metasploit).
- **Headless REST API** – Expose scanning functionality via a REST API for CI/CD integration (start/stop scans, fetch results, health checks).
- **Extensible reporting** – Export findings as **Burp XML**, **SARIF**, **JUnit XML**, **JSON**, or **PDF** (with proof‑of‑concept code snippets).
- **Safety controls** – Configurable maturity levels (0‑3) and a dry‑run mode to control aggressiveness and prevent accidental damage.

---

##  Requirements & Installation

- **Python 3.9+**
- **ChromeDriver** (for Selenium-based crawling) – must be in your `PATH`.

### Install dependencies

```bash
pip install aiohttp beautifulsoup4 selenium pyyaml graphql-core pyjwt \
            dnspython html5lib websockets grpcio grpcio-reflection \
            cvss PyQt5 reportlab cryptography asyncpg motor psutil
```

> All dependencies are optional; the script gracefully degrades if libraries are missing (e.g., GraphQL, gRPC, or WebSocket tests will be skipped).

### Run

```bash
python random_scanner.py
```

The script is self‑contained – no setup or packaging required.

---

## Quick Start

### GUI Mode

Launch the GUI:
```bash
python random_scanner.py
```

- Enter a target URL (e.g., `https://example.com`).
- Configure scan depth, threads, delay, and confidence threshold.
- Choose a **Maturity Level** (0–3) and optionally enable **Dry Run**.
- Click **Start Scan**.

### Command‑Line / Headless (REST API)

The built‑in REST API server allows programmatic control:

```python
from random_scanner import RESTAPIServer, OmegaDAST

# Create scanner instance
scanner = OmegaDAST(target="https://example.com", config={}, signals=None)

# Start API server
api = RESTAPIServer(host="127.0.0.1", port=8080)
api.set_scanner(scanner)
await api.start()
```

Available endpoints:
- `POST /api/scan` – start a scan (JSON body: `{"target_url": "...", "config": {...}}`)
- `GET /api/scan/{task_id}` – check status and results
- `DELETE /api/scan/{task_id}` – stop a scan
- `GET /api/results` – retrieve all results
- `GET /api/health` – health check

---

##  Configuration

UltraDAST is configured via a Python dictionary (or JSON) passed to the `OmegaDAST` constructor. The script’s top‑level docstring contains a comprehensive example. Below are key configuration sections:

### Proxy Pool

```json
{
  "proxy_pool": {
    "enable_rotation": true,
    "rotation_interval": 100,
    "health_check_interval": 300,
    "prefer_geo_diverse": true,
    "max_failure_rate": 0.5,
    "auto_healing_enabled": true,
    "sticky_session_enabled": true,
    "sticky_session_duration": 600,
    "proxies": [
      {"url": "proxy1.example.com:8080", "type": "http", "username": "user1", "password": "pass1", "country": "US"},
      {"url": "proxy2.example.com:1080", "type": "socks5", "country": "GB"}
    ]
  }
}
```

### IDS/IPS Throttling

```json
{
  "ids_ips_throttling": {
    "enabled": true,
    "max_requests_per_second": 10,
    "burst_capacity": 20,
    "min_requests_per_second": 0.1,
    "max_requests_per_second": 100
  }
}
```

### Intelligent Verification (Surgical Mode)

```json
{
  "intelligent_verification": {
    "enabled": true,
    "confidence_threshold": 95,
    "gray_zone_threshold": 10,
    "verification_rate_limit": 1,
    "discovery_rate_limit": 10,
    "off_peak_scheduling": true,
    "proximity_validation_sample_size": 3
  }
}
```

### GraphQL Advanced Testing

```json
{
  "graphql_advanced_testing": true,
  "graphql_depth_limit": 100,
  "graphql_batch_limit": 1000,
  "graphql_variables_support": true
}
```

### gRPC Advanced Testing

```json
{
  "grpc_advanced_testing": true,
  "grpc_ports": [50051, 50052, 8080],
  "grpc_fuzzing_intensity": 0.5
}
```

### Dynamic Payloads

```json
{
  "dynamic_payloads_enabled": true,
  "environment_detection_enabled": true,
  "use_encrypted_payloads": false,
  "use_staged_payloads": false
}
```

---

## Vulnerability Coverage

UltraDAST tests for the following vulnerability classes (non‑exhaustive):

- **Injection**: SQLi (error‑, time‑, boolean‑, union‑based), NoSQLi, LDAPi, Command Injection, SSTI, XXE, CRLF, Log4j, Spring4Shell, Text4Shell.
- **XSS**: Reflected, Stored, DOM‑based, Blind (with OOB), Self‑XSS (context‑aware filtering).
- **Access Control**: IDOR (sequential, UUID, bulk), Mass Assignment, Role Escalation, CORS misconfigurations, JWT attacks (alg=none, kid traversal, algorithm confusion).
- **Business Logic**: Race conditions (cart, checkout, inventory, coupon stacking), Price tampering, Payment bypass, OAuth flow issues (state parameter, redirect validation, PKCE).
- **Infrastructure**: Open ports (SSH, Redis, MySQL, PostgreSQL, RDP, SMB, MongoDB), Subdomain discovery, HTTP header analysis.
- **API‑Specific**: GraphQL introspection, batching, alias attacks, depth bombs, alias brute‑force for IDOR; gRPC reflection, message fuzzing, type confusion; WebSocket fuzzing.

---

## Reporting & Integrations

- **Export formats**: Burp XML, SARIF, JUnit XML, JSON, PDF (with PoC code).
- **Alert integrations**: Slack and JIRA webhooks (configurable via GUI).
- **PoC snippets**: cURL, Python, PowerShell, Metasploit module.

---

## Safety Controls (Reconnaissance Maturity Model)

| Level | Name        | Description                                                                 |
|-------|-------------|-----------------------------------------------------------------------------|
| 0     | Passive     | Crawl only – no attack payloads sent.                                       |
| 1     | Low & Slow  | Idempotent GET‑based payloads only (no state‑changing tests).               |
| 2     | Aggressive  | Time‑based SQLi, POST mutations, OOB tests.                                 |
| 3     | Nuclear     | Full capabilities: stacked queries, race conditions, and all advanced attacks. |

A **dry‑run** mode prints payloads without sending them – useful for SOC review.

---

## Known Limitations

- **Single‑file architecture** – While functional, the codebase is monolithic (~20,000 lines). Refactoring into a proper package is recommended for long‑term maintainability.
- **False positives** – Despite the verification pipeline, some false positives may still occur; manual triage is advised.
- **Dependency‑heavy** – Requires multiple third‑party libraries; missing libraries will disable corresponding features gracefully.
- **GUI performance** – The PyQt5 interface may be slow on large scans; use the REST API for headless operation in production environments.

---

## Legal & Responsible Use

**UltraDAST is intended solely for authorised security testing, research, and educational purposes.**  
Unauthorised scanning of systems you do not own or have explicit written permission to test is illegal in most jurisdictions. The authors assume no responsibility for misuse. Always obtain proper authorisation before running any security tool.

---

## Contributing

Contributions are welcome! Please:

- Fork the repository and create a feature branch.
- Adhere to PEP 8 coding style.
- Update inline documentation for new modules.
- Submit a pull request with a clear description of changes.

---

**UltraDAST – Built to catch what others miss.**
