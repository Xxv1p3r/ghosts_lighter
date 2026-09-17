# GHOSTS LIGHTER

Assessment Engine - Local - Fast - Actionable - Open Source

GHOSTS LIGHTER is a local, high-performance web application security assessment engine (DAST) designed for rapid, automated security audits aligned with the OWASP Top 10 (2025). It combines active crawling with optional Single Page Application (SPA) rendering via Playwright, passive JavaScript bundle analysis, comprehensive vulnerability testing, and multi-format reporting (including SARIF 2.1.0 for CI/CD integration).

---

## Key Features

- SPA-Aware Web Crawler: Recursive link and form discovery with optional dynamic headless Chromium rendering via Playwright.
- JavaScript Static Analysis: Passive extraction of API endpoints, hardcoded credentials, and secrets with automated masking.
- OWASP Top 10 Security Scanners:
  - SQL Injection (SQLi): Error-based signature matching, boolean-based differential analysis, and time-based blind detection with latency baseline confirmation.
  - Reflected Cross-Site Scripting (XSS): Contextual DOM reflection analysis across HTML body, attributes, and script tags.
  - Server-Side Template Injection (SSTI): Arithmetic expression evaluation across Jinja2, Twig, Freemarker, ERB, Smarty, and Razor engines with automated engine fingerprinting.
  - OS Command Injection: Output-based matching and blind time-based verification.
  - Directory / Path Traversal (LFI): Multi-OS path resolution (Linux and Windows), encoding bypasses, and PHP wrapper disclosure verification.
  - Server-Side Request Forgery (SSRF): Cloud metadata endpoints (AWS, GCP, Azure, Alibaba, DigitalOcean), loopback notation variants, file:// scheme handling, and blind timing oracles.
  - Insecure Open Redirect: Parameter tracing and destination validation.
  - GraphQL Introspection: Automated schema discovery and sensitive field extraction.
  - 403 / 401 Access Control Bypass: Header overrides (X-Forwarded-For, X-Original-URL, etc.), HTTP verb tampering, and path manipulation techniques.
  - IDOR / BOLA Auditing (Dual-Session): Horizontal privilege escalation testing (User A vs. User B), unauthenticated vertical privilege escalation checks, and automated RESTful ID tampering.
  - JWT Token Auditing: Unsigned tokens (alg: none), offline cryptographic cracking of weak HMAC secrets, sensitive claim identification, and expiration validation.
  - Security Headers Audit: HSTS, Content-Security-Policy (CSP), X-Frame-Options, and cookie security flags.
  - SSL/TLS Certificate Validation: Certificate expiry, hostname verification, and forced HTTPS redirection.
  - Technology Stack & Dependency Detection: Server fingerprinting and exposed package manifests (package.json, requirements.txt).
- Soft-404 Dynamic Calibration: Anti-false-positive mechanism tailored for modern SPAs and servers returning HTTP 200 on missing resources.
- Multi-Format Reporting:
  - HTML: Interactive dark-theme executive dashboard with OWASP categorization.
  - JSON: Machine-readable structured export for tool chaining.
  - SARIF 2.1.0: Native integration with GitHub Advanced Security and CI/CD pipelines.
  - Plain Text: Clean terminal summary.

---

## Installation

### Prerequisites
- Python 3.8+
- requests >= 2.28.0

### 1. Clone and Install

```bash
git clone https://github.com/Xxv1p3r/ghosts_lighter.git
cd ghosts_lighter

# Install package dependencies and register 'ghosts-lighter' CLI:
pip install -r requirements.txt

# Note for Parrot OS / Kali / Debian environments (PEP 668):
# pip install -r requirements.txt --break-system-packages
# or use a virtual environment:
# python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

### 2. (Optional) Headless Browser Support for SPAs

```bash
pip install -e ".[browser]"
playwright install chromium
```

---

## Usage

Run via the installed command-line entry point or directly through Python:

```bash
# Basic audit
ghosts-lighter http://example.local:3000

# Explicit target flag
ghosts-lighter -u http://example.local:3000
```

### Fast / CTF Mode
Enables headless browser bypass, sets page limit to 15, and uses a concise wordlist:

```bash
ghosts-lighter -u http://10.10.11.50:8000 -f
```

### Authenticated Audit with Custom Wordlist

```bash
ghosts-lighter http://127.0.0.1:8080 -a admin:password -w common.txt -o report.html
```

### Dual-Session IDOR / BOLA Audit

```bash
ghosts-lighter http://127.0.0.1:8080 \
  -a alice:password123 \
  --a2 bob:password456 \
  -l /login \
  -o report_idor.html
```

### Command-Line Arguments

| Parameter | Alias | Description |
|---|---|---|
| target_url | -u, -t, --url, --target | Target URL to assess (e.g., http://127.0.0.1:3000) |
| -f | --fast | Fast / CTF mode: activates --no-browser, --pages 15, -w quickhits.txt |
| -a | --auth | Session 1 credentials in user:password format (e.g., admin:admin) |
| -U | --user, --username | Session 1 username (default: admin) |
| -P | --pass, --password | Session 1 password (default: password) |
| --a2 | --auth2 | Session 2 credentials in user:password format for IDOR auditing |
| --u2 | --user2, --username2 | Session 2 secondary username for IDOR dual-session tests |
| --p2 | --pass2, --password2 | Session 2 secondary password for IDOR dual-session tests |
| -l | --login, --login-path | Specific login form endpoint path (default: /login) |
| -w | --wl, --wordlist | Custom dictionary for path scanning (resolves in ./wordlists/ or direct path) |
| -m | --pages, --max-pages | Maximum page crawl limit (default: 40) |
| -d | --depth, --max-depth | Maximum crawl depth (default: 2) |
| --no-browser | --no-selenium | Disables dynamic rendering via Playwright (headless browser) |
| -o | --out, --output | Path or filename for the generated report (.html, .json, .sarif) |
| --no-html | | Disables saving HTML report to disk |
| -v | --version | Display product version |

---

## Architecture Overview

```text
ghosts_lighter/
├── ghosts_lighter/
│   ├── auth/              # Login detection and authenticated session handling
│   │   ├── detector.py    # Heuristic discovery of login forms
│   │   └── session_auth.py# State management for cookies, CSRF, and bearer tokens
│   ├── core/              # Data models (ResultObject, metrics, CWE mappings)
│   ├── crawler/           # Recursive crawler and SPA Playwright renderer
│   ├── reporters/         # Multi-format report engine (HTML, JSON, SARIF 2.1.0)
│   ├── scanners/          # Specialized OWASP Top 10 security audit scanners
│   │   ├── manager.py     # Central audit orchestrator
│   │   ├── sqli.py        # SQL Injection scanner
│   │   ├── xss.py         # Reflected XSS scanner
│   │   ├── traversal.py   # Directory / Path Traversal scanner
│   │   ├── cmdi.py        # OS Command Injection scanner
│   │   ├── ssti.py        # Server-Side Template Injection scanner
│   │   ├── ssrf.py        # Server-Side Request Forgery scanner
│   │   ├── graphql.py     # GraphQL Introspection scanner
│   │   ├── bypass403.py   # 403 / 401 Access Control bypass scanner
│   │   ├── jwt.py         # JWT security audit scanner
│   │   └── idor.py        # IDOR / BOLA dual-session scanner
│   ├── cli.py             # Command line interface
│   └── config.py          # Centralized configuration, timeouts, and wordlists
├── tests/                 # Automated unit test suite
└── pyproject.toml         # Packaging configuration and entry point definition
```

---

## License

This project is licensed under the terms of the MIT License.  
Author: v1p3rx
