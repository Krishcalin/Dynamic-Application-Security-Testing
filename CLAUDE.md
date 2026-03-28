# CLAUDE.md — DAST Scanner

## Project Overview

Single-file Dynamic Application Security Testing (DAST) scanner that actively crawls
and tests live web applications for OWASP Top 10 vulnerabilities, misconfigurations,
and information disclosure issues.

## Repository Structure

```
Dynamic-Application-Security-Testing/
├── dast_scanner.py              # Main scanner (single file)
├── banner.svg                   # Project banner
├── CLAUDE.md                    # This file
├── LICENSE                      # MIT License
├── README.md                    # Documentation
├── .gitignore                   # Python gitignore
└── tests/
    └── vulnerable_app.py        # Intentionally vulnerable test app (stdlib only)
```

## Architecture

- **File**: `dast_scanner.py` (~3,200 lines)
- **Version**: 1.2.0
- **Dependency**: `requests` (only external dependency)
- **Python**: 3.10+

### Key Classes

| Class | Purpose |
|-------|---------|
| `Finding` | Dataclass: rule_id, name, category, severity, url, method, parameter, payload, evidence, description, recommendation, cwe, owasp |
| `RateLimiter` | Token bucket rate limiter |
| `HTTPClient` | Scope-enforced, rate-limited HTTP client with session management |
| `_LinkFormParser` | stdlib HTML parser for link/form extraction |
| `WebCrawler` | BFS crawler with robots.txt/sitemap, form detection, JS endpoint extraction, tech fingerprint |
| `AuthManager` | 5 auth modes: none, bearer, cookie, basic, form |
| `DASTScanner` | Orchestrator: crawl → WAF detect → parallel checks → report |

### Check Functions (19 modules, 97 rules)

| Module | Rule IDs | Count | OWASP Category |
|--------|----------|-------|----------------|
| `check_injection` | DAST-INJ-001 to 007 | 7 | A03:2021 Injection |
| `check_xss` | DAST-XSS-001 to 005 | 5 | A03:2021 Injection |
| `check_auth_session` | DAST-AUTH-001 to 007 | 7 | A07:2021 Auth Failures |
| `check_access_control` | DAST-AC-001 to 004 | 4 | A01:2021 Broken Access Control |
| `check_info_disclosure` | DAST-INFO-001 to 011 | 11 | A02:2021 Crypto / A05:2021 Misconfig |
| `check_security_headers` | DAST-HDR-001 to 009 | 9 | A05:2021 Security Misconfiguration |
| `check_ssrf` | DAST-SSRF-001 to 003 | 3 | A10:2021 SSRF |
| `check_file_inclusion` | DAST-FI-001 to 003 | 3 | A03:2021 Injection |
| `check_xxe` | DAST-XXE-001 to 002 | 2 | A05:2021 Security Misconfiguration |
| `check_api_security` | DAST-API-001 to 004 | 4 | A05:2021 / A04:2021 |
| `check_jwt` | DAST-JWT-001 to 003 | 3 | A02:2021 Cryptographic Failures |
| `check_deserialization` | DAST-DES-001 to 004 | 4 | A08:2021 Software Integrity |
| `check_file_upload` | DAST-UPLOAD-001 to 004 | 4 | A04:2021 Insecure Design |
| `check_request_smuggling` | DAST-SMUG-001 to 003 | 3 | A05:2021 Security Misconfiguration |
| `check_websocket` | DAST-WS-001 to 003 | 3 | A07:2021 Auth Failures |
| `check_oauth` | DAST-OAUTH-001 to 004 | 4 | A07:2021 Auth Failures |
| `check_cache_poisoning` | DAST-CACHE-001 to 003 | 3 | A05:2021 Security Misconfiguration |
| `check_known_cves` | DAST-CVE-001 to 010 | 10 | A06:2021 Vulnerable Components |
| `check_cms` | DAST-CMS-001 to 008 | 8 | A05:2021 Misconfig / A06:2021 |

### Rule ID Format

`DAST-{CATEGORY}-{NNN}` (e.g. DAST-INJ-001, DAST-XSS-003, DAST-HDR-007)

## CLI

```bash
python dast_scanner.py <target_url> [--severity SEV] [--json FILE] [--html FILE]
    [-v/--verbose] [--version] [--crawl-depth N] [--max-pages N]
    [--rate-limit RPS] [--max-requests N] [--timeout SEC]
    [--no-crawl] [--verify-ssl] [--proxy URL]
    [--auth-mode MODE] [--auth-token TOKEN]
    [--login-url URL] [--login-user USER] [--login-pass PASS]
```

## Testing

```bash
# Start the vulnerable test app
python tests/vulnerable_app.py

# In another terminal, scan it
python dast_scanner.py http://127.0.0.1:5000 --verbose --html report.html --json report.json
```

## Conventions

- Single-file scanner, no submodules
- Generator-based check functions that yield `Finding` objects
- Check functions signature: `(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding]`
- ThreadPoolExecutor (4 workers) for parallel check execution
- Exit code: `1` if CRITICAL or HIGH findings, `0` otherwise
- HTML theme: orange-red gradient (#f97316 → #dc2626 → #991b1b)
- IMPORTANT: Active scanner — only scan apps you own or have authorisation to test
