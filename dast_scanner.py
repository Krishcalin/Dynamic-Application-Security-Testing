#!/usr/bin/env python3
"""
Dynamic Application Security Testing (DAST) Scanner
Version : 1.0.0
License : MIT
Requires: Python 3.10+, requests (pip install requests)

Active web application security scanner that crawls and tests live web
applications for OWASP Top 10 vulnerabilities, misconfigurations, and
information disclosure issues.

IMPORTANT: Only scan applications you own or have explicit authorisation
to test.  Unauthorised scanning is illegal in most jurisdictions.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import html.parser
import json
import os
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any, Generator
from urllib.parse import (
    parse_qs, quote, urlencode, urljoin, urlparse, urlunparse,
)

__version__ = "1.0.0"

# ── Graceful dependency check ────────────────────────────────────────────────
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[ERROR] 'requests' library is required: pip install requests", file=sys.stderr)
    sys.exit(1)

# ════════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

USER_AGENT = "DAST-Scanner/1.0.0"
CANARY = "SKYHIGH"  # Non-executable marker for reflection detection
MAX_BODY_SNIPPET = 2000
DEFAULT_TIMEOUT = 15
DEFAULT_RATE_LIMIT = 10.0  # req/s
DEFAULT_MAX_REQUESTS = 10000
DEFAULT_MAX_PAGES = 500
DEFAULT_CRAWL_DEPTH = 5

EXCLUDED_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".zip", ".gz",
    ".tar", ".mp3", ".mp4", ".avi", ".webm", ".webp", ".map",
}

EXCLUDED_PATHS = {"/logout", "/signout", "/sign-out", "/api/logout", "/auth/logout"}

# ════════════════════════════════════════════════════════════════════════════════
#  DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    rule_id: str
    name: str
    category: str
    severity: str
    url: str
    method: str
    parameter: str
    payload: str
    evidence: str
    description: str
    recommendation: str
    cwe: str
    owasp: str  # OWASP Top 10 2021 category

@dataclass
class FormInfo:
    action: str
    method: str
    fields: list[dict]  # [{name, type, value}]
    source_url: str

@dataclass
class SiteMap:
    urls: set
    forms: list
    api_endpoints: list
    tech: dict  # {server, framework, cms, language}

# ════════════════════════════════════════════════════════════════════════════════
#  RATE LIMITER
# ════════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, rps: float) -> None:
        self._interval = 1.0 / max(rps, 0.1)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delta = self._interval - (now - self._last)
            if delta > 0:
                time.sleep(delta)
            self._last = time.monotonic()

# ════════════════════════════════════════════════════════════════════════════════
#  HTTP CLIENT (scope-enforced, rate-limited)
# ════════════════════════════════════════════════════════════════════════════════

class HTTPClient:
    """Scope-enforced, rate-limited HTTP client with evidence capture."""

    def __init__(self, allowed_hosts: set[str], rate_limit: float = DEFAULT_RATE_LIMIT,
                 max_requests: int = DEFAULT_MAX_REQUESTS, timeout: int = DEFAULT_TIMEOUT,
                 verify_ssl: bool = False, proxy: str | None = None,
                 custom_headers: dict | None = None) -> None:
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.headers["User-Agent"] = USER_AGENT
        if custom_headers:
            self._session.headers.update(custom_headers)
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}
        self._allowed_hosts = allowed_hosts
        self._limiter = RateLimiter(rate_limit)
        self._max_requests = max_requests
        self._request_count = 0
        self._lock = threading.Lock()
        self._timeout = timeout

    @property
    def request_count(self) -> int:
        return self._request_count

    def _check_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host in self._allowed_hosts or host == "127.0.0.1" or host == "localhost"

    def request(self, method: str, url: str, **kwargs) -> requests.Response | None:
        if not self._check_scope(url):
            return None
        with self._lock:
            if self._request_count >= self._max_requests:
                return None
            self._request_count += 1
        self._limiter.wait()
        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("allow_redirects", True)
        try:
            return self._session.request(method, url, **kwargs)
        except (requests.RequestException, Exception):
            return None

    def get(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("DELETE", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("HEAD", url, **kwargs)

    def set_cookie(self, name: str, value: str, domain: str) -> None:
        self._session.cookies.set(name, value, domain=domain)

    def set_auth_header(self, key: str, value: str) -> None:
        self._session.headers[key] = value

# ════════════════════════════════════════════════════════════════════════════════
#  HTML PARSER FOR FORM & LINK EXTRACTION
# ════════════════════════════════════════════════════════════════════════════════

class _LinkFormParser(html.parser.HTMLParser):
    """Extracts links, forms, and form fields from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._cur_form: dict | None = None
        self._cur_fields: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        if tag == "a" and "href" in a:
            self.links.append(a["href"])
        elif tag == "form":
            self._cur_form = {"action": a.get("action", ""), "method": a.get("method", "GET").upper()}
            self._cur_fields = []
        elif tag in ("input", "textarea", "select") and self._cur_form is not None:
            self._cur_fields.append({
                "name": a.get("name", ""),
                "type": a.get("type", "text"),
                "value": a.get("value", ""),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur_form is not None:
            self._cur_form["fields"] = self._cur_fields
            self.forms.append(self._cur_form)
            self._cur_form = None

# ════════════════════════════════════════════════════════════════════════════════
#  WEB CRAWLER
# ════════════════════════════════════════════════════════════════════════════════

class WebCrawler:
    """BFS web crawler with form detection and JS endpoint extraction."""

    def __init__(self, client: HTTPClient, base_url: str,
                 max_depth: int = DEFAULT_CRAWL_DEPTH,
                 max_pages: int = DEFAULT_MAX_PAGES,
                 verbose: bool = False) -> None:
        self._client = client
        self._base_url = base_url
        self._parsed_base = urlparse(base_url)
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._verbose = verbose

    def crawl(self) -> SiteMap:
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(self._base_url, 0)]
        forms: list[FormInfo] = []
        api_endpoints: list[str] = []
        tech: dict = {}

        # Pre-crawl: robots.txt + sitemap.xml
        robots_urls = self._parse_robots()
        for ru in robots_urls:
            queue.append((ru, 1))
        sitemap_urls = self._parse_sitemap()
        for su in sitemap_urls:
            queue.append((su, 1))

        while queue and len(visited) < self._max_pages:
            url, depth = queue.pop(0)
            norm = self._normalise(url)
            if norm in visited or depth > self._max_depth:
                continue
            if self._should_skip(norm):
                continue
            visited.add(norm)

            if self._verbose:
                print(f"  Crawling: {norm}")

            resp = self._client.get(norm)
            if resp is None:
                continue

            ct = resp.headers.get("Content-Type", "")
            if "text/html" not in ct and "application/xhtml" not in ct:
                continue

            # Technology fingerprint (once)
            if not tech:
                tech = self._fingerprint(resp)

            body = resp.text
            try:
                parser = _LinkFormParser()
                parser.feed(body)
            except Exception:
                continue

            # Extract links
            for href in parser.links:
                abs_url = urljoin(norm, href)
                abs_norm = self._normalise(abs_url)
                if abs_norm not in visited and self._is_same_host(abs_norm):
                    queue.append((abs_norm, depth + 1))

            # Extract forms
            for f in parser.forms:
                action = urljoin(norm, f["action"]) if f["action"] else norm
                forms.append(FormInfo(
                    action=action,
                    method=f["method"],
                    fields=f["fields"],
                    source_url=norm,
                ))

            # Extract JS API endpoints
            js_eps = re.findall(
                r'''(?:fetch|axios\.(?:get|post|put|delete)|\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE)['\"],\s*['\"])(['\"])(\/api\/[^'\"]+)\1''',
                body,
            )
            for _, ep in js_eps:
                full = urljoin(norm, ep)
                if full not in api_endpoints:
                    api_endpoints.append(full)

            # Also extract URL-like API paths
            api_matches = re.findall(r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']', body)
            for am in api_matches:
                full = urljoin(norm, am)
                if full not in api_endpoints:
                    api_endpoints.append(full)

        return SiteMap(urls=visited, forms=forms, api_endpoints=api_endpoints, tech=tech)

    def _normalise(self, url: str) -> str:
        parsed = urlparse(url)
        clean = parsed._replace(fragment="")
        return urlunparse(clean)

    def _is_same_host(self, url: str) -> bool:
        return urlparse(url).hostname == self._parsed_base.hostname

    def _should_skip(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in EXCLUDED_EXTENSIONS):
            return True
        if any(path.startswith(ep) for ep in EXCLUDED_PATHS):
            return True
        return False

    def _parse_robots(self) -> list[str]:
        urls: list[str] = []
        resp = self._client.get(urljoin(self._base_url, "/robots.txt"))
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.startswith("Disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        urls.append(urljoin(self._base_url, path))
        return urls[:20]  # Cap

    def _parse_sitemap(self) -> list[str]:
        urls: list[str] = []
        resp = self._client.get(urljoin(self._base_url, "/sitemap.xml"))
        if resp and resp.status_code == 200:
            locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", resp.text, re.I)
            urls = [loc for loc in locs if self._is_same_host(loc)]
        return urls[:50]  # Cap

    def _fingerprint(self, resp: requests.Response) -> dict:
        tech: dict = {"server": "", "framework": "", "cms": "", "language": ""}
        server = resp.headers.get("Server", "")
        if server:
            tech["server"] = server
        xpb = resp.headers.get("X-Powered-By", "")
        if xpb:
            tech["framework"] = xpb
        body = resp.text[:5000].lower()
        cookies = str(resp.cookies)
        if "phpsessid" in cookies.lower():
            tech["language"] = "PHP"
        elif "jsessionid" in cookies.lower():
            tech["language"] = "Java"
        elif "asp.net" in cookies.lower() or "asp.net" in xpb.lower():
            tech["language"] = ".NET"
        if "wp-content/" in body or "wordpress" in body:
            tech["cms"] = "WordPress"
        elif "__next_data__" in body:
            tech["framework"] = "Next.js"
        elif "react" in body and "__react" in body:
            tech["framework"] = "React"
        elif "ng-version" in body:
            tech["framework"] = "Angular"
        return tech

# ════════════════════════════════════════════════════════════════════════════════
#  WAF DETECTION
# ════════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "cookies": ["__cfduid", "cf_clearance"]},
    "AWS WAF": {"headers": ["x-amzn-waf-action"], "body": ["aws waf"]},
    "Imperva": {"headers": ["x-cdn"], "cookies": ["incap_ses_", "visid_incap_"]},
    "Akamai": {"headers": ["x-akamai-transformed"], "cookies": ["ak_bmsc"]},
    "ModSecurity": {"body": ["mod_security", "modsecurity"]},
    "F5 BIG-IP": {"headers": ["x-wa-info"], "cookies": ["TS"]},
    "Sucuri": {"headers": ["x-sucuri-id"]},
    "Barracuda": {"cookies": ["barra_counter_session"]},
}


def detect_waf(client: HTTPClient, target: str) -> dict:
    """Detect WAF by header/cookie/body signatures."""
    result = {"detected": False, "name": "", "evidence": []}

    # Benign probe
    resp = client.get(target)
    if resp is None:
        return result

    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    cookies_str = str(resp.cookies).lower()
    body = resp.text[:3000].lower()

    for waf_name, sigs in WAF_SIGNATURES.items():
        for h in sigs.get("headers", []):
            if h.lower() in hdrs:
                result.update(detected=True, name=waf_name, evidence=[f"Header: {h}"])
                return result
        for c in sigs.get("cookies", []):
            if c.lower() in cookies_str:
                result.update(detected=True, name=waf_name, evidence=[f"Cookie: {c}"])
                return result
        for b in sigs.get("body", []):
            if b.lower() in body:
                result.update(detected=True, name=waf_name, evidence=[f"Body: {b}"])
                return result

    # XSS probe to trigger WAF block
    resp2 = client.get(target, params={"dast_waf_test": "<script>alert(1)</script>"})
    if resp2 and resp2.status_code in (403, 406, 429, 503):
        result.update(detected=True, name="Unknown WAF", evidence=[f"Blocked XSS probe (HTTP {resp2.status_code})"])

    return result

# ════════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATION MANAGER
# ════════════════════════════════════════════════════════════════════════════════

class AuthManager:
    """Handles authentication for the DAST scanner."""

    CSRF_NAMES = {"csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
                  "_csrf", "authenticity_token", "__requestverificationtoken",
                  "xsrf_token", "_token", "antiforgery"}

    def __init__(self, client: HTTPClient, mode: str, token: str | None = None,
                 login_url: str | None = None, username: str | None = None,
                 password: str | None = None) -> None:
        self._client = client
        self._mode = mode
        self._token = token
        self._login_url = login_url
        self._username = username
        self._password = password

    def authenticate(self) -> bool:
        if self._mode == "none":
            return True
        if self._mode == "bearer":
            self._client.set_auth_header("Authorization", f"Bearer {self._token}")
            return True
        if self._mode == "basic":
            self._client.set_auth_header("Authorization",
                                         f"Basic {base64.b64encode(self._token.encode()).decode()}")
            return True
        if self._mode == "cookie":
            parts = self._token.split("=", 1) if self._token else ["session", ""]
            name = parts[0]
            value = parts[1] if len(parts) > 1 else ""
            domain = urlparse(self._login_url or "").hostname or "localhost"
            self._client.set_cookie(name, value, domain)
            return True
        if self._mode == "form":
            return self._form_login()
        return False

    def _form_login(self) -> bool:
        if not self._login_url or not self._username or not self._password:
            return False

        # Fetch login page for CSRF tokens
        resp = self._client.get(self._login_url)
        if resp is None:
            return False

        try:
            parser = _LinkFormParser()
            parser.feed(resp.text)
        except Exception:
            return False

        # Find login form (form with password field)
        login_form = None
        for f in parser.forms:
            has_pwd = any(fld.get("type") == "password" for fld in f["fields"])
            if has_pwd:
                login_form = f
                break

        if not login_form:
            return False

        # Build form data
        data: dict[str, str] = {}
        username_set = password_set = False
        for fld in login_form["fields"]:
            name = fld.get("name", "")
            if not name:
                continue
            ftype = fld.get("type", "text").lower()
            val = fld.get("value", "")

            if ftype == "hidden":
                data[name] = val  # CSRF tokens, etc.
            elif ftype == "password" and not password_set:
                data[name] = self._password
                password_set = True
            elif ftype in ("text", "email") and not username_set:
                nl = name.lower()
                if any(k in nl for k in ("user", "email", "login", "name", "account")):
                    data[name] = self._username
                    username_set = True
            elif ftype == "submit":
                data[name] = val or "Login"

        if not username_set:
            data["username"] = self._username
        if not password_set:
            data["password"] = self._password

        action = urljoin(self._login_url, login_form["action"]) if login_form["action"] else self._login_url
        method = login_form["method"]

        if method == "POST":
            resp2 = self._client.post(action, data=data, allow_redirects=True)
        else:
            resp2 = self._client.get(action, params=data, allow_redirects=True)

        if resp2 is None:
            return False

        body = resp2.text.lower()
        fail_patterns = ["invalid", "incorrect", "failed", "error", "wrong password", "login failed"]
        if any(fp in body for fp in fail_patterns):
            return False

        return True

# ════════════════════════════════════════════════════════════════════════════════
#  CHECK MODULES
# ════════════════════════════════════════════════════════════════════════════════

def _get_params(url: str) -> list[tuple[str, str]]:
    """Extract query parameters as (name, value) pairs."""
    qs = urlparse(url).query
    return [(k, v[0]) for k, v in parse_qs(qs, keep_blank_values=True).items()]


def _inject_param(url: str, param: str, value: str) -> str:
    """Replace a query parameter value in URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_qs = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_qs))


def _urls_with_params(sitemap: SiteMap) -> list[str]:
    """Return URLs that have query parameters."""
    return [u for u in sitemap.urls if "?" in u]

# ── 1. INJECTION CHECKS ─────────────────────────────────────────────────────

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ORA-\d{5}",
    r"pg_query\(\)",
    r"mysql_fetch",
    r"sqlite3\.OperationalError",
    r"SQLSTATE\[",
    r"Microsoft OLE DB Provider",
    r"syntax error at or near",
    r"com\.mysql\.jdbc",
    r"org\.postgresql",
    r"java\.sql\.SQLException",
]

SQL_PAYLOADS = ["'", "\"", "' OR '1'='1", "1; DROP TABLE", "' UNION SELECT NULL--", "1 AND 1=1"]
CMD_PAYLOADS = [";echo SKYHIGH", "|echo SKYHIGH", "$(echo SKYHIGH)", "`echo SKYHIGH`"]
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]
SSTI_MARKERS = ["49"]


def check_injection(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """SQL injection, command injection, SSTI, CRLF, NoSQL."""

    # ── DAST-INJ-001: SQL injection via URL params ──
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            for payload in SQL_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                resp = client.get(test_url)
                if resp is None:
                    continue
                body = resp.text
                for pat in SQL_ERROR_PATTERNS:
                    if re.search(pat, body, re.I):
                        yield Finding(
                            rule_id="DAST-INJ-001", name="SQL Injection (URL parameter)",
                            category="Injection", severity="CRITICAL",
                            url=test_url, method="GET", parameter=param,
                            payload=payload, evidence=re.search(pat, body, re.I).group()[:200],
                            description=f"SQL error triggered by injecting '{payload}' into parameter '{param}'.",
                            recommendation="Use parameterised queries or prepared statements. Never concatenate user input into SQL.",
                            cwe="CWE-89", owasp="A03:2021 Injection",
                        )
                        break  # One finding per param per payload
                else:
                    continue
                break

    # ── DAST-INJ-002: SQL injection via forms ──
    for form in sitemap.forms:
        for fld in form.fields:
            if fld.get("type") in ("hidden", "submit", "file"):
                continue
            fname = fld.get("name", "")
            if not fname:
                continue
            for payload in SQL_PAYLOADS[:3]:  # Limit for forms
                data = {f.get("name", ""): f.get("value", "") for f in form.fields if f.get("name")}
                data[fname] = payload
                if form.method == "POST":
                    resp = client.post(form.action, data=data)
                else:
                    resp = client.get(form.action, params=data)
                if resp is None:
                    continue
                for pat in SQL_ERROR_PATTERNS:
                    if re.search(pat, resp.text, re.I):
                        yield Finding(
                            rule_id="DAST-INJ-002", name="SQL Injection (form input)",
                            category="Injection", severity="CRITICAL",
                            url=form.action, method=form.method, parameter=fname,
                            payload=payload, evidence=re.search(pat, resp.text, re.I).group()[:200],
                            description=f"SQL error triggered via form field '{fname}'.",
                            recommendation="Use parameterised queries. Validate and sanitise all form inputs.",
                            cwe="CWE-89", owasp="A03:2021 Injection",
                        )
                        break
                else:
                    continue
                break

    # ── DAST-INJ-003: OS command injection ──
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            for payload in CMD_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                resp = client.get(test_url)
                if resp and CANARY in resp.text:
                    yield Finding(
                        rule_id="DAST-INJ-003", name="OS Command Injection",
                        category="Injection", severity="CRITICAL",
                        url=test_url, method="GET", parameter=param,
                        payload=payload, evidence=f"Canary '{CANARY}' reflected in response",
                        description=f"Command injection via parameter '{param}'.",
                        recommendation="Never pass user input to shell commands. Use safe APIs.",
                        cwe="CWE-78", owasp="A03:2021 Injection",
                    )
                    break

    # ── DAST-INJ-004: Server-Side Template Injection ──
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            for payload in SSTI_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                resp = client.get(test_url)
                if resp and any(m in resp.text for m in SSTI_MARKERS):
                    # Verify it's not just "49" appearing naturally
                    baseline = client.get(_inject_param(url, param, "harmless"))
                    if baseline and "49" not in baseline.text:
                        yield Finding(
                            rule_id="DAST-INJ-004", name="Server-Side Template Injection (SSTI)",
                            category="Injection", severity="CRITICAL",
                            url=test_url, method="GET", parameter=param,
                            payload=payload, evidence="Template expression evaluated: 7*7=49",
                            description=f"SSTI detected via parameter '{param}'.",
                            recommendation="Never render user input in templates. Use sandboxed template engines.",
                            cwe="CWE-1336", owasp="A03:2021 Injection",
                        )
                        break

    # ── DAST-INJ-005: CRLF injection ──
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            payload = "test%0d%0aX-DAST-Injected:true"
            test_url = _inject_param(url, param, payload)
            resp = client.get(test_url)
            if resp and "x-dast-injected" in {k.lower(): v for k, v in resp.headers.items()}:
                yield Finding(
                    rule_id="DAST-INJ-005", name="CRLF Injection",
                    category="Injection", severity="HIGH",
                    url=test_url, method="GET", parameter=param,
                    payload=payload, evidence="Injected header X-DAST-Injected found in response",
                    description=f"HTTP header injection via CRLF in parameter '{param}'.",
                    recommendation="URL-encode or strip CR/LF characters from user input.",
                    cwe="CWE-93", owasp="A03:2021 Injection",
                )

    # ── DAST-INJ-006: NoSQL injection ──
    nosql_payloads = ['{"$gt": ""}', '{"$ne": ""}', '[$ne]=']
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            for payload in nosql_payloads:
                test_url = _inject_param(url, param, payload)
                resp = client.get(test_url)
                baseline = client.get(url)
                if resp and baseline and resp.status_code == 200 and len(resp.text) > len(baseline.text) * 1.5:
                    yield Finding(
                        rule_id="DAST-INJ-006", name="NoSQL Injection",
                        category="Injection", severity="HIGH",
                        url=test_url, method="GET", parameter=param,
                        payload=payload, evidence=f"Response significantly larger ({len(resp.text)} vs {len(baseline.text)} bytes)",
                        description=f"Possible NoSQL injection via parameter '{param}'.",
                        recommendation="Sanitise user input. Use parameterised NoSQL queries.",
                        cwe="CWE-943", owasp="A03:2021 Injection",
                    )
                    break

    # ── DAST-INJ-007: Time-based blind SQL ──
    time_payloads = ["' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "' OR pg_sleep(5)--"]
    for url in list(_urls_with_params(sitemap))[:5]:  # Limit -- time-based is slow
        for param, orig_val in _get_params(url):
            # Baseline timing
            t0 = time.monotonic()
            baseline = client.get(url)
            baseline_time = time.monotonic() - t0
            if baseline is None:
                continue
            for payload in time_payloads:
                test_url = _inject_param(url, param, payload)
                t0 = time.monotonic()
                resp = client.get(test_url)
                elapsed = time.monotonic() - t0
                if resp and elapsed > baseline_time + 4.0:
                    yield Finding(
                        rule_id="DAST-INJ-007", name="Blind SQL Injection (time-based)",
                        category="Injection", severity="CRITICAL",
                        url=test_url, method="GET", parameter=param,
                        payload=payload, evidence=f"Response delayed by {elapsed - baseline_time:.1f}s",
                        description=f"Time-based blind SQL injection via parameter '{param}'.",
                        recommendation="Use parameterised queries. Implement WAF rules for time-based payloads.",
                        cwe="CWE-89", owasp="A03:2021 Injection",
                    )
                    break

# ── 2. XSS CHECKS ───────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    f"<{CANARY}xss>",
    f'"><img onerror={CANARY} src=x>',
    f"<script>{CANARY}</script>",
    f"javascript:{CANARY}",
    f"' onfocus='{CANARY}' autofocus='",
]

DOM_XSS_SINKS = [
    "document.write", ".innerHTML", "eval(", "setTimeout(",
    "setInterval(", "document.location", "window.location",
]


def check_xss(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """Reflected XSS, DOM XSS indicators, header-based XSS."""

    # ── DAST-XSS-001: Reflected XSS via URL params ──
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            for payload in XSS_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                resp = client.get(test_url)
                if resp and CANARY in resp.text:
                    yield Finding(
                        rule_id="DAST-XSS-001", name="Reflected XSS (URL parameter)",
                        category="XSS", severity="HIGH",
                        url=test_url, method="GET", parameter=param,
                        payload=payload, evidence=f"Canary '{CANARY}' reflected in response body",
                        description=f"Reflected XSS via URL parameter '{param}'.",
                        recommendation="Encode output in HTML context. Implement Content-Security-Policy.",
                        cwe="CWE-79", owasp="A03:2021 Injection",
                    )
                    break

    # ── DAST-XSS-002: Reflected XSS via forms ──
    for form in sitemap.forms:
        for fld in form.fields:
            if fld.get("type") in ("hidden", "submit", "file", "password"):
                continue
            fname = fld.get("name", "")
            if not fname:
                continue
            for payload in XSS_PAYLOADS[:3]:
                data = {f.get("name", ""): f.get("value", "") for f in form.fields if f.get("name")}
                data[fname] = payload
                if form.method == "POST":
                    resp = client.post(form.action, data=data)
                else:
                    resp = client.get(form.action, params=data)
                if resp and CANARY in resp.text:
                    yield Finding(
                        rule_id="DAST-XSS-002", name="Reflected XSS (form input)",
                        category="XSS", severity="HIGH",
                        url=form.action, method=form.method, parameter=fname,
                        payload=payload, evidence=f"Canary '{CANARY}' reflected in response body",
                        description=f"Reflected XSS via form field '{fname}'.",
                        recommendation="Encode all user input before rendering. Use CSP headers.",
                        cwe="CWE-79", owasp="A03:2021 Injection",
                    )
                    break

    # ── DAST-XSS-003: DOM-based XSS indicators ──
    checked: set[str] = set()
    for url in list(sitemap.urls)[:30]:
        if url in checked:
            continue
        checked.add(url)
        resp = client.get(url)
        if resp is None:
            continue
        for sink in DOM_XSS_SINKS:
            if sink in resp.text:
                yield Finding(
                    rule_id="DAST-XSS-003", name="DOM-based XSS indicator",
                    category="XSS", severity="MEDIUM",
                    url=url, method="GET", parameter="",
                    payload="", evidence=f"Dangerous sink '{sink}' found in JavaScript",
                    description=f"DOM XSS sink '{sink}' detected in page source.",
                    recommendation="Avoid using dangerous DOM sinks. Sanitise data before DOM insertion.",
                    cwe="CWE-79", owasp="A03:2021 Injection",
                )
                break  # One per page

    # ── DAST-XSS-004: XSS via HTTP headers ──
    resp = client.get(target, headers={"Referer": f"https://evil.com/{CANARY}header"})
    if resp and f"{CANARY}header" in resp.text:
        yield Finding(
            rule_id="DAST-XSS-004", name="XSS via HTTP header reflection",
            category="XSS", severity="MEDIUM",
            url=target, method="GET", parameter="Referer",
            payload=f"https://evil.com/{CANARY}header", evidence="Referer header reflected in body",
            description="HTTP Referer header value reflected in HTML without encoding.",
            recommendation="Never render HTTP headers in HTML responses without encoding.",
            cwe="CWE-79", owasp="A03:2021 Injection",
        )

    # ── DAST-XSS-005: XSS in error pages ──
    parsed = urlparse(target)
    err_url = urlunparse(parsed._replace(path=f"/nonexistent_{CANARY}err"))
    resp = client.get(err_url)
    if resp and f"{CANARY}err" in resp.text:
        yield Finding(
            rule_id="DAST-XSS-005", name="XSS via error page reflection",
            category="XSS", severity="MEDIUM",
            url=err_url, method="GET", parameter="path",
            payload=f"/nonexistent_{CANARY}err", evidence="Path reflected in 404 error page",
            description="URL path reflected in error page without HTML encoding.",
            recommendation="Sanitise error page output. Use generic error pages.",
            cwe="CWE-79", owasp="A03:2021 Injection",
        )

# ── 3. AUTH & SESSION CHECKS ────────────────────────────────────────────────

CSRF_TOKEN_NAMES = {
    "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken", "_csrf",
    "authenticity_token", "__requestverificationtoken", "xsrf_token", "_token",
}

SESSION_COOKIE_NAMES = {
    "sessionid", "session_id", "phpsessid", "jsessionid", "sid",
    "aspsessionid", "connect.sid", "express.sid", "laravel_session",
}


def check_auth_session(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """CSRF, session cookie flags, login over HTTP, default creds."""

    # ── DAST-AUTH-001: Missing CSRF tokens ──
    for form in sitemap.forms:
        if form.method != "POST":
            continue
        field_names = {f.get("name", "").lower() for f in form.fields}
        has_csrf = any(fn in field_names for fn in CSRF_TOKEN_NAMES)
        if not has_csrf:
            yield Finding(
                rule_id="DAST-AUTH-001", name="Missing CSRF token",
                category="Auth & Session", severity="MEDIUM",
                url=form.action, method="POST", parameter="",
                payload="", evidence=f"POST form at {form.source_url} has no CSRF token field",
                description="POST form lacks CSRF token -- vulnerable to cross-site request forgery.",
                recommendation="Include CSRF tokens in all state-changing forms.",
                cwe="CWE-352", owasp="A01:2021 Broken Access Control",
            )

    # ── DAST-AUTH-002: Session token in URL ──
    for url in sitemap.urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for p in params:
            if p.lower() in SESSION_COOKIE_NAMES:
                yield Finding(
                    rule_id="DAST-AUTH-002", name="Session token in URL",
                    category="Auth & Session", severity="HIGH",
                    url=url, method="GET", parameter=p,
                    payload="", evidence=f"Session parameter '{p}' found in URL query string",
                    description="Session identifier passed in URL -- visible in logs, referrer, and browser history.",
                    recommendation="Transport session tokens only via cookies, never in URLs.",
                    cwe="CWE-598", owasp="A07:2021 Identification and Authentication Failures",
                )
                break

    # ── DAST-AUTH-003: Login form over HTTP ──
    for form in sitemap.forms:
        has_pwd = any(f.get("type") == "password" for f in form.fields)
        if has_pwd and form.action.startswith("http://"):
            yield Finding(
                rule_id="DAST-AUTH-003", name="Login form over HTTP",
                category="Auth & Session", severity="HIGH",
                url=form.action, method=form.method, parameter="",
                payload="", evidence=f"Login form on {form.source_url} submits to HTTP endpoint",
                description="Login form submits credentials over unencrypted HTTP.",
                recommendation="Always use HTTPS for login forms and entire application.",
                cwe="CWE-319", owasp="A02:2021 Cryptographic Failures",
            )

    # ── DAST-AUTH-004 & 005 & 006: Session cookie flags ──
    resp = client.get(target)
    if resp:
        for cookie_header in resp.headers.get("Set-Cookie", "").split(","):
            cookie_header = cookie_header.strip()
            if not cookie_header:
                continue
            cookie_name = cookie_header.split("=")[0].strip().lower()
            is_session = any(sn in cookie_name for sn in SESSION_COOKIE_NAMES)
            ch_lower = cookie_header.lower()

            if is_session and "httponly" not in ch_lower:
                yield Finding(
                    rule_id="DAST-AUTH-004", name="Session cookie missing HttpOnly",
                    category="Auth & Session", severity="HIGH",
                    url=target, method="GET", parameter=cookie_name,
                    payload="", evidence=f"Set-Cookie: {cookie_header[:100]}",
                    description="Session cookie lacks HttpOnly flag -- accessible via JavaScript.",
                    recommendation="Set HttpOnly flag on all session cookies.",
                    cwe="CWE-1004", owasp="A07:2021 Identification and Authentication Failures",
                )
            if is_session and "secure" not in ch_lower:
                yield Finding(
                    rule_id="DAST-AUTH-005", name="Session cookie missing Secure flag",
                    category="Auth & Session", severity="HIGH",
                    url=target, method="GET", parameter=cookie_name,
                    payload="", evidence=f"Set-Cookie: {cookie_header[:100]}",
                    description="Session cookie lacks Secure flag -- sent over unencrypted connections.",
                    recommendation="Set Secure flag on all session cookies.",
                    cwe="CWE-614", owasp="A02:2021 Cryptographic Failures",
                )
            if is_session and "samesite" not in ch_lower:
                yield Finding(
                    rule_id="DAST-AUTH-006", name="Session cookie missing SameSite",
                    category="Auth & Session", severity="MEDIUM",
                    url=target, method="GET", parameter=cookie_name,
                    payload="", evidence=f"Set-Cookie: {cookie_header[:100]}",
                    description="Session cookie lacks SameSite attribute.",
                    recommendation="Set SameSite=Strict or SameSite=Lax on session cookies.",
                    cwe="CWE-1275", owasp="A01:2021 Broken Access Control",
                )

    # ── DAST-AUTH-007: Default credentials ──
    default_creds = [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                     ("root", "root"), ("root", "password"), ("test", "test")]
    for form in sitemap.forms:
        has_pwd = any(f.get("type") == "password" for f in form.fields)
        if not has_pwd:
            continue
        for user, pwd in default_creds:
            data: dict[str, str] = {}
            user_set = pwd_set = False
            for fld in form.fields:
                name = fld.get("name", "")
                if not name:
                    continue
                if fld.get("type") == "password" and not pwd_set:
                    data[name] = pwd
                    pwd_set = True
                elif fld.get("type") in ("text", "email") and not user_set:
                    data[name] = user
                    user_set = True
                elif fld.get("type") == "hidden":
                    data[name] = fld.get("value", "")
            if form.method == "POST":
                resp = client.post(form.action, data=data, allow_redirects=True)
            else:
                resp = client.get(form.action, params=data, allow_redirects=True)
            if resp is None:
                continue
            body = resp.text.lower()
            fail_patterns = ["invalid", "incorrect", "failed", "error", "wrong"]
            if resp.status_code == 200 and not any(fp in body for fp in fail_patterns):
                success_indicators = ["dashboard", "welcome", "profile", "logout", "sign out"]
                if any(si in body for si in success_indicators):
                    yield Finding(
                        rule_id="DAST-AUTH-007", name="Default credentials accepted",
                        category="Auth & Session", severity="CRITICAL",
                        url=form.action, method=form.method, parameter="",
                        payload=f"{user}:{pwd}", evidence="Login succeeded with default credentials",
                        description=f"Application accepts default credentials ({user}/{pwd}).",
                        recommendation="Change all default credentials. Enforce strong password policies.",
                        cwe="CWE-798", owasp="A07:2021 Identification and Authentication Failures",
                    )
                    return  # Stop after first match

# ── 4. ACCESS CONTROL CHECKS ────────────────────────────────────────────────

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/adminer", "/console", "/dashboard", "/manage",
    "/actuator", "/actuator/health", "/actuator/env", "/_debug",
    "/server-status", "/server-info", "/manager/html",
]


def check_access_control(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """Forced browsing, HTTP verb tampering, IDOR indicators."""

    # ── DAST-AC-001: Forced browsing to admin paths ──
    for path in ADMIN_PATHS:
        url = urljoin(target, path)
        resp = client.get(url)
        if resp and resp.status_code == 200:
            body = resp.text.lower()
            if any(k in body for k in ["login", "password", "admin", "dashboard", "console",
                                        "configuration", "management", "actuator"]):
                yield Finding(
                    rule_id="DAST-AC-001", name="Admin/sensitive path accessible",
                    category="Access Control", severity="HIGH",
                    url=url, method="GET", parameter="",
                    payload=path, evidence=f"HTTP 200 with admin-related content",
                    description=f"Admin or sensitive path '{path}' is accessible.",
                    recommendation="Restrict admin paths with authentication and IP allowlisting.",
                    cwe="CWE-425", owasp="A01:2021 Broken Access Control",
                )

    # ── DAST-AC-002: HTTP verb tampering ──
    for url in list(sitemap.urls)[:10]:
        get_resp = client.get(url)
        if get_resp and get_resp.status_code == 403:
            for method in ["POST", "PUT", "PATCH"]:
                alt_resp = client.request(method, url)
                if alt_resp and alt_resp.status_code == 200:
                    yield Finding(
                        rule_id="DAST-AC-002", name="HTTP verb tampering bypass",
                        category="Access Control", severity="HIGH",
                        url=url, method=method, parameter="",
                        payload=f"GET=403, {method}=200", evidence=f"{method} returned 200 where GET returned 403",
                        description=f"Access control bypassed using {method} method instead of GET.",
                        recommendation="Enforce access control regardless of HTTP method.",
                        cwe="CWE-650", owasp="A01:2021 Broken Access Control",
                    )
                    break

    # ── DAST-AC-003: Dangerous HTTP methods ──
    resp = client.options(target)
    if resp:
        allow = resp.headers.get("Allow", "")
        dangerous = {"PUT", "DELETE", "TRACE", "CONNECT"}
        enabled = {m.strip().upper() for m in allow.split(",") if m.strip()} & dangerous
        if enabled:
            yield Finding(
                rule_id="DAST-AC-003", name="Dangerous HTTP methods enabled",
                category="Access Control", severity="MEDIUM",
                url=target, method="OPTIONS", parameter="",
                payload="", evidence=f"Allow: {allow}",
                description=f"Dangerous HTTP methods enabled: {', '.join(enabled)}.",
                recommendation="Disable unused HTTP methods (PUT, DELETE, TRACE, CONNECT).",
                cwe="CWE-749", owasp="A05:2021 Security Misconfiguration",
            )

    # ── DAST-AC-004: IDOR indicators ──
    for url in _urls_with_params(sitemap):
        for param, val in _get_params(url):
            if val.isdigit() and param.lower() in ("id", "user_id", "uid", "account", "order_id", "doc_id"):
                new_val = str(int(val) + 1)
                test_url = _inject_param(url, param, new_val)
                resp = client.get(test_url)
                if resp and resp.status_code == 200:
                    yield Finding(
                        rule_id="DAST-AC-004", name="Potential IDOR",
                        category="Access Control", severity="MEDIUM",
                        url=test_url, method="GET", parameter=param,
                        payload=f"{val} -> {new_val}", evidence=f"HTTP 200 for modified ID value",
                        description=f"Incrementing '{param}' from {val} to {new_val} returned data.",
                        recommendation="Implement object-level authorisation checks for all data access.",
                        cwe="CWE-639", owasp="A01:2021 Broken Access Control",
                    )

# ── 5. INFORMATION DISCLOSURE CHECKS ────────────────────────────────────────

SENSITIVE_PATHS = [
    ("/.git/HEAD", r"ref:\s+refs/", "DAST-INFO-001", ".git repository exposed", "CRITICAL"),
    ("/.env", r"(DB_PASSWORD|API_KEY|SECRET|AWS_ACCESS)", "DAST-INFO-002", ".env file exposed", "CRITICAL"),
    ("/.env.local", r"(DB_PASSWORD|API_KEY|SECRET)", "DAST-INFO-002", ".env.local file exposed", "CRITICAL"),
    ("/phpinfo.php", r"phpinfo\(\)", "DAST-INFO-003", "phpinfo() exposed", "HIGH"),
    ("/server-status", r"Apache Server Status", "DAST-INFO-003", "Apache server-status exposed", "HIGH"),
    ("/.htaccess", r"(RewriteEngine|Deny|Redirect)", "DAST-INFO-004", ".htaccess file exposed", "MEDIUM"),
    ("/crossdomain.xml", r'allow-access-from\s+domain="\*"', "DAST-INFO-005", "Wildcard crossdomain.xml", "MEDIUM"),
    ("/wp-config.php.bak", r"DB_NAME|DB_PASSWORD", "DAST-INFO-006", "WordPress config backup exposed", "CRITICAL"),
    ("/elmah.axd", r"Error Log", "DAST-INFO-003", "ELMAH error log exposed", "HIGH"),
    ("/trace.axd", r"Application Trace", "DAST-INFO-003", "ASP.NET trace exposed", "HIGH"),
    ("/web.config", r"connectionString|appSettings", "DAST-INFO-006", "web.config exposed", "CRITICAL"),
    ("/backup.sql", r"(CREATE TABLE|INSERT INTO|DROP TABLE)", "DAST-INFO-006", "SQL backup file exposed", "CRITICAL"),
]

INTERNAL_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",  # Python
    r"at\s+[\w.$]+\([\w.]+\.java:\d+\)",  # Java
    r"(Fatal error|Parse error|Warning):.*in\s+/",  # PHP
    r"System\.\w+Exception",  # .NET
    r"Error:.*\n\s+at\s+",  # Node.js
]


def check_info_disclosure(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """Sensitive files, server headers, stack traces, internal IPs."""

    # ── DAST-INFO-001 to 006: Sensitive path probing ──
    for path, pattern, rule_id, name, severity in SENSITIVE_PATHS:
        url = urljoin(target, path)
        resp = client.get(url)
        if resp and resp.status_code == 200 and re.search(pattern, resp.text, re.I):
            yield Finding(
                rule_id=rule_id, name=name,
                category="Information Disclosure", severity=severity,
                url=url, method="GET", parameter="",
                payload=path, evidence=re.search(pattern, resp.text, re.I).group()[:200],
                description=f"Sensitive file or endpoint '{path}' is publicly accessible.",
                recommendation="Remove or restrict access to sensitive files and debug endpoints.",
                cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
            )

    # ── DAST-INFO-007: Server version disclosure ──
    resp = client.get(target)
    if resp:
        server = resp.headers.get("Server", "")
        if server and re.search(r"/\d", server):  # Contains version number
            yield Finding(
                rule_id="DAST-INFO-007", name="Server version disclosed",
                category="Information Disclosure", severity="LOW",
                url=target, method="GET", parameter="Server",
                payload="", evidence=f"Server: {server}",
                description=f"Server header reveals version information: {server}",
                recommendation="Remove or mask version information from Server header.",
                cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
            )

        xpb = resp.headers.get("X-Powered-By", "")
        if xpb:
            yield Finding(
                rule_id="DAST-INFO-008", name="Technology stack disclosed",
                category="Information Disclosure", severity="LOW",
                url=target, method="GET", parameter="X-Powered-By",
                payload="", evidence=f"X-Powered-By: {xpb}",
                description=f"X-Powered-By header reveals technology: {xpb}",
                recommendation="Remove X-Powered-By header from responses.",
                cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
            )

    # ── DAST-INFO-009: Stack traces in error responses ──
    error_urls = [urljoin(target, "/nonexistent_page_404"), target + "?id='"]
    for url in error_urls:
        resp = client.get(url)
        if resp is None:
            continue
        for pat in STACK_TRACE_PATTERNS:
            if re.search(pat, resp.text):
                yield Finding(
                    rule_id="DAST-INFO-009", name="Stack trace in error response",
                    category="Information Disclosure", severity="MEDIUM",
                    url=url, method="GET", parameter="",
                    payload="", evidence=re.search(pat, resp.text).group()[:200],
                    description="Application exposes stack traces in error responses.",
                    recommendation="Implement custom error pages. Disable debug mode in production.",
                    cwe="CWE-209", owasp="A05:2021 Security Misconfiguration",
                )
                break

    # ── DAST-INFO-010: Internal IP addresses ──
    for url in list(sitemap.urls)[:20]:
        resp = client.get(url)
        if resp is None:
            continue
        match = INTERNAL_IP_PATTERN.search(resp.text)
        if match:
            yield Finding(
                rule_id="DAST-INFO-010", name="Internal IP address disclosed",
                category="Information Disclosure", severity="MEDIUM",
                url=url, method="GET", parameter="",
                payload="", evidence=f"Internal IP: {match.group()}",
                description="Response body contains internal/private IP address.",
                recommendation="Sanitise responses to remove internal network information.",
                cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
            )
            break  # One is enough

    # ── DAST-INFO-011: Directory listing ──
    test_paths = ["/", "/images/", "/uploads/", "/static/", "/assets/", "/files/"]
    for path in test_paths:
        url = urljoin(target, path)
        resp = client.get(url)
        if resp and resp.status_code == 200:
            if re.search(r"(Index of|Directory listing|Parent Directory)", resp.text, re.I):
                yield Finding(
                    rule_id="DAST-INFO-011", name="Directory listing enabled",
                    category="Information Disclosure", severity="MEDIUM",
                    url=url, method="GET", parameter="",
                    payload=path, evidence="Directory listing page detected",
                    description=f"Directory listing is enabled at '{path}'.",
                    recommendation="Disable directory listing in web server configuration.",
                    cwe="CWE-548", owasp="A05:2021 Security Misconfiguration",
                )

# ── 6. SECURITY HEADER CHECKS ───────────────────────────────────────────────

REQUIRED_HEADERS = [
    ("Content-Security-Policy", "DAST-HDR-001", "Missing Content-Security-Policy", "MEDIUM",
     "Implement a strict CSP to prevent XSS and data injection attacks."),
    ("X-Content-Type-Options", "DAST-HDR-002", "Missing X-Content-Type-Options", "MEDIUM",
     "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing."),
    ("X-Frame-Options", "DAST-HDR-003", "Missing X-Frame-Options", "MEDIUM",
     "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking."),
    ("Referrer-Policy", "DAST-HDR-004", "Missing Referrer-Policy", "LOW",
     "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."),
    ("Permissions-Policy", "DAST-HDR-005", "Missing Permissions-Policy", "LOW",
     "Add Permissions-Policy to restrict browser feature access."),
]


def check_security_headers(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """Missing/weak security headers, HSTS, CSP analysis."""

    resp = client.get(target)
    if resp is None:
        return

    hdrs = {k.lower(): v for k, v in resp.headers.items()}

    # ── DAST-HDR-001 to 005: Required headers ──
    for header_name, rule_id, name, severity, rec in REQUIRED_HEADERS:
        if header_name.lower() not in hdrs:
            yield Finding(
                rule_id=rule_id, name=name,
                category="Security Headers", severity=severity,
                url=target, method="GET", parameter=header_name,
                payload="", evidence=f"Header '{header_name}' not present in response",
                description=f"Response is missing the {header_name} security header.",
                recommendation=rec,
                cwe="CWE-693", owasp="A05:2021 Security Misconfiguration",
            )

    # ── DAST-HDR-006: Weak/missing HSTS ──
    hsts = hdrs.get("strict-transport-security", "")
    if target.startswith("https://"):
        if not hsts:
            yield Finding(
                rule_id="DAST-HDR-006", name="Missing HSTS header",
                category="Security Headers", severity="MEDIUM",
                url=target, method="GET", parameter="Strict-Transport-Security",
                payload="", evidence="HSTS header not present on HTTPS response",
                description="HTTPS site lacks Strict-Transport-Security header.",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                cwe="CWE-319", owasp="A02:2021 Cryptographic Failures",
            )
        elif "max-age=" in hsts:
            ma = re.search(r"max-age=(\d+)", hsts)
            if ma and int(ma.group(1)) < 15768000:  # < 6 months
                yield Finding(
                    rule_id="DAST-HDR-006", name="Weak HSTS max-age",
                    category="Security Headers", severity="LOW",
                    url=target, method="GET", parameter="Strict-Transport-Security",
                    payload="", evidence=f"HSTS max-age={ma.group(1)} (< 6 months)",
                    description=f"HSTS max-age is too short ({ma.group(1)} seconds).",
                    recommendation="Set HSTS max-age to at least 31536000 (1 year).",
                    cwe="CWE-319", owasp="A02:2021 Cryptographic Failures",
                )

    # ── DAST-HDR-007: Weak CSP ──
    csp = hdrs.get("content-security-policy", "")
    if csp:
        weak_directives = []
        if "'unsafe-inline'" in csp:
            weak_directives.append("unsafe-inline")
        if "'unsafe-eval'" in csp:
            weak_directives.append("unsafe-eval")
        if "script-src *" in csp or "default-src *" in csp:
            weak_directives.append("wildcard source")
        if weak_directives:
            yield Finding(
                rule_id="DAST-HDR-007", name="Weak Content-Security-Policy",
                category="Security Headers", severity="MEDIUM",
                url=target, method="GET", parameter="Content-Security-Policy",
                payload="", evidence=f"Weak directives: {', '.join(weak_directives)}",
                description=f"CSP contains unsafe directives: {', '.join(weak_directives)}.",
                recommendation="Remove unsafe-inline and unsafe-eval. Use nonce-based or hash-based CSP.",
                cwe="CWE-693", owasp="A05:2021 Security Misconfiguration",
            )

    # ── DAST-HDR-008: CORS misconfiguration ──
    acao = hdrs.get("access-control-allow-origin", "")
    if acao == "*":
        acac = hdrs.get("access-control-allow-credentials", "")
        severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
        yield Finding(
            rule_id="DAST-HDR-008", name="CORS wildcard origin",
            category="Security Headers", severity=severity,
            url=target, method="GET", parameter="Access-Control-Allow-Origin",
            payload="", evidence=f"ACAO: {acao}" + (f", ACAC: {acac}" if acac else ""),
            description="CORS allows requests from any origin" + (" with credentials" if acac else "") + ".",
            recommendation="Restrict CORS to specific trusted origins. Never combine wildcard with credentials.",
            cwe="CWE-942", owasp="A05:2021 Security Misconfiguration",
        )

    # ── DAST-HDR-009: CORS origin reflection ──
    evil_origin = "https://evil.example.com"
    resp2 = client.get(target, headers={"Origin": evil_origin})
    if resp2:
        acao2 = resp2.headers.get("Access-Control-Allow-Origin", "")
        if acao2 == evil_origin:
            yield Finding(
                rule_id="DAST-HDR-009", name="CORS origin reflection",
                category="Security Headers", severity="HIGH",
                url=target, method="GET", parameter="Origin",
                payload=evil_origin, evidence=f"ACAO reflected attacker origin: {acao2}",
                description="Server reflects arbitrary Origin in Access-Control-Allow-Origin.",
                recommendation="Validate Origin against an allowlist. Do not reflect arbitrary origins.",
                cwe="CWE-942", owasp="A05:2021 Security Misconfiguration",
            )

# ── 7. SSRF CHECKS ──────────────────────────────────────────────────────────

SSRF_TARGETS = [
    ("http://127.0.0.1", "localhost"),
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://[::1]", "IPv6 localhost"),
]

SSRF_EVIDENCE_PATTERNS = [
    r"root:.*:0:0:",        # /etc/passwd
    r"ami-[a-f0-9]+",       # AWS AMI ID
    r"latest/meta-data",    # AWS IMDS
    r"computeMetadata",     # GCP metadata
    r"<html",               # Got HTML from internal service
]

SSRF_PARAM_NAMES = {"url", "uri", "link", "src", "source", "redirect", "target",
                    "dest", "destination", "next", "return", "returnurl",
                    "callback", "webhook", "feed", "fetch", "load", "file"}


def check_ssrf(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """SSRF via URL params, forms, and redirects."""

    # ── DAST-SSRF-001: SSRF via URL params ──
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            if param.lower() not in SSRF_PARAM_NAMES:
                continue
            for ssrf_target, label in SSRF_TARGETS:
                test_url = _inject_param(url, param, ssrf_target)
                resp = client.get(test_url)
                if resp is None:
                    continue
                for pat in SSRF_EVIDENCE_PATTERNS:
                    if re.search(pat, resp.text, re.I):
                        yield Finding(
                            rule_id="DAST-SSRF-001", name=f"SSRF via URL parameter ({label})",
                            category="SSRF", severity="CRITICAL",
                            url=test_url, method="GET", parameter=param,
                            payload=ssrf_target, evidence=re.search(pat, resp.text, re.I).group()[:200],
                            description=f"Server-side request forgery to {label} via parameter '{param}'.",
                            recommendation="Validate and whitelist URLs. Block access to internal addresses.",
                            cwe="CWE-918", owasp="A10:2021 SSRF",
                        )
                        break

    # ── DAST-SSRF-002: SSRF via forms ──
    for form in sitemap.forms:
        for fld in form.fields:
            if fld.get("type") in ("hidden", "submit", "file"):
                continue
            fname = fld.get("name", "").lower()
            if fname not in SSRF_PARAM_NAMES:
                continue
            for ssrf_target, label in SSRF_TARGETS[:2]:  # Limit
                data = {f.get("name", ""): f.get("value", "") for f in form.fields if f.get("name")}
                data[fld.get("name", "")] = ssrf_target
                if form.method == "POST":
                    resp = client.post(form.action, data=data)
                else:
                    resp = client.get(form.action, params=data)
                if resp is None:
                    continue
                for pat in SSRF_EVIDENCE_PATTERNS:
                    if re.search(pat, resp.text, re.I):
                        yield Finding(
                            rule_id="DAST-SSRF-002", name=f"SSRF via form input ({label})",
                            category="SSRF", severity="CRITICAL",
                            url=form.action, method=form.method, parameter=fld.get("name", ""),
                            payload=ssrf_target, evidence=re.search(pat, resp.text, re.I).group()[:200],
                            description=f"SSRF to {label} via form field '{fld.get('name', '')}'.",
                            recommendation="Validate and whitelist URLs server-side. Block internal addresses.",
                            cwe="CWE-918", owasp="A10:2021 SSRF",
                        )
                        break

    # ── DAST-SSRF-003: Open redirect ──
    redirect_params = {"redirect", "url", "next", "return", "returnurl", "continue", "dest", "goto"}
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            if param.lower() not in redirect_params:
                continue
            test_url = _inject_param(url, param, "https://evil.example.com")
            resp = client.get(test_url, allow_redirects=False)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.example.com" in location:
                    yield Finding(
                        rule_id="DAST-SSRF-003", name="Open redirect",
                        category="SSRF", severity="MEDIUM",
                        url=test_url, method="GET", parameter=param,
                        payload="https://evil.example.com", evidence=f"Location: {location}",
                        description=f"Open redirect via parameter '{param}'.",
                        recommendation="Validate redirect URLs against an allowlist of internal paths.",
                        cwe="CWE-601", owasp="A01:2021 Broken Access Control",
                    )

# ── 8. FILE INCLUSION CHECKS ────────────────────────────────────────────────

LFI_PAYLOADS = [
    ("../../../etc/passwd", r"root:.*:0:0:"),
    ("..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]"),
    ("....//....//....//etc/passwd", r"root:.*:0:0:"),
    ("..%252f..%252f..%252fetc/passwd", r"root:.*:0:0:"),
    ("/etc/passwd%00.txt", r"root:.*:0:0:"),
]

FILE_PARAM_NAMES = {"file", "path", "page", "template", "include", "doc",
                    "document", "folder", "dir", "root", "filename", "lang"}


def check_file_inclusion(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """LFI, RFI, path traversal, backup file exposure."""

    # ── DAST-FI-001: Local file inclusion via URL params ──
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            if param.lower() not in FILE_PARAM_NAMES:
                continue
            for payload, pattern in LFI_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                resp = client.get(test_url)
                if resp and re.search(pattern, resp.text, re.I):
                    yield Finding(
                        rule_id="DAST-FI-001", name="Local File Inclusion (LFI)",
                        category="File Inclusion", severity="CRITICAL",
                        url=test_url, method="GET", parameter=param,
                        payload=payload, evidence=re.search(pattern, resp.text, re.I).group()[:200],
                        description=f"Local file inclusion via parameter '{param}'.",
                        recommendation="Never use user input in file paths. Use a whitelist of allowed files.",
                        cwe="CWE-98", owasp="A03:2021 Injection",
                    )
                    break

    # ── DAST-FI-002: Remote file inclusion ──
    rfi_target = "http://192.0.2.1/dast_rfi_test.txt"  # RFC 5737 documentation address
    for url in _urls_with_params(sitemap):
        for param, orig_val in _get_params(url):
            if param.lower() not in FILE_PARAM_NAMES:
                continue
            test_url = _inject_param(url, param, rfi_target)
            resp = client.get(test_url)
            if resp and "dast_rfi_test" in resp.text:
                yield Finding(
                    rule_id="DAST-FI-002", name="Remote File Inclusion (RFI)",
                    category="File Inclusion", severity="CRITICAL",
                    url=test_url, method="GET", parameter=param,
                    payload=rfi_target, evidence="RFI test marker found in response",
                    description=f"Remote file inclusion via parameter '{param}'.",
                    recommendation="Disable remote file inclusion (allow_url_include=Off in PHP). Whitelist paths.",
                    cwe="CWE-98", owasp="A03:2021 Injection",
                )
                break

    # ── DAST-FI-003: Backup file disclosure ──
    backup_exts = [".bak", ".backup", ".old", ".orig", ".save", "~", ".swp", ".copy"]
    for url in list(sitemap.urls)[:10]:
        parsed = urlparse(url)
        path = parsed.path
        if not path or path == "/":
            continue
        for ext in backup_exts:
            backup_url = urlunparse(parsed._replace(path=path + ext, query=""))
            resp = client.get(backup_url)
            if resp and resp.status_code == 200:
                ct = resp.headers.get("Content-Type", "")
                if "text/html" not in ct:  # Non-HTML = likely file content
                    yield Finding(
                        rule_id="DAST-FI-003", name="Backup file accessible",
                        category="File Inclusion", severity="MEDIUM",
                        url=backup_url, method="GET", parameter="",
                        payload=ext, evidence=f"HTTP 200 with Content-Type: {ct}",
                        description=f"Backup file '{path + ext}' is publicly accessible.",
                        recommendation="Remove backup files from web-accessible directories.",
                        cwe="CWE-530", owasp="A05:2021 Security Misconfiguration",
                    )
                    break

# ── 9. XXE CHECKS ───────────────────────────────────────────────────────────

XXE_PAYLOAD_LINUX = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>'''

XXE_PAYLOAD_WIN = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>'''


def check_xxe(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """XXE via XML endpoints and SOAP services."""

    xml_content_type = {"Content-Type": "application/xml"}

    # Find XML-accepting endpoints
    xml_urls = [target]
    for url in list(sitemap.urls)[:20]:
        resp = client.head(url)
        if resp and "xml" in resp.headers.get("Content-Type", "").lower():
            xml_urls.append(url)
    for ep in sitemap.api_endpoints:
        xml_urls.append(ep)

    # ── DAST-XXE-001: XXE file disclosure ──
    for url in xml_urls[:10]:
        for payload, pattern in [(XXE_PAYLOAD_LINUX, r"root:.*:0:0:"), (XXE_PAYLOAD_WIN, r"\[fonts\]")]:
            resp = client.post(url, data=payload, headers=xml_content_type)
            if resp and re.search(pattern, resp.text, re.I):
                yield Finding(
                    rule_id="DAST-XXE-001", name="XXE -- external entity file disclosure",
                    category="XXE", severity="CRITICAL",
                    url=url, method="POST", parameter="XML body",
                    payload="<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                    evidence=re.search(pattern, resp.text, re.I).group()[:200],
                    description="XML External Entity injection allows reading local files.",
                    recommendation="Disable external entities in XML parser. Use JSON instead of XML.",
                    cwe="CWE-611", owasp="A05:2021 Security Misconfiguration",
                )
                break

    # ── DAST-XXE-002: SOAP endpoint XXE ──
    soap_paths = ["/ws", "/service", "/soap", "/api/soap"]
    soap_envelope = f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body><test>&xxe;</test></soapenv:Body></soapenv:Envelope>'''

    for path in soap_paths:
        url = urljoin(target, path)
        resp = client.post(url, data=soap_envelope,
                          headers={"Content-Type": "text/xml; charset=utf-8"})
        if resp and re.search(r"root:.*:0:0:", resp.text, re.I):
            yield Finding(
                rule_id="DAST-XXE-002", name="XXE via SOAP endpoint",
                category="XXE", severity="CRITICAL",
                url=url, method="POST", parameter="SOAP body",
                payload="DOCTYPE with SYSTEM entity in SOAP envelope",
                evidence="File contents leaked via XXE in SOAP",
                description="SOAP endpoint vulnerable to XXE injection.",
                recommendation="Disable external entities. Use secure XML parser configuration.",
                cwe="CWE-611", owasp="A05:2021 Security Misconfiguration",
            )

# ── 10. API SECURITY CHECKS ─────────────────────────────────────────────────

API_DOC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/api-docs.json",
    "/openapi.json", "/openapi.yaml", "/graphql", "/graphiql",
    "/api/docs", "/redoc", "/api-explorer",
]

GRAPHQL_INTROSPECTION_QUERY = '{"query": "{ __schema { types { name } } }"}'


def check_api_security(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """GraphQL introspection, exposed API docs, API key in URL, CORS."""

    # ── DAST-API-001: API documentation exposed ──
    for path in API_DOC_PATHS:
        url = urljoin(target, path)
        resp = client.get(url)
        if resp and resp.status_code == 200:
            body = resp.text[:1000].lower()
            if any(k in body for k in ["swagger", "openapi", "paths", "__schema", "graphql",
                                        "api-docs", "endpoints"]):
                yield Finding(
                    rule_id="DAST-API-001", name="API documentation exposed",
                    category="API Security", severity="MEDIUM",
                    url=url, method="GET", parameter="",
                    payload=path, evidence=f"API documentation accessible at {path}",
                    description=f"API documentation endpoint '{path}' is publicly accessible.",
                    recommendation="Restrict API documentation to authenticated users or internal networks.",
                    cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
                )

    # ── DAST-API-002: GraphQL introspection enabled ──
    graphql_urls = [urljoin(target, "/graphql"), urljoin(target, "/api/graphql")]
    for url in graphql_urls:
        resp = client.post(url, data=GRAPHQL_INTROSPECTION_QUERY,
                          headers={"Content-Type": "application/json"})
        if resp and resp.status_code == 200 and "__schema" in resp.text:
            yield Finding(
                rule_id="DAST-API-002", name="GraphQL introspection enabled",
                category="API Security", severity="MEDIUM",
                url=url, method="POST", parameter="",
                payload="{ __schema { types { name } } }",
                evidence="Introspection query returned schema types",
                description="GraphQL introspection is enabled -- exposes entire API schema.",
                recommendation="Disable introspection in production. Use persisted queries.",
                cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
            )

    # ── DAST-API-003: API key in URL ──
    api_key_params = {"api_key", "apikey", "access_token", "token", "key", "auth"}
    for url in _urls_with_params(sitemap):
        for param, val in _get_params(url):
            if param.lower() in api_key_params and len(val) > 10:
                yield Finding(
                    rule_id="DAST-API-003", name="API key transmitted in URL",
                    category="API Security", severity="HIGH",
                    url=url, method="GET", parameter=param,
                    payload="", evidence=f"Parameter '{param}' contains what appears to be an API key",
                    description=f"API key passed in URL parameter '{param}' -- visible in logs and referrer.",
                    recommendation="Send API keys in Authorization header, not URL parameters.",
                    cwe="CWE-598", owasp="A02:2021 Cryptographic Failures",
                )

    # ── DAST-API-004: Missing rate limiting ──
    for ep in list(sitemap.api_endpoints)[:5]:
        resp = client.get(ep)
        if resp and resp.status_code == 200:
            rate_headers = {"x-ratelimit-limit", "x-ratelimit-remaining", "x-rate-limit",
                          "retry-after", "ratelimit-limit"}
            has_rate_limit = any(h in {k.lower() for k in resp.headers} for h in rate_headers)
            if not has_rate_limit:
                yield Finding(
                    rule_id="DAST-API-004", name="API endpoint missing rate limiting",
                    category="API Security", severity="MEDIUM",
                    url=ep, method="GET", parameter="",
                    payload="", evidence="No rate-limiting headers in API response",
                    description="API endpoint lacks rate-limiting headers.",
                    recommendation="Implement rate limiting with X-RateLimit-* headers.",
                    cwe="CWE-770", owasp="A04:2021 Insecure Design",
                )
                break  # One finding is enough

# ── 11. JWT CHECKS ───────────────────────────────────────────────────────────

WEAK_JWT_SECRETS = ["secret", "password", "key", "123456", "jwt_secret",
                    "changeme", "test", "admin", "default", "jwt"]


def _find_jwts(client: HTTPClient, sitemap: SiteMap) -> list[str]:
    """Collect JWTs from API responses."""
    jwts: list[str] = []
    for ep in list(sitemap.api_endpoints)[:10]:
        resp = client.get(ep)
        if resp is None:
            continue
        # From response body
        matches = re.findall(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", resp.text)
        jwts.extend(matches)
        # From Set-Cookie
        for cookie_val in resp.headers.get("Set-Cookie", "").split(";"):
            jwt_match = re.search(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", cookie_val)
            if jwt_match:
                jwts.append(jwt_match.group())
    return list(set(jwts))[:5]


def _jwt_decode_part(part: str) -> dict:
    """Decode a JWT base64url part."""
    padding = 4 - len(part) % 4
    part += "=" * padding
    try:
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def check_jwt(client: HTTPClient, sitemap: SiteMap, target: str) -> Generator[Finding, None, None]:
    """JWT algorithm confusion, weak secrets, expired token acceptance."""
    jwts = _find_jwts(client, sitemap)
    if not jwts:
        return

    for token in jwts:
        parts = token.split(".")
        if len(parts) != 3:
            continue

        header = _jwt_decode_part(parts[0])
        payload_data = _jwt_decode_part(parts[1])

        # ── DAST-JWT-001: Algorithm none attack ──
        none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        none_token = f"{none_header}.{parts[1]}."
        for ep in list(sitemap.api_endpoints)[:3]:
            resp = client.get(ep, headers={"Authorization": f"Bearer {none_token}"})
            if resp and resp.status_code == 200:
                yield Finding(
                    rule_id="DAST-JWT-001", name="JWT algorithm 'none' accepted",
                    category="JWT Security", severity="CRITICAL",
                    url=ep, method="GET", parameter="Authorization",
                    payload="alg: none", evidence="Server accepted JWT with alg=none",
                    description="JWT with algorithm 'none' is accepted -- signature validation bypassed.",
                    recommendation="Reject JWTs with alg=none. Enforce strong algorithms (RS256, ES256).",
                    cwe="CWE-345", owasp="A02:2021 Cryptographic Failures",
                )
                break

        # ── DAST-JWT-002: Signature stripping ──
        stripped = f"{parts[0]}.{parts[1]}."
        for ep in list(sitemap.api_endpoints)[:3]:
            resp = client.get(ep, headers={"Authorization": f"Bearer {stripped}"})
            if resp and resp.status_code == 200:
                yield Finding(
                    rule_id="DAST-JWT-002", name="JWT signature not verified",
                    category="JWT Security", severity="CRITICAL",
                    url=ep, method="GET", parameter="Authorization",
                    payload="Stripped signature", evidence="Server accepted JWT without signature",
                    description="JWT accepted without valid signature -- signature verification disabled.",
                    recommendation="Always verify JWT signatures. Use a well-tested JWT library.",
                    cwe="CWE-345", owasp="A02:2021 Cryptographic Failures",
                )
                break

        # ── DAST-JWT-003: Weak signing secret ──
        if header.get("alg", "").startswith("HS"):
            for secret in WEAK_JWT_SECRETS:
                try:
                    signing_input = f"{parts[0]}.{parts[1]}".encode()
                    sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                    ).rstrip(b"=").decode()
                    if sig == parts[2]:
                        yield Finding(
                            rule_id="DAST-JWT-003", name="JWT signed with weak secret",
                            category="JWT Security", severity="CRITICAL",
                            url=target, method="", parameter="JWT",
                            payload=f"Secret: {secret}", evidence=f"JWT signature matches HMAC with secret '{secret}'",
                            description=f"JWT is signed with a weak/guessable secret: '{secret}'.",
                            recommendation="Use a strong, randomly generated secret (256+ bits).",
                            cwe="CWE-326", owasp="A02:2021 Cryptographic Failures",
                        )
                        break
                except Exception:
                    pass

        break  # Analyse first JWT only

# ════════════════════════════════════════════════════════════════════════════════
#  SCANNER ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════

CHECK_MODULES = [
    ("Injection", check_injection),
    ("XSS", check_xss),
    ("Auth & Session", check_auth_session),
    ("Access Control", check_access_control),
    ("Information Disclosure", check_info_disclosure),
    ("Security Headers", check_security_headers),
    ("SSRF", check_ssrf),
    ("File Inclusion", check_file_inclusion),
    ("XXE", check_xxe),
    ("API Security", check_api_security),
    ("JWT Security", check_jwt),
]


class DASTScanner:
    """Dynamic Application Security Testing Scanner."""

    SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_COLOR: dict[str, str] = {
        "CRITICAL": "\033[91m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
        "LOW": "\033[36m", "INFO": "\033[37m",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def __init__(self, target: str, verbose: bool = False,
                 crawl_depth: int = DEFAULT_CRAWL_DEPTH,
                 max_pages: int = DEFAULT_MAX_PAGES,
                 rate_limit: float = DEFAULT_RATE_LIMIT,
                 max_requests: int = DEFAULT_MAX_REQUESTS,
                 timeout: int = DEFAULT_TIMEOUT,
                 verify_ssl: bool = False,
                 proxy: str | None = None,
                 auth_mode: str = "none",
                 auth_token: str | None = None,
                 login_url: str | None = None,
                 login_user: str | None = None,
                 login_pass: str | None = None,
                 no_crawl: bool = False,
                 custom_headers: dict | None = None) -> None:
        self.target = target
        self.verbose = verbose
        self.findings: list[Finding] = []
        self._no_crawl = no_crawl

        parsed = urlparse(target)
        host = parsed.hostname or "localhost"
        self._client = HTTPClient(
            allowed_hosts={host},
            rate_limit=rate_limit,
            max_requests=max_requests,
            timeout=timeout,
            verify_ssl=verify_ssl,
            proxy=proxy,
            custom_headers=custom_headers,
        )
        self._crawler = WebCrawler(self._client, target, max_depth=crawl_depth,
                                   max_pages=max_pages, verbose=verbose)
        self._auth = AuthManager(self._client, auth_mode, auth_token,
                                 login_url, login_user, login_pass)

    def scan(self) -> list[Finding]:
        target = self.target
        self._vprint(f"\n  Target: {target}")

        # Phase 1: Authentication
        if self._auth._mode != "none":
            self._vprint(f"  Authenticating ({self._auth._mode})...")
            if self._auth.authenticate():
                self._vprint("  Authentication successful")
            else:
                self._warn("Authentication failed -- scanning without credentials")

        # Phase 2: WAF detection
        self._vprint("  Detecting WAF...")
        waf = detect_waf(self._client, target)
        if waf["detected"]:
            self._vprint(f"  WAF detected: {waf['name']} ({', '.join(waf['evidence'])})")
        else:
            self._vprint("  No WAF detected")

        # Phase 3: Crawling
        if self._no_crawl:
            self._vprint("  Crawling disabled -- scanning seed URL only")
            sitemap = SiteMap(urls={target}, forms=[], api_endpoints=[], tech={})
        else:
            self._vprint("  Crawling...")
            sitemap = self._crawler.crawl()
            self._vprint(f"  Crawled {len(sitemap.urls)} URLs, {len(sitemap.forms)} forms, "
                         f"{len(sitemap.api_endpoints)} API endpoints")
            if sitemap.tech:
                tech_parts = [f"{k}: {v}" for k, v in sitemap.tech.items() if v]
                if tech_parts:
                    self._vprint(f"  Technology: {', '.join(tech_parts)}")

        # Phase 4: Run checks in parallel
        self._vprint("  Running security checks...")
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}
            for name, check_fn in CHECK_MODULES:
                future = executor.submit(self._run_check, name, check_fn, sitemap)
                futures[future] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    findings = future.result()
                    self.findings.extend(findings)
                    if findings:
                        self._vprint(f"    {name}: {len(findings)} finding(s)")
                except Exception as e:
                    self._warn(f"Check '{name}' failed: {e}")

        self._vprint(f"  Total requests: {self._client.request_count}")
        return self.findings

    def _run_check(self, name: str, check_fn, sitemap: SiteMap) -> list[Finding]:
        results = []
        try:
            for finding in check_fn(self._client, sitemap, self.target):
                results.append(finding)
        except Exception:
            pass
        return results

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_sev: str) -> None:
        cutoff = self.SEVERITY_ORDER.get(min_sev, 4)
        self.findings = [f for f in self.findings if self.SEVERITY_ORDER.get(f.severity, 4) <= cutoff]

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def _warn(self, msg: str) -> None:
        print(f"\033[33m[WARN]\033[0m {msg}", file=sys.stderr)

    # ════════════════════════════════════════════════════════════════════════
    #  CONSOLE REPORT
    # ════════════════════════════════════════════════════════════════════════
    def print_report(self) -> None:
        self.findings.sort(key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category))
        s = self.summary()
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        hdr = (
            f"\n{'=' * 80}\n"
            f"  DAST Scanner -- Security Report\n"
            f"  Scanner Version : {__version__}\n"
            f"  Target          : {self.target}\n"
            f"  Scan Date       : {now}\n"
            f"  Total Requests  : {self._client.request_count}\n"
            f"  Findings        : {len(self.findings)}\n"
            f"{'=' * 80}\n"
        )
        print(hdr)

        # Category summary
        cats: dict[str, int] = {}
        for f in self.findings:
            cats[f.category] = cats.get(f.category, 0) + 1
        if cats:
            print("  Findings by Category:")
            for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
                print(f"    {cat}: {cnt}")
            print()

        for idx, f in enumerate(self.findings, 1):
            clr = self.SEVERITY_COLOR.get(f.severity, self.RESET)
            print(f"  {self.BOLD}[{idx}]{self.RESET} {f.rule_id} -- {clr}{f.severity}{self.RESET}")
            print(f"      {f.name}")
            print(f"      Category: {f.category}  |  OWASP: {f.owasp}")
            print(f"      URL: {f.url}")
            if f.method:
                print(f"      Method: {f.method}", end="")
                if f.parameter:
                    print(f"  |  Parameter: {f.parameter}", end="")
                print()
            if f.payload:
                print(f"      Payload: {f.payload[:100]}")
            if f.evidence:
                print(f"      Evidence: {f.evidence[:200]}")
            print(f"      CWE: {f.cwe}")
            print(f"      Recommendation: {f.recommendation}")
            print()

        sev_parts = [f"{k}: {v}" for k, v in s.items() if v > 0]
        print(f"{'=' * 80}")
        print(f"  Summary:  {('  '.join(sev_parts)) if sev_parts else 'No findings'}")
        print(f"{'=' * 80}")

    # ════════════════════════════════════════════════════════════════════════
    #  JSON REPORT
    # ════════════════════════════════════════════════════════════════════════
    def save_json(self, path: str) -> None:
        report = {
            "scanner": "DAST Scanner",
            "version": __version__,
            "target": self.target,
            "scan_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_requests": self._client.request_count,
            "summary": self.summary(),
            "findings": [asdict(f) for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"  JSON report saved: {path}")

    # ════════════════════════════════════════════════════════════════════════
    #  HTML REPORT
    # ════════════════════════════════════════════════════════════════════════
    def save_html(self, path: str) -> None:
        s = self.summary()
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
                      "LOW": "#0891b2", "INFO": "#6b7280"}

        rows = ""
        for f in self.findings:
            clr = sev_colors.get(f.severity, "#6b7280")
            payload_esc = (f.payload or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            evidence_esc = (f.evidence or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            url_esc = f.url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            rows += f"""<tr>
<td><span class="sev" style="background:{clr}">{f.severity}</span></td>
<td><strong>{f.rule_id}</strong><br>{f.name}</td>
<td>{f.category}</td>
<td style="word-break:break-all"><a href="{url_esc}" target="_blank">{url_esc[:80]}</a><br>
<small>{f.method} {f.parameter}</small></td>
<td><code>{payload_esc[:100]}</code></td>
<td>{evidence_esc[:200]}</td>
<td>{f.cwe}<br><small>{f.owasp}</small></td>
<td>{f.recommendation}</td>
</tr>\n"""

        html_content = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DAST Scanner Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0}}
.header{{background:linear-gradient(135deg,#f97316,#dc2626,#991b1b);padding:2rem;text-align:center}}
.header h1{{font-size:1.8rem;color:#fff}}
.header p{{color:#fed7aa;margin-top:.3rem}}
.cards{{display:flex;gap:1rem;padding:1.5rem;flex-wrap:wrap;justify-content:center}}
.card{{background:#1e293b;border-radius:12px;padding:1.2rem;min-width:120px;text-align:center}}
.card .num{{font-size:2rem;font-weight:700}}
.card .label{{font-size:.85rem;color:#94a3b8}}
.critical .num{{color:#dc2626}} .high .num{{color:#ea580c}} .medium .num{{color:#ca8a04}} .low .num{{color:#0891b2}}
.content{{padding:1rem 1.5rem}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}}
th{{background:#334155;padding:.75rem;text-align:left;font-size:.85rem;color:#94a3b8}}
td{{padding:.75rem;border-bottom:1px solid #334155;font-size:.85rem;vertical-align:top}}
tr:hover{{background:#334155}}
.sev{{padding:2px 8px;border-radius:4px;color:#fff;font-size:.75rem;font-weight:600}}
a{{color:#60a5fa}} code{{color:#fb923c;font-size:.8rem}}
.filters{{padding:.5rem 1.5rem;display:flex;gap:.5rem;flex-wrap:wrap}}
.filters button{{background:#334155;color:#e2e8f0;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.8rem}}
.filters button:hover,.filters button.active{{background:#f97316;color:#fff}}
</style></head><body>
<div class="header">
<h1>DAST Scanner &mdash; Security Report</h1>
<p>Target: {self.target} &nbsp;|&nbsp; Scanned: {now} &nbsp;|&nbsp; v{__version__}</p>
</div>
<div class="cards">
<div class="card critical"><div class="num">{s['CRITICAL']}</div><div class="label">Critical</div></div>
<div class="card high"><div class="num">{s['HIGH']}</div><div class="label">High</div></div>
<div class="card medium"><div class="num">{s['MEDIUM']}</div><div class="label">Medium</div></div>
<div class="card low"><div class="num">{s['LOW']}</div><div class="label">Low</div></div>
<div class="card"><div class="num">{len(self.findings)}</div><div class="label">Total</div></div>
<div class="card"><div class="num">{self._client.request_count}</div><div class="label">Requests</div></div>
</div>
<div class="filters">
<button class="active" onclick="filterSev('ALL')">All</button>
<button onclick="filterSev('CRITICAL')">Critical</button>
<button onclick="filterSev('HIGH')">High</button>
<button onclick="filterSev('MEDIUM')">Medium</button>
<button onclick="filterSev('LOW')">Low</button>
</div>
<div class="content">
<table id="findings">
<thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>URL</th><th>Payload</th><th>Evidence</th><th>CWE / OWASP</th><th>Recommendation</th></tr></thead>
<tbody>{rows}</tbody>
</table></div>
<script>
function filterSev(s){{
document.querySelectorAll('.filters button').forEach(b=>b.classList.remove('active'));
event.target.classList.add('active');
document.querySelectorAll('#findings tbody tr').forEach(r=>{{
if(s==='ALL'){{r.style.display='';return}}
const sv=r.querySelector('.sev');
r.style.display=sv&&sv.textContent===s?'':'none';
}});
}}
</script></body></html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"  HTML report saved: {path}")

# ════════════════════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dast_scanner.py",
        description="Dynamic Application Security Testing (DAST) Scanner",
    )
    p.add_argument("target", help="Target URL to scan (e.g. https://example.com)")
    p.add_argument("--json", metavar="FILE", help="Save JSON report to FILE")
    p.add_argument("--html", metavar="FILE", help="Save HTML report to FILE")
    p.add_argument("--severity", default="INFO",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                   help="Minimum severity to report (default: INFO)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--version", action="version", version=f"DAST Scanner v{__version__}")

    # Scan settings
    g = p.add_argument_group("scan settings")
    g.add_argument("--crawl-depth", type=int, default=DEFAULT_CRAWL_DEPTH,
                   help=f"Max crawl depth (default: {DEFAULT_CRAWL_DEPTH})")
    g.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES,
                   help=f"Max pages to crawl (default: {DEFAULT_MAX_PAGES})")
    g.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT,
                   help=f"Requests per second (default: {DEFAULT_RATE_LIMIT})")
    g.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
                   help=f"Max total requests (default: {DEFAULT_MAX_REQUESTS})")
    g.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    g.add_argument("--no-crawl", action="store_true", help="Skip crawling, test target URL only")
    g.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    g.add_argument("--proxy", metavar="URL", help="HTTP proxy (e.g. http://127.0.0.1:8080)")

    # Auth settings
    a = p.add_argument_group("authentication")
    a.add_argument("--auth-mode", default="none",
                   choices=["none", "bearer", "cookie", "basic", "form"],
                   help="Authentication mode (default: none)")
    a.add_argument("--auth-token", help="Bearer token, cookie (name=value), or basic (user:pass)")
    a.add_argument("--login-url", help="Login page URL (for form auth)")
    a.add_argument("--login-user", help="Username (for form auth)")
    a.add_argument("--login-pass", help="Password (for form auth)")

    return p


WARNING_BANNER = f"""\033[91m
{'=' * 70}
  WARNING: DAST Scanner performs ACTIVE security testing.
  It sends real HTTP requests including injection payloads.

  Only scan applications you OWN or have EXPLICIT AUTHORISATION to test.
  Unauthorised scanning is ILLEGAL in most jurisdictions.
{'=' * 70}\033[0m
"""


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    # Validate target
    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.hostname:
        print("[ERROR] Invalid target URL. Use format: https://example.com", file=sys.stderr)
        return 2

    # Warning banner
    print(WARNING_BANNER)

    scanner = DASTScanner(
        target=args.target,
        verbose=args.verbose,
        crawl_depth=args.crawl_depth,
        max_pages=args.max_pages,
        rate_limit=args.rate_limit,
        max_requests=args.max_requests,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        proxy=args.proxy,
        auth_mode=args.auth_mode,
        auth_token=args.auth_token,
        login_url=args.login_url,
        login_user=args.login_user,
        login_pass=args.login_pass,
        no_crawl=args.no_crawl,
    )

    scanner.scan()
    scanner.filter_severity(args.severity)
    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)

    s = scanner.summary()
    return 1 if s["CRITICAL"] + s["HIGH"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
