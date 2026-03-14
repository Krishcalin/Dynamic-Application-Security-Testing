#!/usr/bin/env python3
"""
Intentionally Vulnerable Web Application for DAST Scanner Testing
=================================================================

WARNING: This application is INTENTIONALLY INSECURE. It is designed
exclusively for testing the DAST Scanner. NEVER deploy this on a
network accessible to others.

Usage:
    python tests/vulnerable_app.py          # Starts on http://127.0.0.1:5000
    python tests/vulnerable_app.py 8080     # Starts on http://127.0.0.1:8080

Then in another terminal:
    python dast_scanner.py http://127.0.0.1:5000 --verbose --html report.html
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000

# ── Fake "database" ──────────────────────────────────────────────────────────
USERS_DB = {
    "admin": "admin",
    "test": "test123",
}

PRODUCTS = [
    {"id": 1, "name": "Widget A", "price": 9.99, "secret_note": "Internal SKU: WA-001"},
    {"id": 2, "name": "Widget B", "price": 19.99, "secret_note": "Internal SKU: WB-002"},
]

SESSIONS: dict[str, str] = {}  # session_id -> username


# ── Request handler ──────────────────────────────────────────────────────────

class VulnerableHandler(BaseHTTPRequestHandler):
    """Intentionally insecure HTTP handler with multiple vulnerability classes."""

    def log_message(self, fmt, *args):
        pass  # Suppress request logs

    # ── Routing ───────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        routes = {
            "/": self._index,
            "/login": self._login_page,
            "/search": self._search,
            "/profile": self._profile,
            "/api/products": self._api_products,
            "/api/users": self._api_users,
            "/api/config": self._api_config,
            "/admin": self._admin,
            "/admin/debug": self._admin_debug,
            "/redirect": self._redirect,
            "/robots.txt": self._robots,
            "/sitemap.xml": self._sitemap,
            "/.env": self._dotenv,
            "/.git/config": self._git_config,
            "/swagger.json": self._swagger,
            "/graphql": self._graphql_get,
            "/include": self._file_include,
        }

        handler = routes.get(path)
        if handler:
            handler(params)
        else:
            self._not_found()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""

        if path == "/login":
            self._login_submit(body)
        elif path == "/search":
            params = parse_qs(body)
            self._search(params)
        elif path == "/api/xml":
            self._xml_endpoint(body)
        elif path == "/graphql":
            self._graphql_post(body)
        elif path == "/contact":
            self._contact_submit(body)
        else:
            self._not_found()

    def do_OPTIONS(self):
        self.send_response(200)
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin)  # VULN: reflects any origin
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    # ── Pages ─────────────────────────────────────────────────────────────

    def _index(self, params):
        """Home page with links to vulnerable endpoints."""
        html = """<!DOCTYPE html>
<html><head><title>Vulnerable Test App</title></head>
<body>
<h1>Vulnerable Test Application</h1>
<p>This app is intentionally insecure for DAST scanner testing.</p>
<nav>
<ul>
    <li><a href="/login">Login</a></li>
    <li><a href="/search?q=test">Search</a></li>
    <li><a href="/profile?id=1">Profile</a></li>
    <li><a href="/admin">Admin Panel</a></li>
    <li><a href="/admin/debug">Debug Info</a></li>
    <li><a href="/api/products">Products API</a></li>
    <li><a href="/api/users">Users API</a></li>
    <li><a href="/api/config">Config API</a></li>
    <li><a href="/contact">Contact Form</a></li>
    <li><a href="/include?file=about.html">Include Page</a></li>
    <li><a href="/redirect?url=/">Redirect</a></li>
    <li><a href="/swagger.json">API Docs</a></li>
    <li><a href="/graphql">GraphQL</a></li>
</ul>
</nav>
<form action="/contact" method="POST">
    <input type="text" name="name" placeholder="Name">
    <input type="email" name="email" placeholder="Email">
    <textarea name="message" placeholder="Message"></textarea>
    <button type="submit">Send</button>
</form>
<script>
// Simulated API calls for crawler to discover
fetch('/api/products');
fetch('/api/users');
</script>
</body></html>"""
        self._respond(200, html)

    def _login_page(self, params):
        """Login page — no CSRF token (VULN: CSRF)."""
        html = """<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<h1>Login</h1>
<form action="/login" method="POST">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
</form>
</body></html>"""
        self._respond(200, html)

    def _login_submit(self, body):
        """Login handler — accepts default credentials (VULN: default creds)."""
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        if username in USERS_DB and USERS_DB[username] == password:
            import hashlib
            session_id = hashlib.md5(f"{username}{os.urandom(4).hex()}".encode()).hexdigest()
            SESSIONS[session_id] = username
            self.send_response(302)
            # VULN: no HttpOnly, no Secure, no SameSite
            self.send_header("Set-Cookie", f"session={session_id}; Path=/")
            self.send_header("Location", "/profile?id=1")
            self.end_headers()
        else:
            # VULN: different error messages for valid/invalid users
            if username in USERS_DB:
                msg = "Invalid password"
            else:
                msg = "User not found"
            html = f"""<!DOCTYPE html><html><body>
<h1>Login Failed</h1><p>{msg}</p>
<a href="/login">Try again</a>
</body></html>"""
            self._respond(401, html)

    def _search(self, params):
        """Search — reflects input without encoding (VULN: XSS)."""
        query = params.get("q", [""])[0]
        # VULN: reflected XSS — user input directly in HTML
        html = f"""<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body>
<h1>Search Results for: {query}</h1>
<p>No results found for <strong>{query}</strong></p>
<form action="/search" method="GET">
    <input type="text" name="q" value="{query}">
    <button type="submit">Search</button>
</form>
</body></html>"""
        self._respond(200, html)

    def _profile(self, params):
        """Profile page — IDOR (VULN: Broken Access Control)."""
        user_id = params.get("id", ["1"])[0]
        # VULN: SQL injection simulation — error-based
        if "'" in user_id or ";" in user_id:
            html = f"""<!DOCTYPE html><html><body>
<h1>Error</h1>
<p>SQL Error: You have an error in your SQL syntax near '{user_id}'
at line 1: SELECT * FROM users WHERE id = {user_id}</p>
<p>MySQL server version: 8.0.33</p>
</body></html>"""
            self._respond(500, html)
            return

        html = f"""<!DOCTYPE html>
<html><head><title>Profile</title></head>
<body>
<h1>User Profile #{user_id}</h1>
<p>Username: testuser</p>
<p>Email: test@example.com</p>
<a href="/profile?id=2">Next User</a>
</body></html>"""
        self._respond(200, html)

    def _admin(self, params):
        """Admin panel — no authentication required (VULN: Broken Access Control)."""
        html = """<!DOCTYPE html>
<html><head><title>Admin Panel</title></head>
<body>
<h1>Admin Panel</h1>
<p>Welcome, Administrator!</p>
<ul>
    <li><a href="/admin/debug">Debug Info</a></li>
    <li><a href="/api/config">Configuration</a></li>
    <li><a href="/api/users">User Management</a></li>
</ul>
</body></html>"""
        self._respond(200, html)

    def _admin_debug(self, params):
        """Debug endpoint — exposes server info (VULN: Info Disclosure)."""
        import platform
        debug_info = {
            "python_version": platform.python_version(),
            "os": platform.platform(),
            "db_host": "mysql.internal.example.com:3306",
            "db_user": "app_rw",
            "db_password": "s3cr3t_db_p4ss",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "api_key": "sk-live-abcdef1234567890",
            "internal_endpoints": [
                "http://10.0.1.5:8080/internal-api",
                "http://192.168.1.100:9200/elasticsearch",
            ],
        }
        self._respond_json(200, debug_info)

    def _redirect(self, params):
        """Open redirect (VULN: SSRF/Open Redirect)."""
        url = params.get("url", ["/"])[0]
        # VULN: no validation of redirect target
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def _file_include(self, params):
        """File include endpoint (VULN: LFI)."""
        filename = params.get("file", ["about.html"])[0]
        # VULN: path traversal — no sanitisation
        if os.path.exists(filename):
            try:
                with open(filename, "r") as f:
                    content = f.read()
                self._respond(200, f"<pre>{content}</pre>")
                return
            except Exception:
                pass
        # Simulate file inclusion error showing path
        self._respond(404, f"<p>File not found: {filename}</p>")

    def _contact_submit(self, body):
        """Contact form — no CSRF token (VULN: CSRF)."""
        params = parse_qs(body)
        name = params.get("name", [""])[0]
        html = f"""<!DOCTYPE html><html><body>
<h1>Thank you, {name}!</h1>
<p>Your message has been sent.</p>
</body></html>"""
        self._respond(200, html)

    # ── API Endpoints ─────────────────────────────────────────────────────

    def _api_products(self, params):
        """Products API — no auth required, no rate limit headers."""
        origin = self.headers.get("Origin", "")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        # VULN: CORS reflects any origin
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(json.dumps(PRODUCTS).encode())

    def _api_users(self, params):
        """Users API — exposes user data without auth (VULN: Broken Access Control)."""
        users = [{"username": u, "role": "admin" if u == "admin" else "user"} for u in USERS_DB]
        self._respond_json(200, users)

    def _api_config(self, params):
        """Config API — exposes sensitive configuration."""
        config = {
            "debug": True,
            "database_url": "mysql://root:password@localhost:3306/app",
            "secret_key": "super-secret-key-12345",
            "smtp_password": "mailpass123",
            "jwt_secret": "secret",
        }
        self._respond_json(200, config)

    def _xml_endpoint(self, body):
        """XML endpoint — echoes back XML (VULN: XXE simulation)."""
        # In a real app, this would parse XML with external entities enabled
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(body.encode())

    def _swagger(self, params):
        """Exposed Swagger/OpenAPI doc (VULN: Info Disclosure)."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Vulnerable App API", "version": "1.0.0"},
            "paths": {
                "/api/products": {"get": {"summary": "List products"}},
                "/api/users": {"get": {"summary": "List users"}},
                "/api/config": {"get": {"summary": "Get configuration"}},
            },
        }
        self._respond_json(200, spec)

    def _graphql_get(self, params):
        self._respond_json(200, {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}})

    def _graphql_post(self, body):
        """GraphQL endpoint with introspection enabled (VULN: Info Disclosure)."""
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        if "__schema" in data.get("query", ""):
            self._respond_json(200, {"data": {"__schema": {"types": [
                {"name": "Query"}, {"name": "User"}, {"name": "Product"},
                {"name": "AdminSettings"}, {"name": "InternalConfig"},
            ]}}})
        else:
            self._respond_json(200, {"data": None})

    # ── Special files ─────────────────────────────────────────────────────

    def _dotenv(self, params):
        """Exposed .env file (VULN: Info Disclosure)."""
        content = """# Application Configuration
DATABASE_URL=mysql://root:password@localhost:3306/app
SECRET_KEY=super-secret-key-12345
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SMTP_PASSWORD=mailpass123
API_KEY=sk-live-abcdef1234567890
"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(content.encode())

    def _git_config(self, params):
        """Exposed .git/config (VULN: Info Disclosure)."""
        content = """[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/example/vulnerable-app.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(content.encode())

    def _robots(self, params):
        content = """User-agent: *
Disallow: /admin
Disallow: /admin/debug
Disallow: /api/config
"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(content.encode())

    def _sitemap(self, params):
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>http://127.0.0.1:{PORT}/</loc></url>
    <url><loc>http://127.0.0.1:{PORT}/login</loc></url>
    <url><loc>http://127.0.0.1:{PORT}/search?q=test</loc></url>
    <url><loc>http://127.0.0.1:{PORT}/profile?id=1</loc></url>
</urlset>"""
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(content.encode())

    def _not_found(self):
        # VULN: error page reflects path (potential XSS)
        path = unquote(self.path)
        html = f"""<!DOCTYPE html><html><body>
<h1>404 Not Found</h1>
<p>The page {path} was not found.</p>
<p>Powered by VulnApp/1.0 (Python)</p>
</body></html>"""
        self.send_response(404)
        # VULN: No security headers at all
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "VulnApp/1.0")
        self.end_headers()
        self.wfile.write(html.encode())

    # ── Response helpers ──────────────────────────────────────────────────

    def _respond(self, code, html):
        self.send_response(code)
        # VULN: Missing all security headers
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "VulnApp/1.0")
        # VULN: X-Powered-By reveals stack
        self.send_header("X-Powered-By", "Python/3.12")
        self.end_headers()
        self.wfile.write(html.encode())

    def _respond_json(self, code, data):
        origin = self.headers.get("Origin", "")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "VulnApp/1.0")
        self.send_header("X-Powered-By", "Python/3.12")
        # VULN: CORS reflects any origin
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())


def main():
    server = HTTPServer(("127.0.0.1", PORT), VulnerableHandler)
    print(f"\n  Vulnerable Test App running on http://127.0.0.1:{PORT}")
    print(f"  Press Ctrl+C to stop\n")
    print(f"  Scan with:")
    print(f"    python dast_scanner.py http://127.0.0.1:{PORT} --verbose --html report.html\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
