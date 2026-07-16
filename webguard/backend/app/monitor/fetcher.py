"""
Passive, read-only reconnaissance of a monitored asset.

Everything here only issues normal HTTP(S) GET/HEAD requests that any
ordinary visitor or browser would make against the asset the organization
already owns/operates. It does not attempt exploitation, brute forcing,
or any intrusive action against third-party systems.
"""
import hashlib
import json
import re
import socket
import ssl
import time
from datetime import datetime
from urllib.parse import urlparse

import httpx

from app.config import settings

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]

# Common paths that should NOT be publicly exposed on a production site.
# Checking whether *your own* asset accidentally serves these is a standard,
# non-intrusive part of an external security posture review (comparable to
# what tools like Mozilla Observatory / securityheaders.com do).
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/backup.zip",
    "/.aws/credentials",
    "/server-status",
]


def normalize_html(html: str) -> str:
    """Strip volatile bits (whitespace runs, common timestamp/nonce patterns)
    so trivial dynamic content doesn't trigger false-positive defacement alerts."""
    text = re.sub(r"\s+", " ", html)
    text = re.sub(r"nonce=\"[^\"]+\"", "nonce=\"X\"", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", "TIMESTAMP", text)
    return text.strip()


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def get_tls_info(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"enabled": False, "note": "Site is not served over HTTPS."}
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=settings.REQUEST_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        expiry = None
        days_left = None
        if not_after:
            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry_dt.isoformat()
            days_left = (expiry_dt - datetime.utcnow()).days
        return {
            "enabled": True,
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "not_after": expiry,
            "days_until_expiry": days_left,
        }
    except Exception as e:
        return {"enabled": True, "error": str(e)}


def check_security_headers(headers: httpx.Headers) -> dict:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    present = {h: lower_headers.get(h) for h in SECURITY_HEADERS if h in lower_headers}
    missing = [h for h in SECURITY_HEADERS if h not in lower_headers]
    server_banner = lower_headers.get("server")
    powered_by = lower_headers.get("x-powered-by")
    return {
        "present": present,
        "missing": missing,
        "server_banner_disclosed": server_banner,
        "x_powered_by_disclosed": powered_by,
    }


def check_exposed_paths(client: httpx.Client, base_url: str) -> list:
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    exposed = []
    for path in SENSITIVE_PATHS:
        try:
            resp = client.get(root + path, timeout=settings.REQUEST_TIMEOUT_SECONDS)
            if resp.status_code == 200 and len(resp.content) > 0:
                exposed.append({"path": path, "status": resp.status_code})
        except httpx.HTTPError:
            continue
    return exposed


def derive_vulnerability_findings(headers_report: dict, tls_report: dict, exposed_paths: list) -> list:
    findings = []
    for h in headers_report.get("missing", []):
        findings.append({
            "id": f"missing-header-{h}",
            "severity": "medium" if h in ("content-security-policy", "strict-transport-security") else "low",
            "title": f"Missing security header: {h}",
        })
    if headers_report.get("server_banner_disclosed"):
        findings.append({
            "id": "server-banner-disclosed",
            "severity": "low",
            "title": f"Server header discloses software info: {headers_report['server_banner_disclosed']}",
        })
    if tls_report.get("enabled") is False:
        findings.append({"id": "no-https", "severity": "critical", "title": "Site is not served over HTTPS."})
    days_left = tls_report.get("days_until_expiry")
    if isinstance(days_left, int) and days_left < 21:
        findings.append({
            "id": "tls-expiring-soon",
            "severity": "high" if days_left < 7 else "medium",
            "title": f"TLS certificate expires in {days_left} day(s).",
        })
    for item in exposed_paths:
        findings.append({
            "id": f"exposed-path-{item['path']}",
            "severity": "critical",
            "title": f"Sensitive path publicly accessible: {item['path']}",
        })
    return findings


def fetch_asset(url: str) -> dict:
    """Performs one full monitoring pass against a single asset URL."""
    result = {
        "fetched_at": datetime.utcnow().isoformat(),
        "http_status": None,
        "response_time_ms": None,
        "raw_html": "",
        "normalized_text": "",
        "content_hash": None,
        "content_length": 0,
        "security_headers": {},
        "tls_info": {},
        "exposed_paths": [],
        "vulnerability_findings": [],
        "error": None,
    }
    try:
        with httpx.Client(follow_redirects=True, headers={"User-Agent": "WebGuard-Monitor/1.0"}) as client:
            start = time.time()
            resp = client.get(url, timeout=settings.REQUEST_TIMEOUT_SECONDS)
            elapsed_ms = (time.time() - start) * 1000

            result["http_status"] = resp.status_code
            result["response_time_ms"] = round(elapsed_ms, 2)
            result["raw_html"] = resp.text
            normalized = normalize_html(resp.text)
            result["normalized_text"] = normalized
            result["content_hash"] = content_hash(normalized)
            result["content_length"] = len(resp.content)

            headers_report = check_security_headers(resp.headers)
            tls_report = get_tls_info(url)
            exposed = check_exposed_paths(client, url)

            result["security_headers"] = headers_report
            result["tls_info"] = tls_report
            result["exposed_paths"] = exposed
            result["vulnerability_findings"] = derive_vulnerability_findings(headers_report, tls_report, exposed)
    except httpx.HTTPError as e:
        result["error"] = f"Request failed: {e}"
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    return result
