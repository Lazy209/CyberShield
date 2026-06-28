"""Basic web vulnerability scanner — HTTP headers and SSL checks."""

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Content-Security-Policy": "Prevents XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Restricts browser features",
    "X-XSS-Protection": "Legacy XSS filter (deprecated but still checked)",
}


def scan_url(target: str, timeout: int = 10) -> dict:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    hostname = parsed.hostname
    findings = []
    score = 100

    if not hostname:
        return _error_result(target, "Invalid URL")

    ssl_info = _check_ssl(hostname, parsed.port or 443)
    findings.extend(ssl_info["findings"])
    score -= ssl_info["penalty"]

    try:
        response = requests.get(
            target,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "CyberShield-Scanner/1.0"},
        )
        findings.append({
            "severity": "info",
            "title": "HTTP Response",
            "detail": f"Status {response.status_code}, final URL: {response.url}",
        })

        if response.url.startswith("http://"):
            score -= 15
            findings.append({
                "severity": "medium",
                "title": "Final URL uses HTTP",
                "detail": "Connection may not be fully encrypted",
            })

        server = response.headers.get("Server", "")
        if server:
            score -= 5
            findings.append({
                "severity": "low",
                "title": "Server banner exposed",
                "detail": f"Server: {server}",
            })

        powered = response.headers.get("X-Powered-By", "")
        if powered:
            score -= 10
            findings.append({
                "severity": "medium",
                "title": "Technology disclosure",
                "detail": f"X-Powered-By: {powered}",
            })

        for header, description in SECURITY_HEADERS.items():
            if header.lower() in {k.lower() for k in response.headers}:
                actual = next(
                    (response.headers[k] for k in response.headers if k.lower() == header.lower()),
                    "",
                )
                findings.append({
                    "severity": "info",
                    "title": f"Header present: {header}",
                    "detail": f"{description} — {actual[:80]}",
                })
            else:
                penalty = 8 if header in ("Strict-Transport-Security", "Content-Security-Policy") else 5
                score -= penalty
                findings.append({
                    "severity": "medium" if penalty >= 8 else "low",
                    "title": f"Missing header: {header}",
                    "detail": description,
                })

        cookies = response.headers.get("Set-Cookie", "")
        if cookies and "secure" not in cookies.lower():
            score -= 10
            findings.append({
                "severity": "medium",
                "title": "Cookie without Secure flag",
                "detail": "Session cookies may be sent over HTTP",
            })

    except requests.exceptions.SSLError as exc:
        score -= 30
        findings.append({
            "severity": "high",
            "title": "SSL/TLS error",
            "detail": str(exc)[:200],
        })
    except requests.exceptions.RequestException as exc:
        return _error_result(target, str(exc)[:200])

    score = max(0, min(100, score))
    if score >= 80:
        risk = "low"
    elif score >= 60:
        risk = "medium"
    elif score >= 40:
        risk = "high"
    else:
        risk = "critical"

    return {
        "target": target,
        "security_score": score,
        "risk_level": risk,
        "findings": findings,
        "summary": f"Security score: {score}/100 — {len(findings)} findings",
    }


def _check_ssl(hostname: str, port: int) -> dict:
    findings = []
    penalty = 0
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    not_after = cert.get("notAfter", "")
                    findings.append({
                        "severity": "info",
                        "title": "SSL certificate valid",
                        "detail": f"Expires: {not_after}",
                    })
                    try:
                        if not isinstance(not_after, str):
                            raise ValueError("notAfter is not a string")
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        days_left = (expiry - datetime.now(timezone.utc)).days
                        if days_left < 30:
                            penalty += 15
                            findings.append({
                                "severity": "high",
                                "title": "Certificate expiring soon",
                                "detail": f"Expires in {days_left} days",
                            })
                    except ValueError:
                        pass
    except ssl.SSLCertVerificationError as exc:
        penalty += 25
        findings.append({
            "severity": "high",
            "title": "Invalid SSL certificate",
            "detail": str(exc)[:200],
        })
    except OSError as exc:
        penalty += 10
        findings.append({
            "severity": "medium",
            "title": "SSL check skipped",
            "detail": str(exc)[:200],
        })
    return {"findings": findings, "penalty": penalty}


def _error_result(target: str, message: str) -> dict:
    return {
        "target": target,
        "security_score": 0,
        "risk_level": "critical",
        "findings": [{"severity": "high", "title": "Scan failed", "detail": message}],
        "summary": f"Scan failed: {message}",
    }
