"""Phishing URL detection using heuristic analysis."""

import re
import socket
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "signin", "wallet", "suspend", "urgent",
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov"]

TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "amazon.com",
    "apple.com", "facebook.com", "linkedin.com",
]


def analyze_url(url: str) -> dict:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower()
    findings = []
    score = 0

    if not domain:
        return {
            "url": url,
            "risk_level": "critical",
            "phishing_score": 100,
            "is_suspicious": True,
            "findings": [{"severity": "high", "title": "Invalid URL", "detail": "Could not parse domain"}],
            "summary": "Invalid URL — cannot analyze",
        }

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 30
        findings.append({
            "severity": "high",
            "title": "IP address in URL",
            "detail": f"Domain is a raw IP: {domain}",
        })

    if domain.count(".") >= 3:
        score += 15
        findings.append({
            "severity": "medium",
            "title": "Many subdomains",
            "detail": "Excessive subdomains can hide the real domain",
        })

    if parsed.scheme == "http":
        score += 10
        findings.append({
            "severity": "medium",
            "title": "No HTTPS",
            "detail": "Connection is not encrypted",
        })

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            findings.append({
                "severity": "high",
                "title": "Suspicious TLD",
                "detail": f"Domain uses high-risk TLD: {tld}",
            })

    if "@" in url:
        score += 25
        findings.append({
            "severity": "high",
            "title": "URL contains @ symbol",
            "detail": "Often used to disguise the real destination",
        })

    keyword_hits = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
    if keyword_hits:
        score += min(20, len(keyword_hits) * 5)
        findings.append({
            "severity": "medium",
            "title": "Suspicious keywords",
            "detail": f"Found: {', '.join(keyword_hits[:5])}",
        })

    if len(url) > 100:
        score += 10
        findings.append({
            "severity": "low",
            "title": "Unusually long URL",
            "detail": f"URL length: {len(url)} characters",
        })

    if "xn--" in domain or any(ord(c) > 127 for c in domain):
        score += 25
        findings.append({
            "severity": "high",
            "title": "Possible homograph attack",
            "detail": "Punycode or unicode characters detected in domain",
        })

    brand_impersonation = _check_brand_impersonation(domain)
    if brand_impersonation:
        score += 35
        findings.append({
            "severity": "critical",
            "title": "Brand impersonation",
            "detail": f"Domain may impersonate: {brand_impersonation}",
        })

    try:
        resolved = socket.gethostbyname(domain)
        findings.append({
            "severity": "info",
            "title": "DNS resolution",
            "detail": f"Resolves to {resolved}",
        })
    except socket.gaierror:
        score += 15
        findings.append({
            "severity": "medium",
            "title": "DNS lookup failed",
            "detail": "Domain could not be resolved",
        })

    score = min(100, score)
    if score >= 70:
        risk, suspicious = "critical", True
    elif score >= 50:
        risk, suspicious = "high", True
    elif score >= 30:
        risk, suspicious = "medium", True
    elif score >= 15:
        risk, suspicious = "low", False
    else:
        risk, suspicious = "low", False

    return {
        "url": url,
        "domain": domain,
        "phishing_score": score,
        "risk_level": risk,
        "is_suspicious": suspicious,
        "findings": findings,
        "summary": f"Phishing risk score: {score}/100 — {'Suspicious' if suspicious else 'Likely safe'}",
    }


def _check_brand_impersonation(domain: str) -> str | None:
    for brand in TRUSTED_DOMAINS:
        brand_name = brand.split(".")[0]
        if brand_name in domain and domain != brand and not domain.endswith("." + brand):
            if domain.replace("-", "").replace(".", "") != brand.replace(".", ""):
                return brand
    return None
