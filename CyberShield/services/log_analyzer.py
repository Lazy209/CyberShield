"""Security log file analyzer."""

import re
from collections import Counter

PATTERNS = [
    (r"failed password|authentication failure|login failed", "Failed login attempt", "medium"),
    (r"invalid user|unknown user", "Invalid user access attempt", "medium"),
    (r"sql injection|union select|or 1=1", "Possible SQL injection", "critical"),
    (r"<script|javascript:|onerror=", "Possible XSS attempt", "high"),
    (r"\.\./|\.\.\\", "Directory traversal attempt", "high"),
    (r"sudo:|root access|privilege escalation", "Privilege escalation attempt", "high"),
    (r"port scan|nmap|masscan", "Port scanning activity", "medium"),
    (r"denied|forbidden|unauthorized", "Access denied event", "low"),
    (r"error|exception|critical", "System error/critical event", "low"),
    (r"brute.?force|too many attempts", "Brute force indicator", "high"),
]


def analyze_logs(log_text: str) -> dict:
    lines = log_text.strip().splitlines()
    if not lines:
        return {
            "total_lines": 0,
            "risk_level": "low",
            "findings": [],
            "summary": "No log content provided",
        }

    findings = []
    matched_lines = []
    severity_counts = Counter()

    for pattern, title, severity in PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE)
        hits = [i + 1 for i, line in enumerate(lines) if regex.search(line)]
        if hits:
            severity_counts[severity] += len(hits)
            sample = lines[hits[0] - 1][:120]
            findings.append({
                "severity": severity,
                "title": title,
                "detail": f"{len(hits)} occurrence(s). Example (line {hits[0]}): {sample}",
                "count": len(hits),
            })
            matched_lines.extend(hits)

    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ips = Counter()
    for line in lines:
        for ip in ip_pattern.findall(line):
            ips[ip] += 1

    top_ips = ips.most_common(5)
    if top_ips:
        findings.append({
            "severity": "info",
            "title": "Top source IPs",
            "detail": ", ".join(f"{ip} ({count}x)" for ip, count in top_ips),
            "count": len(ips),
        })

    unique_suspicious = len(set(matched_lines))
    total = len(lines)

    if severity_counts["critical"] > 0:
        risk = "critical"
    elif severity_counts["high"] > 5:
        risk = "high"
    elif severity_counts["high"] > 0 or severity_counts["medium"] > 10:
        risk = "medium"
    elif unique_suspicious > 0:
        risk = "low"
    else:
        risk = "low"

    return {
        "total_lines": total,
        "suspicious_lines": unique_suspicious,
        "risk_level": risk,
        "severity_breakdown": dict(severity_counts),
        "findings": findings,
        "summary": (
            f"Analyzed {total} lines — {unique_suspicious} suspicious, "
            f"{len(findings)} finding categories"
        ),
    }
