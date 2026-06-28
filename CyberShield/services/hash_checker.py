"""File hash checker with known-malware sample database."""

import hashlib

KNOWN_MALWARE_HASHES = {
    "5d41402abc4b2a76b9719d911017c592": {
        "name": "EICAR Test File (MD5)",
        "type": "Test malware signature",
        "severity": "critical",
    },
    "275a021bbfb6489e54d471899f7db9d1663fc033ec8aec31efb6798fb0b64511d": {
        "name": "EICAR Test File (SHA256)",
        "type": "Test malware signature",
        "severity": "critical",
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "name": "Sample trojan hash (demo)",
        "type": "Trojan",
        "severity": "high",
    },
}


def compute_hashes(file_bytes: bytes) -> dict:
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


def check_hash(file_bytes: bytes, filename: str = "upload") -> dict:
    hashes = compute_hashes(file_bytes)
    findings = []

    for algo, digest in hashes.items():
        if digest in KNOWN_MALWARE_HASHES:
            match = KNOWN_MALWARE_HASHES[digest]
            findings.append({
                "algorithm": algo.upper(),
                "hash": digest,
                "matched": True,
                "name": match["name"],
                "type": match["type"],
                "severity": match["severity"],
            })

    matched = bool(findings)
    risk = "critical" if matched else "low"

    return {
        "filename": filename,
        "file_size": len(file_bytes),
        "hashes": hashes,
        "matched_threats": findings,
        "risk_level": risk,
        "is_malicious": matched,
        "summary": (
            f"Threat detected: {findings[0]['name']}"
            if matched
            else "No match in local threat database"
        ),
        "note": "Checked against local demo database. Integrate VirusTotal API for production.",
    }
