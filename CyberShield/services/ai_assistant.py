"""AI cybersecurity assistant — OpenAI API with offline fallback."""

import requests

import config

FALLBACK_KB = {
    "phishing": (
        "Phishing is a social engineering attack where attackers impersonate trusted entities "
        "to steal credentials. Look for mismatched URLs, urgent language, and suspicious senders. "
        "Always verify links by hovering and report suspicious emails to your security team."
    ),
    "password": (
        "Strong passwords should be at least 12 characters with uppercase, lowercase, numbers, "
        "and symbols. Use a password manager and enable MFA. Never reuse passwords across sites."
    ),
    "malware": (
        "Malware includes viruses, trojans, ransomware, and spyware. Prevent it with updated "
        "antivirus, avoid suspicious downloads, verify file hashes, and maintain regular backups."
    ),
    "xss": (
        "Cross-Site Scripting (XSS) injects malicious scripts into web pages. Developers should "
        "sanitize input, use Content-Security-Policy headers, and encode output."
    ),
    "sql injection": (
        "SQL injection exploits poorly sanitized database queries. Use parameterized queries, "
        "ORM frameworks, input validation, and least-privilege database accounts."
    ),
    "jwt": (
        "JWT (JSON Web Tokens) are used for stateless authentication. Store securely, set short "
        "expiry, use HTTPS, and never put sensitive data in the payload."
    ),
    "firewall": (
        "Firewalls filter network traffic based on rules. Configure to deny by default, allow "
        "only required ports, and monitor logs for anomalies."
    ),
    "ransomware": (
        "Ransomware encrypts files and demands payment. Prevent with backups, patch management, "
        "email filtering, and user training. Never pay without consulting security experts."
    ),
}


def ask_assistant(question: str) -> dict:
    question = question.strip()
    if not question:
        return {"answer": "Please enter a cybersecurity question.", "source": "system"}

    if config.OPENAI_API_KEY:
        api_answer = _call_openai(question)
        if api_answer:
            return {"answer": api_answer, "source": "openai"}

    return {"answer": _fallback_answer(question), "source": "offline_kb"}


def _call_openai(question: str) -> str | None:
    try:
        response = requests.post(
            f"{config.OPENAI_API_BASE}/chat/completions",
            headers={
                "Authorization": f"Bearer {config.OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": config.OPENAI_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are CyberShield AI, a concise cybersecurity assistant. "
                            "Give practical, accurate security advice in 2-4 paragraphs."
                        ),
                    },
                    {"role": "user", "content": question},
                ],
                "max_tokens": 500,
                "temperature": 0.4,
            },
            timeout=30,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except Exception:
        return None


def _fallback_answer(question: str) -> str:
    q = question.lower()
    for keyword, answer in FALLBACK_KB.items():
        if keyword in q:
            return answer

    return (
        "I'm CyberShield AI (offline mode). Based on your question, here are general tips:\n\n"
        "• Keep software and systems patched\n"
        "• Use strong, unique passwords with MFA\n"
        "• Be cautious with email links and attachments\n"
        "• Monitor logs and use threat detection tools\n"
        "• Follow the principle of least privilege\n\n"
        "For AI-powered responses, add your OPENAI_API_KEY to the .env file.\n\n"
        f"Your question: {question}"
    )
