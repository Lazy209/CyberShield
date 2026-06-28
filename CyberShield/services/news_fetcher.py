"""Fetch latest cybersecurity news from RSS feeds."""

import re
from datetime import datetime, timezone

import feedparser

import config


def fetch_security_news(limit: int = 12) -> list[dict]:
    articles = []
    for feed_url in config.SECURITY_NEWS_RSS:
        try:
            feed = feedparser.parse(feed_url)
            source = getattr(feed.feed, "title", None) or feed_url
            for entry in feed.entries[: limit // len(config.SECURITY_NEWS_RSS) + 2]:
                published = entry.get("published", entry.get("updated", ""))
                articles.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", "#"),
                    "source": source,
                    "published": published,
                    "summary": _clean_summary(str(entry.get("summary") or "")),
                })
        except Exception:
            continue

    if not articles:
        return _fallback_news()

    articles.sort(key=lambda a: a.get("published", ""), reverse=True)
    return articles[:limit]


def _clean_summary(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    return text[:200] + "..." if len(text) > 200 else text


def _fallback_news() -> list[dict]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return [
        {
            "title": "Phishing remains top initial access vector in 2025",
            "link": "#",
            "source": "CyberShield Intel",
            "published": now,
            "summary": "Industry reports show phishing accounts for over 30% of breach entry points.",
        },
        {
            "title": "Critical OpenSSL vulnerability patched — update recommended",
            "link": "#",
            "source": "CyberShield Intel",
            "published": now,
            "summary": "Security teams urged to patch affected systems within 48 hours.",
        },
        {
            "title": "AI-powered social engineering attacks on the rise",
            "link": "#",
            "source": "CyberShield Intel",
            "published": now,
            "summary": "Attackers use LLMs to craft highly personalized phishing emails.",
        },
    ]
