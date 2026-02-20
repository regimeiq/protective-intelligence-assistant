import feedparser
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.init_db import get_connection


def fetch_rss_feed(url):
    feed = feedparser.parse(url)
    return feed.entries


def match_keywords(text, keywords):
    matched = []
    text_lower = text.lower()
    for keyword_id, term in keywords:
        if term.lower() in text_lower:
            matched.append((keyword_id, term))
    return matched


def get_severity(text, severity_map):
    text_lower = text.lower()
    for severity, terms in severity_map.items():
        for term in terms:
            if term.lower() in text_lower:
                return severity
    return "low"


SEVERITY_MAP = {
    "critical": ["zero-day", "active exploitation", "critical vulnerability", "nation-state"],
    "high": ["ransomware", "data breach", "APT", "remote code execution"],
    "medium": ["phishing", "credential leak", "DDoS"],
    "low": ["vulnerability disclosed", "patch available"],
}


def scrape_rss_sources():
    conn = get_connection()
    sources = conn.execute(
        "SELECT id, name, url FROM sources WHERE source_type = 'rss' AND active = 1"
    ).fetchall()
    keywords = conn.execute(
        "SELECT id, term FROM keywords WHERE active = 1"
    ).fetchall()

    total_alerts = 0
    for source in sources:
        source_id, source_name, feed_url = source["id"], source["name"], source["url"]
        print(f"Scraping: {source_name} ({feed_url})")
        try:
            entries = fetch_rss_feed(feed_url)
        except Exception as e:
            print(f"  Error fetching {source_name}: {e}")
            continue

        for entry in entries:
            title = entry.get("title", "")
            content = entry.get("summary", entry.get("description", ""))
            link = entry.get("link", "")
            combined_text = f"{title} {content}"
            matched = match_keywords(combined_text, keywords)

            for keyword_id, term in matched:
                existing = conn.execute(
                    "SELECT id FROM alerts WHERE url = ? AND matched_keyword_id = ?",
                    (link, keyword_id),
                ).fetchone()
                if existing:
                    continue
                severity = get_severity(combined_text, SEVERITY_MAP)
                conn.execute(
                    "INSERT INTO alerts (title, content, url, source_id, matched_keyword_id, severity) VALUES (?, ?, ?, ?, ?, ?)",
                    (title, content[:500], link, source_id, keyword_id, severity),
                )
                total_alerts += 1
                print(f"  ALERT [{severity.upper()}]: '{title}' matched '{term}'")

    conn.commit()
    conn.close()
    print(f"\nScraping complete. {total_alerts} new alerts generated.")
    return total_alerts


if __name__ == "__main__":
    scrape_rss_sources()
