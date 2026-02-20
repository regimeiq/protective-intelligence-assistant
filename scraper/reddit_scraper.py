import feedparser
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.init_db import get_connection
from scraper.rss_scraper import match_keywords, get_severity, SEVERITY_MAP


def scrape_reddit_sources():
    conn = get_connection()
    sources = conn.execute(
        "SELECT id, name, url FROM sources WHERE source_type = 'reddit' AND active = 1"
    ).fetchall()
    keywords = conn.execute(
        "SELECT id, term FROM keywords WHERE active = 1"
    ).fetchall()

    total_alerts = 0
    for source in sources:
        source_id, source_name, feed_url = source["id"], source["name"], source["url"]
        print(f"Scraping: {source_name} ({feed_url})")
        try:
            feed = feedparser.parse(feed_url)
            entries = feed.entries
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
    print(f"\nReddit scraping complete. {total_alerts} new alerts generated.")
    return total_alerts


if __name__ == "__main__":
    scrape_reddit_sources()
