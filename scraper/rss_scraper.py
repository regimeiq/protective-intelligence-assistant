import feedparser
import re
from datetime import datetime
from database.init_db import get_connection
from analytics.risk_scoring import increment_keyword_frequency, score_alert
from analytics.dedup import check_duplicate


def fetch_rss_feed(url):
    feed = feedparser.parse(url)
    entries = []
    for entry in feed.entries:
        entries.append(
            {
                "title": entry.get("title", ""),
                "content": entry.get("summary", entry.get("description", "")),
                "url": entry.get("link", ""),
                "published": entry.get("published", str(datetime.utcnow())),
            }
        )
    return entries


def match_keywords(text, keywords):
    matches = []
    text_lower = text.lower()
    for keyword in keywords:
        if re.search(r"\b" + re.escape(keyword["term"].lower()) + r"\b", text_lower):
            matches.append(keyword)
    return matches


def get_active_keywords(conn):
    cursor = conn.execute("SELECT id, term, category FROM keywords WHERE active = 1")
    return [dict(row) for row in cursor.fetchall()]


def get_active_sources(conn, source_type="rss"):
    cursor = conn.execute(
        "SELECT id, name, url FROM sources WHERE source_type = ? AND active = 1",
        (source_type,),
    )
    return [dict(row) for row in cursor.fetchall()]


def alert_exists(conn, source_id, keyword_id, url):
    cursor = conn.execute(
        "SELECT 1 FROM alerts WHERE source_id = ? AND keyword_id = ? AND url = ?",
        (source_id, keyword_id, url),
    )
    return cursor.fetchone() is not None


def run_rss_scraper():
    conn = get_connection()
    keywords = get_active_keywords(conn)
    sources = get_active_sources(conn, "rss")
    new_alerts = 0
    duplicates = 0

    for source in sources:
        print(f"Scraping: {source['name']}")
        entries = fetch_rss_feed(source["url"])

        for entry in entries:
            combined_text = f"{entry['title']} {entry['content']}"
            matches = match_keywords(combined_text, keywords)

            for keyword in matches:
                if not alert_exists(conn, source["id"], keyword["id"], entry["url"]):
                    content_hash, duplicate_of = check_duplicate(
                        conn, entry["title"], entry["content"]
                    )
                    conn.execute(
                        """INSERT INTO alerts
                           (source_id, keyword_id, title, content, url, matched_term,
                            content_hash, duplicate_of, severity)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            source["id"],
                            keyword["id"],
                            entry["title"],
                            entry["content"][:2000],
                            entry["url"],
                            keyword["term"],
                            content_hash,
                            duplicate_of,
                            "low",
                        ),
                    )
                    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

                    if duplicate_of is None:
                        # Only score and count unique alerts
                        increment_keyword_frequency(conn, keyword["id"])
                        score_alert(
                            conn, alert_id, keyword["id"], source["id"]
                        )
                        new_alerts += 1
                    else:
                        duplicates += 1

    conn.commit()
    conn.close()
    print(f"RSS scrape complete. {new_alerts} new alerts, {duplicates} duplicates skipped.")
    return new_alerts


if __name__ == "__main__":
    run_rss_scraper()
