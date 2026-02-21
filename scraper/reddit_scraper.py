import feedparser
from datetime import datetime
from database.init_db import get_connection
from scraper.rss_scraper import match_keywords, get_active_keywords, alert_exists
from analytics.risk_scoring import increment_keyword_frequency, score_alert
from analytics.dedup import check_duplicate


def fetch_reddit_rss(url):
    feed = feedparser.parse(url)
    entries = []
    for entry in feed.entries:
        entries.append(
            {
                "title": entry.get("title", ""),
                "content": entry.get("summary", ""),
                "url": entry.get("link", ""),
                "published": entry.get("published", str(datetime.utcnow())),
            }
        )
    return entries


def get_reddit_sources(conn):
    cursor = conn.execute(
        "SELECT id, name, url FROM sources WHERE source_type = 'reddit' AND active = 1"
    )
    return [dict(row) for row in cursor.fetchall()]


def run_reddit_scraper():
    conn = get_connection()
    keywords = get_active_keywords(conn)
    sources = get_reddit_sources(conn)
    new_alerts = 0
    duplicates = 0

    for source in sources:
        print(f"Scraping: {source['name']}")
        entries = fetch_reddit_rss(source["url"])

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
                        increment_keyword_frequency(conn, keyword["id"])
                        score_alert(conn, alert_id, keyword["id"], source["id"])
                        new_alerts += 1
                    else:
                        duplicates += 1

    conn.commit()
    conn.close()
    print(f"Reddit scrape complete. {new_alerts} new alerts, {duplicates} duplicates skipped.")
    return new_alerts


if __name__ == "__main__":
    run_reddit_scraper()
