"""
Scraper orchestration with async HTTP fetching and performance tracking.

Architecture:
- HTTP fetches use aiohttp for concurrent source fetching within each scraper type
- SQLite writes stay synchronous (single connection, no locking issues)
- feedparser parses raw text from aiohttp responses (not URLs directly)
- Performance metrics recorded to scrape_runs table
"""

import asyncio
import time
from datetime import datetime

from scraper.rss_scraper import (
    run_rss_scraper,
    match_keywords,
    get_active_keywords,
    get_active_sources,
    alert_exists,
)
from scraper.reddit_scraper import run_reddit_scraper
from scraper.pastebin_monitor import run_pastebin_scraper
from database.init_db import get_connection

try:
    import aiohttp
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False


def _record_scrape_run(scraper_type, started_at, total_alerts, status="completed"):
    """Record scrape run metrics to scrape_runs table."""
    try:
        conn = get_connection()
        completed_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        duration = time.time() - started_at
        aps = total_alerts / duration if duration > 0 else 0.0

        conn.execute(
            """INSERT INTO scrape_runs
            (started_at, completed_at, scraper_type, total_alerts,
             duration_seconds, alerts_per_second, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.utcfromtimestamp(started_at).strftime("%Y-%m-%d %H:%M:%S"),
                completed_at,
                scraper_type,
                total_alerts,
                round(duration, 2),
                round(aps, 2),
                status,
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: Could not record scrape run: {e}")


async def _fetch_url_async(session, url, timeout=15):
    """Fetch a URL asynchronously, return text content."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            return await resp.text()
    except Exception as e:
        print(f"Async fetch error for {url}: {e}")
        return None


async def run_rss_scraper_async():
    """
    Async RSS scraper: fetch all RSS feeds concurrently via aiohttp,
    then parse and process synchronously.
    """
    import feedparser
    from analytics.risk_scoring import increment_keyword_frequency, score_alert
    from analytics.dedup import check_duplicate

    conn = get_connection()
    keywords = get_active_keywords(conn)
    sources = get_active_sources(conn, "rss")
    new_alerts = 0
    duplicates = 0

    # Fetch all feeds concurrently
    async with aiohttp.ClientSession() as session:
        tasks = [_fetch_url_async(session, s["url"]) for s in sources]
        raw_responses = await asyncio.gather(*tasks)

    # Process each feed synchronously (SQLite writes)
    for source, raw_text in zip(sources, raw_responses):
        if not raw_text:
            print(f"Skipping {source['name']} (fetch failed)")
            continue

        print(f"Processing: {source['name']}")
        feed = feedparser.parse(raw_text)

        for entry in feed.entries:
            title = entry.get("title", "")
            content = entry.get("summary", entry.get("description", ""))
            url = entry.get("link", "")
            combined_text = f"{title} {content}"
            matches = match_keywords(combined_text, keywords)

            for keyword in matches:
                if not alert_exists(conn, source["id"], keyword["id"], url):
                    content_hash, duplicate_of = check_duplicate(conn, title, content)
                    conn.execute(
                        """INSERT INTO alerts
                           (source_id, keyword_id, title, content, url, matched_term,
                            content_hash, duplicate_of, severity)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (source["id"], keyword["id"], title, content[:2000], url,
                         keyword["term"], content_hash, duplicate_of, "low"),
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
    print(f"Async RSS scrape complete. {new_alerts} new alerts, {duplicates} duplicates.")
    return new_alerts


async def run_reddit_scraper_async():
    """
    Async Reddit scraper: fetch all Reddit RSS feeds concurrently.
    """
    import feedparser
    from analytics.risk_scoring import increment_keyword_frequency, score_alert
    from analytics.dedup import check_duplicate

    conn = get_connection()
    keywords = get_active_keywords(conn)
    sources = conn.execute(
        "SELECT id, name, url FROM sources WHERE source_type = 'reddit' AND active = 1"
    ).fetchall()
    sources = [dict(s) for s in sources]
    new_alerts = 0
    duplicates = 0

    async with aiohttp.ClientSession() as session:
        tasks = [_fetch_url_async(session, s["url"]) for s in sources]
        raw_responses = await asyncio.gather(*tasks)

    for source, raw_text in zip(sources, raw_responses):
        if not raw_text:
            print(f"Skipping {source['name']} (fetch failed)")
            continue

        print(f"Processing: {source['name']}")
        feed = feedparser.parse(raw_text)

        for entry in feed.entries:
            title = entry.get("title", "")
            content = entry.get("summary", "")
            url = entry.get("link", "")
            combined_text = f"{title} {content}"
            matches = match_keywords(combined_text, keywords)

            for keyword in matches:
                if not alert_exists(conn, source["id"], keyword["id"], url):
                    content_hash, duplicate_of = check_duplicate(conn, title, content)
                    conn.execute(
                        """INSERT INTO alerts
                           (source_id, keyword_id, title, content, url, matched_term,
                            content_hash, duplicate_of, severity)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (source["id"], keyword["id"], title, content[:2000], url,
                         keyword["term"], content_hash, duplicate_of, "low"),
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
    print(f"Async Reddit scrape complete. {new_alerts} new alerts, {duplicates} duplicates.")
    return new_alerts


async def run_all_scrapers_async():
    """
    Orchestrate all async scrapers concurrently.
    RSS and Reddit run in parallel; Pastebin runs sync after (rate-limited).
    """
    rss_task = run_rss_scraper_async()
    reddit_task = run_reddit_scraper_async()

    # RSS and Reddit concurrently
    rss_count, reddit_count = await asyncio.gather(rss_task, reddit_task)

    # Pastebin stays sync (individual paste fetches are rate-limited)
    pastebin_count = run_pastebin_scraper()

    total = rss_count + reddit_count + pastebin_count
    return total


def run_all_scrapers():
    """
    Run all scrapers with performance tracking.
    Uses async if aiohttp is available, falls back to sync.
    Backward-compatible — run.py needs zero changes.
    """
    started_at = time.time()
    total = 0
    status = "completed"

    try:
        if ASYNC_AVAILABLE:
            print("Running scrapers (async mode)...")
            total = asyncio.run(run_all_scrapers_async())
        else:
            print("Running scrapers (sync mode — install aiohttp for async)...")
            total += run_rss_scraper()
            total += run_reddit_scraper()
            total += run_pastebin_scraper()
    except Exception as e:
        print(f"Scraper error: {e}")
        status = "error"

    _record_scrape_run("all", started_at, total, status)
    print(f"\nTotal new alerts across all sources: {total}")
    print(f"Duration: {time.time() - started_at:.1f}s")
    return total
