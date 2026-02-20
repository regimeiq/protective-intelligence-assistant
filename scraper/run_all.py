import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.init_db import init_db, seed_sources, seed_keywords
from scraper.rss_scraper import scrape_rss_sources
from scraper.reddit_scraper import scrape_reddit_sources
from scraper.pastebin_monitor import scrape_pastebin


def run_all_scrapers():
    print("=" * 60)
    print("OSINT THREAT MONITOR - SCRAPER RUN")
    print("=" * 60)

    # Initialize database if needed
    init_db()
    seed_sources()
    seed_keywords()

    total = 0
    print("\n--- RSS Feeds ---")
    total += scrape_rss_sources()

    print("\n--- Reddit ---")
    total += scrape_reddit_sources()

    print("\n--- Pastebin ---")
    total += scrape_pastebin()

    print("\n" + "=" * 60)
    print(f"TOTAL NEW ALERTS: {total}")
    print("=" * 60)


if __name__ == "__main__":
    run_all_scrapers()
