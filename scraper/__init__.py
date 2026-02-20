from scraper.rss_scraper import run_rss_scraper
from scraper.reddit_scraper import run_reddit_scraper
from scraper.pastebin_monitor import run_pastebin_scraper


def run_all_scrapers():
    """Run all scrapers sequentially."""
    total = 0
    total += run_rss_scraper()
    total += run_reddit_scraper()
    total += run_pastebin_scraper()
    print(f"\nTotal new alerts across all sources: {total}")
    return total
