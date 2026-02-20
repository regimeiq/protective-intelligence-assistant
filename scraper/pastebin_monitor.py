import requests
from bs4 import BeautifulSoup
from datetime import datetime
from database.init_db import get_connection
from scraper.rss_scraper import match_keywords, get_active_keywords, alert_exists, assign_severity

PASTEBIN_ARCHIVE_URL = "https://pastebin.com/archive"


def fetch_recent_pastes():
    """Scrape pastebin archive page for recent public pastes."""
    entries = []
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(PASTEBIN_ARCHIVE_URL, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.find("table", class_="maintable")
        if not table:
            print("No paste table found.")
            return entries

        rows = table.find_all("tr")[1:]  # skip header
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 1:
                link = cols[0].find("a")
                if link:
                    paste_id = link.get("href", "").strip("/")
                    title = link.text.strip() or "Untitled"
                    entries.append(
                        {
                            "title": title,
                            "url": f"https://pastebin.com/{paste_id}",
                            "paste_id": paste_id,
                        }
                    )
    except requests.RequestException as e:
        print(f"Error fetching pastebin archive: {e}")

    return entries


def fetch_paste_content(url):
    """Fetch raw content of a specific paste."""
    try:
        raw_url = url.replace("pastebin.com/", "pastebin.com/raw/")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text[:5000]
    except requests.RequestException as e:
        print(f"Error fetching paste content: {e}")
        return ""


def ensure_pastebin_source(conn):
    """Make sure pastebin exists as a source in the DB."""
    cursor = conn.execute(
        "SELECT id FROM sources WHERE name = 'Pastebin Archive'"
    )
    row = cursor.fetchone()
    if row:
        return row["id"]

    conn.execute(
        "INSERT INTO sources (name, url, source_type) VALUES (?, ?, ?)",
        ("Pastebin Archive", PASTEBIN_ARCHIVE_URL, "pastebin"),
    )
    conn.commit()
    cursor = conn.execute(
        "SELECT id FROM sources WHERE name = 'Pastebin Archive'"
    )
    return cursor.fetchone()["id"]


def run_pastebin_scraper():
    conn = get_connection()
    keywords = get_active_keywords(conn)
    source_id = ensure_pastebin_source(conn)
    new_alerts = 0

    print("Scraping: Pastebin Archive")
    pastes = fetch_recent_pastes()

    for paste in pastes[:20]:  # limit to avoid rate limiting
        content = fetch_paste_content(paste["url"])
        if not content:
            continue

        combined_text = f"{paste['title']} {content}"
        matches = match_keywords(combined_text, keywords)

        for keyword in matches:
            if not alert_exists(conn, source_id, keyword["id"], paste["url"]):
                severity = assign_severity(keyword["category"], len(matches))
                conn.execute(
                    """INSERT INTO alerts 
                       (source_id, keyword_id, title, content, url, matched_term, severity) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        source_id,
                        keyword["id"],
                        paste["title"],
                        content[:2000],
                        paste["url"],
                        keyword["term"],
                        severity,
                    ),
                )
                new_alerts += 1

    conn.commit()
    conn.close()
    print(f"Pastebin scrape complete. {new_alerts} new alerts.")
    return new_alerts


if __name__ == "__main__":
    run_pastebin_scraper()
