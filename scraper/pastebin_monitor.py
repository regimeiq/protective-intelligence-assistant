import requests
from bs4 import BeautifulSoup
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.init_db import get_connection
from scraper.rss_scraper import match_keywords, get_severity, SEVERITY_MAP

PASTEBIN_ARCHIVE_URL = "https://pastebin.com/archive"


def fetch_recent_pastes():
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        response = requests.get(PASTEBIN_ARCHIVE_URL, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching Pastebin archive: {e}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    pastes = []
    table = soup.find("table", class_="maintable")
    if not table:
        print("Could not find paste archive table.")
        return []

    rows = table.find_all("tr")[1:]
    for row in rows:
        cells = row.find_all("td")
        if len(cells) >= 1:
            link_tag = cells[0].find("a")
            if link_tag:
                paste_id = link_tag.get("href", "").strip("/")
                title = link_tag.text.strip() or "Untitled"
                pastes.append({"id": paste_id, "title": title, "url": f"https://pastebin.com/{paste_id}"})
    return pastes


def fetch_paste_content(paste_url):
    raw_url = paste_url.replace("pastebin.com/", "pastebin.com/raw/")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        response = requests.get(raw_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text[:2000]
    except requests.RequestException:
        return ""


def scrape_pastebin():
    conn = get_connection()
    keywords = conn.execute("SELECT id, term FROM keywords WHERE active = 1").fetchall()

    source = conn.execute("SELECT id FROM sources WHERE name = 'Pastebin'").fetchone()
    if not source:
        conn.execute(
            "INSERT INTO sources (name, url, source_type) VALUES (?, ?, ?)",
            ("Pastebin", PASTEBIN_ARCHIVE_URL, "pastebin"),
        )
        conn.commit()
        source = conn.execute("SELECT id FROM sources WHERE name = 'Pastebin'").fetchone()
    source_id = source["id"]

    total_alerts = 0
    pastes = fetch_recent_pastes()
    print(f"Found {len(pastes)} recent pastes.")

    for paste in pastes[:20]:
        existing = conn.execute("SELECT id FROM alerts WHERE url = ?", (paste["url"],)).fetchone()
        if existing:
            continue
        content = fetch_paste_content(paste["url"])
        if not content:
            continue
        combined_text = f"{paste['title']} {content}"
        matched = match_keywords(combined_text, keywords)

        for keyword_id, term in matched:
            severity = get_severity(combined_text, SEVERITY_MAP)
            conn.execute(
                "INSERT INTO alerts (title, content, url, source_id, matched_keyword_id, severity) VALUES (?, ?, ?, ?, ?, ?)",
                (paste["title"], content[:500], paste["url"], source_id, keyword_id, severity),
            )
            total_alerts += 1
            print(f"  ALERT [{severity.upper()}]: '{paste['title']}' matched '{term}'")

    conn.commit()
    conn.close()
    print(f"\nPastebin scraping complete. {total_alerts} new alerts generated.")
    return total_alerts


if __name__ == "__main__":
    scrape_pastebin()
