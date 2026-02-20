import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "osint_monitor.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")


def seed_sources():
    sources = [
        ("CISA Alerts", "https://www.cisa.gov/news.xml", "rss"),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/", "rss"),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "rss"),
        ("r/cybersecurity", "https://www.reddit.com/r/cybersecurity/.rss", "reddit"),
        ("r/netsec", "https://www.reddit.com/r/netsec/.rss", "reddit"),
        ("r/threatintel", "https://www.reddit.com/r/threatintel/.rss", "reddit"),
    ]
    conn = get_connection()
    for name, url, source_type in sources:
        existing = conn.execute(
            "SELECT id FROM sources WHERE url = ?", (url,)
        ).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO sources (name, url, source_type) VALUES (?, ?, ?)",
                (name, url, source_type),
            )
    conn.commit()
    conn.close()
    print("Default sources seeded.")


def seed_keywords():
    keywords = [
        ("ransomware", "malware"),
        ("data breach", "incident"),
        ("credential leak", "incident"),
        ("threat actor", "actor"),
        ("zero-day", "vulnerability"),
        ("CVE", "vulnerability"),
        ("phishing", "tactics"),
        ("APT", "actor"),
        ("supply chain attack", "tactics"),
        ("insider threat", "threat"),
        ("nation-state", "actor"),
        ("cryptocurrency fraud", "financial"),
        ("dark web", "source"),
        ("exploit", "vulnerability"),
        ("DDoS", "tactics"),
    ]
    conn = get_connection()
    for term, category in keywords:
        try:
            conn.execute(
                "INSERT INTO keywords (term, category) VALUES (?, ?)",
                (term, category),
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()
    print("Default keywords seeded.")


if __name__ == "__main__":
    init_db()
    seed_sources()
    seed_keywords()
