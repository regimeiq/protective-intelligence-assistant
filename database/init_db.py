import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "osint_monitor.db")


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")


def seed_default_sources():
    conn = get_connection()
    sources = [
        ("CISA Alerts", "https://www.cisa.gov/news.xml", "rss"),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/", "rss"),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "rss"),
        ("r/cybersecurity", "https://www.reddit.com/r/cybersecurity/.rss", "reddit"),
        ("r/netsec", "https://www.reddit.com/r/netsec/.rss", "reddit"),
        ("r/threatintel", "https://www.reddit.com/r/threatintel/.rss", "reddit"),
    ]
    for name, url, source_type in sources:
        try:
            conn.execute(
                "INSERT OR IGNORE INTO sources (name, url, source_type) VALUES (?, ?, ?)",
                (name, url, source_type),
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()
    print("Default sources seeded.")


def seed_default_keywords():
    conn = get_connection()
    keywords = [
        ("ransomware", "malware"),
        ("data breach", "general"),
        ("credential leak", "vulnerability"),
        ("phishing", "general"),
        ("zero day", "vulnerability"),
        ("APT", "threat_actor"),
        ("supply chain attack", "general"),
        ("CVE", "vulnerability"),
        ("DDoS", "general"),
        ("insider threat", "general"),
        ("cryptocurrency fraud", "general"),
        ("dark web", "general"),
        ("threat actor", "threat_actor"),
        ("exploitation", "vulnerability"),
        ("malware", "malware"),
    ]
    for term, category in keywords:
        try:
            conn.execute(
                "INSERT OR IGNORE INTO keywords (term, category) VALUES (?, ?)",
                (term, category),
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()
    print("Default keywords seeded.")


if __name__ == "__main__":
    init_db()
    seed_default_sources()
    seed_default_keywords()
    print("Setup complete.")
