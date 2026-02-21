import os
import sqlite3

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


def migrate_schema():
    """Add new columns to existing tables. Safe to run multiple times."""
    conn = get_connection()
    migrations = [
        "ALTER TABLE keywords ADD COLUMN weight REAL DEFAULT 1.0",
        "ALTER TABLE sources ADD COLUMN credibility_score REAL DEFAULT 0.5",
        "ALTER TABLE sources ADD COLUMN true_positives INTEGER DEFAULT 0",
        "ALTER TABLE sources ADD COLUMN false_positives INTEGER DEFAULT 0",
        "ALTER TABLE sources ADD COLUMN bayesian_alpha REAL DEFAULT 2.0",
        "ALTER TABLE sources ADD COLUMN bayesian_beta REAL DEFAULT 2.0",
        "ALTER TABLE alerts ADD COLUMN risk_score REAL DEFAULT 0.0",
        "ALTER TABLE alerts ADD COLUMN content_hash TEXT",
        "ALTER TABLE alerts ADD COLUMN duplicate_of INTEGER",
        "ALTER TABLE alerts ADD COLUMN published_at TIMESTAMP",
        "ALTER TABLE alert_scores ADD COLUMN z_score REAL DEFAULT 0.0",
        "ALTER TABLE threat_actors ADD COLUMN alert_count INTEGER DEFAULT 0",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass  # Column already exists

    # Indexes for performance
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_alerts_content_hash ON alerts(content_hash)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_duplicate_of ON alerts(duplicate_of)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created_date ON alerts(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_published_date ON alerts(published_at)",
        "CREATE INDEX IF NOT EXISTS idx_keyword_frequency_kw_date ON keyword_frequency(keyword_id, date)",
    ]
    for sql in indexes:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass

    conn.execute("UPDATE keywords SET weight = 1.0 WHERE weight IS NULL")
    conn.execute("UPDATE sources SET credibility_score = 0.5 WHERE credibility_score IS NULL")
    conn.execute("UPDATE alerts SET risk_score = 0.0 WHERE risk_score IS NULL")
    conn.execute("UPDATE alerts SET published_at = created_at WHERE published_at IS NULL")
    conn.commit()
    conn.close()


def seed_default_sources():
    conn = get_connection()
    sources = [
        ("CISA Alerts", "https://www.cisa.gov/news.xml", "rss", 1.0),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/", "rss", 0.85),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "rss", 0.8),
        ("r/cybersecurity", "https://www.reddit.com/r/cybersecurity/.rss", "reddit", 0.4),
        ("r/netsec", "https://www.reddit.com/r/netsec/.rss", "reddit", 0.5),
        ("r/threatintel", "https://www.reddit.com/r/threatintel/.rss", "reddit", 0.5),
    ]
    for name, url, source_type, credibility in sources:
        existing = conn.execute("SELECT id FROM sources WHERE url = ?", (url,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE sources SET credibility_score = ? WHERE id = ?",
                (credibility, existing["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO sources (name, url, source_type, credibility_score) VALUES (?, ?, ?, ?)",
                (name, url, source_type, credibility),
            )
    conn.commit()
    conn.close()
    print("Default sources seeded.")


def seed_default_keywords():
    conn = get_connection()
    keywords = [
        ("ransomware", "malware", 4.5),
        ("data breach", "incident", 3.5),
        ("credential leak", "incident", 3.0),
        ("phishing", "tactics", 2.0),
        ("zero day", "vulnerability", 5.0),
        ("APT", "threat_actor", 4.5),
        ("supply chain attack", "tactics", 4.0),
        ("CVE", "vulnerability", 2.5),
        ("DDoS", "tactics", 2.5),
        ("insider threat", "general", 3.5),
        ("cryptocurrency fraud", "financial", 2.0),
        ("dark web", "general", 1.5),
        ("threat actor", "threat_actor", 3.5),
        ("exploitation", "vulnerability", 3.5),
        ("malware", "malware", 4.0),
        ("nation-state", "threat_actor", 4.5),
        ("remote code execution", "vulnerability", 4.5),
        ("privilege escalation", "vulnerability", 3.5),
    ]
    for term, category, weight in keywords:
        existing = conn.execute("SELECT id FROM keywords WHERE term = ?", (term,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE keywords SET category = ?, weight = ? WHERE id = ?",
                (category, weight, existing["id"]),
            )
        else:
            try:
                conn.execute(
                    "INSERT INTO keywords (term, category, weight) VALUES (?, ?, ?)",
                    (term, category, weight),
                )
            except sqlite3.IntegrityError:
                pass
    conn.commit()
    conn.close()
    print("Default keywords seeded.")


def seed_threat_actors():
    conn = get_connection()
    actors = [
        ("APT28", "Fancy Bear, Sofacy, Sednit", "Russian state-sponsored cyber espionage group"),
        ("APT29", "Cozy Bear, The Dukes, Nobelium", "Russian state-sponsored, SolarWinds campaign"),
        ("Lazarus Group", "Hidden Cobra, Zinc, Diamond Sleet", "North Korean state-sponsored"),
        (
            "APT41",
            "Winnti, Barium, Wicked Panda",
            "Chinese state-sponsored dual espionage/financial",
        ),
        ("Conti", "Wizard Spider", "Russian-speaking ransomware syndicate"),
        ("LockBit", "LockBit 3.0, LockBit Black", "Ransomware-as-a-Service operation"),
        ("BlackCat", "ALPHV, Noberus", "Rust-based ransomware group"),
        ("Sandworm", "Voodoo Bear, IRIDIUM", "Russian GRU Unit 74455"),
        ("Scattered Spider", "UNC3944, 0ktapus", "Social engineering focused group"),
        ("Cl0p", "TA505, FIN11", "Ransomware group, MOVEit campaigns"),
    ]
    for name, aliases, description in actors:
        existing = conn.execute("SELECT id FROM threat_actors WHERE name = ?", (name,)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO threat_actors (name, aliases, description) VALUES (?, ?, ?)",
                (name, aliases, description),
            )
    conn.commit()
    conn.close()
    print("Threat actors seeded.")


if __name__ == "__main__":
    init_db()
    migrate_schema()
    seed_default_sources()
    seed_default_keywords()
    seed_threat_actors()
    print("Setup complete.")
