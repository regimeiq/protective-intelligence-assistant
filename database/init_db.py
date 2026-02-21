import os
import sqlite3
from urllib.parse import quote_plus, urlencode

import yaml

DB_PATH = os.path.join(os.path.dirname(__file__), "osint_monitor.db")
WATCHLIST_CONFIG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "watchlist.yaml")
)

SOURCE_DEFAULT_CREDIBILITY = {
    "rss": 0.8,
    "reddit": 0.5,
    "pastebin": 0.2,
}

GDELT_DOC_API_BASE_URL = "https://api.gdeltproject.org/api/v2/doc/doc"
DEFAULT_GDELT_PI_EP_QUERY = (
    '("threat to CEO" OR swatting OR doxxing OR "death threat" OR kidnapping OR "bomb threat") '
    'AND (executive OR CEO OR "corporate headquarters" OR "company name")'
)

KEYWORD_CATEGORY_ALIASES = {
    "threat_actors": "threat_actor",
    "threat_actor": "threat_actor",
    "vulnerabilities": "vulnerability",
    "vulnerability": "vulnerability",
    "person_of_interest": "poi",
    "people_of_interest": "poi",
}

KEYWORD_DEFAULT_WEIGHTS_BY_CATEGORY = {
    "poi": 4.0,
}


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


def _get_table_columns(conn, table_name):
    return [row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()]


def _create_alert_entities_v2(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS alert_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            entity_value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(alert_id, entity_type, entity_value),
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
        )"""
    )


def _migrate_alert_entities_table(conn):
    """
    Ensure alert_entities matches flat IOC-entity schema.
    Migrates legacy normalized schema if present.
    """
    existing = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'alert_entities'"
    ).fetchone()
    if not existing:
        _create_alert_entities_v2(conn)
        return

    cols = set(_get_table_columns(conn, "alert_entities"))
    expected = {"id", "alert_id", "entity_type", "entity_value", "created_at"}
    if expected.issubset(cols):
        return

    conn.execute("ALTER TABLE alert_entities RENAME TO alert_entities_legacy")
    _create_alert_entities_v2(conn)

    legacy_cols = set(_get_table_columns(conn, "alert_entities_legacy"))
    if {"alert_id", "entity_type", "entity_value"}.issubset(legacy_cols):
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities
            (alert_id, entity_type, entity_value, created_at)
            SELECT alert_id, entity_type, entity_value, COALESCE(created_at, CURRENT_TIMESTAMP)
            FROM alert_entities_legacy"""
        )
        return

    if {"alert_id", "entity_id"}.issubset(legacy_cols):
        conn.execute(
            """INSERT OR IGNORE INTO alert_entities
            (alert_id, entity_type, entity_value, created_at)
            SELECT ae.alert_id, e.type, e.value, CURRENT_TIMESTAMP
            FROM alert_entities_legacy ae
            JOIN entities e ON e.id = ae.entity_id"""
        )


def migrate_schema():
    """Add new columns to existing tables. Safe to run multiple times."""
    conn = get_connection()
    migrations = [
        "ALTER TABLE keywords ADD COLUMN weight REAL DEFAULT 1.0",
        "ALTER TABLE keywords ADD COLUMN weight_sigma REAL",
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
        "ALTER TABLE alert_scores ADD COLUMN mc_mean REAL",
        "ALTER TABLE alert_scores ADD COLUMN mc_p05 REAL",
        "ALTER TABLE alert_scores ADD COLUMN mc_p50 REAL",
        "ALTER TABLE alert_scores ADD COLUMN mc_p95 REAL",
        "ALTER TABLE alert_scores ADD COLUMN mc_std REAL",
        "ALTER TABLE threat_actors ADD COLUMN alert_count INTEGER DEFAULT 0",
        "ALTER TABLE intelligence_reports ADD COLUMN top_entities TEXT",
        "ALTER TABLE intelligence_reports ADD COLUMN new_cves TEXT",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass  # Column already exists

    _migrate_alert_entities_table(conn)

    # Indexes for performance
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_alerts_content_hash ON alerts(content_hash)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_duplicate_of ON alerts(duplicate_of)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created_date ON alerts(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_published_date ON alerts(published_at)",
        "CREATE INDEX IF NOT EXISTS idx_keyword_frequency_kw_date ON keyword_frequency(keyword_id, date)",
        "CREATE INDEX IF NOT EXISTS idx_entities_type_value ON entities(type, value)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value)",
        "CREATE INDEX IF NOT EXISTS idx_alert_entities_alert ON alert_entities(alert_id)",
        "CREATE INDEX IF NOT EXISTS idx_alert_entities_type_value ON alert_entities(entity_type, entity_value)",
        "CREATE INDEX IF NOT EXISTS idx_alert_iocs_alert ON alert_iocs(alert_id)",
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


def _normalize_keyword_category(raw_category):
    normalized = (raw_category or "general").strip().lower().replace(" ", "_")
    return KEYWORD_CATEGORY_ALIASES.get(normalized, normalized or "general")


def _default_keyword_weight(category):
    return KEYWORD_DEFAULT_WEIGHTS_BY_CATEGORY.get(category, 1.0)


def build_gdelt_rss_url(query, maxrecords=100, timespan="24h", sort="datedesc"):
    """Build a URL-encoded GDELT DOC API RSS feed URL."""
    query_text = str(query or "").strip()
    if not query_text:
        raise ValueError("query must not be empty")
    safe_maxrecords = max(1, min(250, int(maxrecords)))
    params = {
        "query": query_text,
        "mode": "artlist",
        "format": "rss",
        "maxrecords": safe_maxrecords,
        "timespan": str(timespan),
        "sort": str(sort),
    }
    return f"{GDELT_DOC_API_BASE_URL}?{urlencode(params, quote_via=quote_plus)}"


def load_watchlist_yaml(config_path=None):
    """
    Load watchlist config from YAML.

    Expected structure:
      sources:
        rss/reddit/pastebin: [{name, url}]
      keywords:
        <category>: [term, ...] or [{term, weight}, ...]
    """
    watchlist_path = config_path or WATCHLIST_CONFIG_PATH
    if not os.path.exists(watchlist_path):
        return None

    try:
        with open(watchlist_path, "r", encoding="utf-8") as f:
            payload = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return None

    if not isinstance(payload, dict):
        return None

    parsed = {"path": watchlist_path, "sources": [], "keywords": []}

    source_block = payload.get("sources", {})
    if isinstance(source_block, dict):
        for source_type in ("rss", "reddit", "pastebin"):
            entries = source_block.get(source_type, [])
            if not isinstance(entries, list):
                continue
            default_credibility = SOURCE_DEFAULT_CREDIBILITY.get(source_type, 0.5)
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", "")).strip()
                raw_url = entry.get("url")
                gdelt_query = str(entry.get("gdelt_query", "")).strip()
                url = str(raw_url).strip() if raw_url else ""
                if not url and gdelt_query:
                    try:
                        url = build_gdelt_rss_url(gdelt_query)
                    except (TypeError, ValueError):
                        url = ""
                if not name or not url:
                    continue
                cred_raw = entry.get("credibility_score", entry.get("credibility"))
                try:
                    credibility = float(cred_raw) if cred_raw is not None else default_credibility
                except (TypeError, ValueError):
                    credibility = default_credibility
                credibility = max(0.0, min(1.0, credibility))
                parsed["sources"].append(
                    {
                        "name": name,
                        "url": url,
                        "source_type": source_type,
                        "credibility_score": credibility,
                    }
                )

    keyword_block = payload.get("keywords", {})
    if isinstance(keyword_block, dict):
        seen_terms = set()
        for raw_category, terms in keyword_block.items():
            if not isinstance(terms, list):
                continue
            category = _normalize_keyword_category(raw_category)
            default_weight = _default_keyword_weight(category)
            for term_item in terms:
                weight = default_weight
                if isinstance(term_item, dict):
                    term_text = str(term_item.get("term", "")).strip()
                    raw_weight = term_item.get("weight")
                    if raw_weight is not None:
                        try:
                            weight = float(raw_weight)
                        except (TypeError, ValueError):
                            weight = default_weight
                else:
                    term_text = str(term_item).strip()

                if not term_text:
                    continue
                dedupe_key = term_text.lower()
                if dedupe_key in seen_terms:
                    continue
                seen_terms.add(dedupe_key)
                weight = max(0.1, min(5.0, weight))
                parsed["keywords"].append(
                    {"term": term_text, "category": category, "weight": weight}
                )

    return parsed


def seed_default_sources():
    conn = get_connection()
    watchlist = load_watchlist_yaml()
    if watchlist and watchlist["sources"]:
        sources = [
            (
                source["name"],
                source["url"],
                source["source_type"],
                source["credibility_score"],
            )
            for source in watchlist["sources"]
        ]
        seed_origin = f"config ({watchlist['path']})"
    else:
        sources = [
            ("CISA Alerts", "https://www.cisa.gov/news.xml", "rss", 1.0),
            ("Krebs on Security", "https://krebsonsecurity.com/feed/", "rss", 0.85),
            ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "rss", 0.8),
            (
                "GDELT PI/EP Watch",
                build_gdelt_rss_url(DEFAULT_GDELT_PI_EP_QUERY),
                "rss",
                0.6,
            ),
            ("r/cybersecurity", "https://www.reddit.com/r/cybersecurity/.rss", "reddit", 0.4),
            ("r/netsec", "https://www.reddit.com/r/netsec/.rss", "reddit", 0.5),
            ("r/threatintel", "https://www.reddit.com/r/threatintel/.rss", "reddit", 0.5),
        ]
        seed_origin = "hardcoded defaults"

    for name, url, source_type, credibility in sources:
        existing = conn.execute("SELECT id FROM sources WHERE url = ?", (url,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE sources SET name = ?, source_type = ?, credibility_score = ? WHERE id = ?",
                (name, source_type, credibility, existing["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO sources (name, url, source_type, credibility_score) VALUES (?, ?, ?, ?)",
                (name, url, source_type, credibility),
            )
    conn.commit()
    conn.close()
    print(f"Default sources seeded from {seed_origin}.")


def seed_default_keywords():
    conn = get_connection()
    watchlist = load_watchlist_yaml()
    if watchlist and watchlist["keywords"]:
        keywords = [
            (keyword["term"], keyword["category"], keyword["weight"])
            for keyword in watchlist["keywords"]
        ]
        seed_origin = f"config ({watchlist['path']})"
    else:
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
        seed_origin = "hardcoded defaults"

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
    print(f"Default keywords seeded from {seed_origin}.")


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
