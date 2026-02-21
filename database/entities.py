def upsert_entity(conn, entity_type, value):
    """Insert entity if needed and return ID."""
    row = conn.execute(
        "SELECT id FROM entities WHERE type = ? AND value = ?",
        (entity_type, value),
    ).fetchone()
    if row:
        return row["id"]

    conn.execute(
        "INSERT INTO entities (type, value) VALUES (?, ?)",
        (entity_type, value),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def link_alert_entity(alert_id, entity_id, confidence, extractor, context, conn):
    """Link an entity to an alert in flat alert_entities schema."""
    row = conn.execute(
        "SELECT type, value FROM entities WHERE id = ?",
        (entity_id,),
    ).fetchone()
    if not row:
        return
    conn.execute(
        """INSERT INTO alert_entities
        (alert_id, entity_type, entity_value, created_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(alert_id, entity_type, entity_value) DO NOTHING""",
        (
            alert_id,
            row["type"],
            row["value"],
        ),
    )


def upsert_ioc(conn, ioc_type, value):
    """Insert IOC if needed and return ID."""
    row = conn.execute(
        "SELECT id FROM iocs WHERE type = ? AND value = ?",
        (ioc_type, value),
    ).fetchone()
    if row:
        return row["id"]

    conn.execute(
        "INSERT INTO iocs (type, value) VALUES (?, ?)",
        (ioc_type, value),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def link_alert_ioc(alert_id, ioc_id, extractor, context, conn):
    """Link an IOC to an alert with extractor metadata."""
    conn.execute(
        """INSERT INTO alert_iocs
        (alert_id, ioc_id, extractor, context)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(alert_id, ioc_id) DO UPDATE SET
            extractor = excluded.extractor,
            context = COALESCE(excluded.context, alert_iocs.context)""",
        (
            alert_id,
            ioc_id,
            extractor,
            context[:240] if context else None,
        ),
    )
