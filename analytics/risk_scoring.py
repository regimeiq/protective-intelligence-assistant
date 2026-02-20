"""
Risk Scoring Engine for OSINT Threat Monitor.

Formula: risk_score = (keyword_weight * frequency_factor * source_credibility * 20) + recency_bonus
Clamped to 0-100 range.

Severity derivation:
  90-100 = critical
  70-89  = high
  40-69  = medium
  0-39   = low
"""

import sqlite3
from datetime import datetime, timedelta


def compute_risk_score(keyword_weight, source_credibility, frequency_factor, recency_hours):
    """
    Compute a 0-100 risk score and derive severity.

    Args:
        keyword_weight: Weight of the matched keyword (0.1-5.0)
        source_credibility: Credibility of the source (0.0-1.0)
        frequency_factor: Spike multiplier (1.0 = normal, >1.0 = spiking)
        recency_hours: Hours since the alert was created

    Returns:
        (risk_score, severity) tuple
    """
    recency_factor = max(0.1, 1.0 - (recency_hours / 168.0))  # decays over 7 days
    raw_score = (keyword_weight * frequency_factor * source_credibility * 20.0) + (recency_factor * 10.0)
    risk_score = round(min(100.0, max(0.0, raw_score)), 1)
    severity = score_to_severity(risk_score)
    return risk_score, severity


def score_to_severity(score):
    """Map numeric score to severity label."""
    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high"
    elif score >= 40:
        return "medium"
    return "low"


def get_keyword_weight(conn, keyword_id):
    """Fetch keyword weight from database, defaulting to 1.0."""
    row = conn.execute(
        "SELECT weight FROM keywords WHERE id = ?", (keyword_id,)
    ).fetchone()
    return row["weight"] if row and row["weight"] else 1.0


def get_source_credibility(conn, source_id):
    """Fetch source credibility from database, defaulting to 0.5."""
    row = conn.execute(
        "SELECT credibility_score FROM sources WHERE id = ?", (source_id,)
    ).fetchone()
    return row["credibility_score"] if row and row["credibility_score"] else 0.5


def get_frequency_factor(conn, keyword_id):
    """
    Compare today's keyword match count to 7-day rolling average.
    Returns a multiplier >= 1.0 if spiking.
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")
    today_row = conn.execute(
        "SELECT count FROM keyword_frequency WHERE keyword_id = ? AND date = ?",
        (keyword_id, today),
    ).fetchone()
    today_count = today_row["count"] if today_row else 0

    seven_days_ago = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    avg_row = conn.execute(
        """SELECT AVG(count) as avg_count FROM keyword_frequency
        WHERE keyword_id = ? AND date >= ? AND date < ?""",
        (keyword_id, seven_days_ago, today),
    ).fetchone()
    avg_count = avg_row["avg_count"] if avg_row and avg_row["avg_count"] else 1.0

    if avg_count < 1.0:
        avg_count = 1.0

    factor = today_count / avg_count
    return max(1.0, round(factor, 2))


def increment_keyword_frequency(conn, keyword_id):
    """Increment today's count for a keyword. Called each time a keyword matches."""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    conn.execute(
        """INSERT INTO keyword_frequency (keyword_id, date, count)
        VALUES (?, ?, 1)
        ON CONFLICT(keyword_id, date)
        DO UPDATE SET count = count + 1""",
        (keyword_id, today),
    )


def score_alert(conn, alert_id, keyword_id, source_id, created_at=None):
    """
    Full scoring pipeline for a single alert.
    Computes score, updates alert, and stores audit trail in alert_scores.
    Returns the final risk score.
    """
    keyword_weight = get_keyword_weight(conn, keyword_id)
    source_credibility = get_source_credibility(conn, source_id)
    frequency_factor = get_frequency_factor(conn, keyword_id)

    if created_at:
        try:
            created_dt = datetime.strptime(str(created_at), "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            created_dt = datetime.utcnow()
    else:
        created_dt = datetime.utcnow()

    recency_hours = (datetime.utcnow() - created_dt).total_seconds() / 3600.0
    recency_factor = max(0.1, 1.0 - (recency_hours / 168.0))

    risk_score, severity = compute_risk_score(
        keyword_weight, source_credibility, frequency_factor, recency_hours
    )

    conn.execute(
        "UPDATE alerts SET risk_score = ?, severity = ? WHERE id = ?",
        (risk_score, severity, alert_id),
    )
    conn.execute(
        """INSERT INTO alert_scores
        (alert_id, keyword_weight, source_credibility, frequency_factor, recency_factor, final_score)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (alert_id, keyword_weight, source_credibility, frequency_factor, recency_factor, risk_score),
    )
    return risk_score


def rescore_all_alerts(conn):
    """
    Re-score all unreviewed alerts. Useful for periodic recalculation
    as recency and frequency factors change over time.
    Returns count of alerts rescored.
    """
    alerts = conn.execute(
        """SELECT a.id, a.keyword_id, a.source_id, a.created_at
        FROM alerts a WHERE a.reviewed = 0"""
    ).fetchall()
    count = 0
    for alert in alerts:
        score_alert(
            conn, alert["id"], alert["keyword_id"],
            alert["source_id"], alert["created_at"]
        )
        count += 1
    conn.commit()
    return count
