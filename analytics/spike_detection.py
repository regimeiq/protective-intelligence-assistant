"""
Spike detection for keyword frequency trends.
Identifies keywords with unusual activity levels.
"""

from datetime import datetime, timedelta
from database.init_db import get_connection


def detect_spikes(threshold=2.0):
    """
    Find keywords whose today count exceeds their 7-day average
    by the given threshold multiplier.

    Args:
        threshold: Minimum ratio of today/average to qualify as a spike (default 2.0)

    Returns:
        List of dicts with keyword info and spike details, sorted by spike_ratio descending.
    """
    conn = get_connection()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    seven_days_ago = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")

    rows = conn.execute(
        """SELECT kf.keyword_id, k.term, k.category, kf.count as today_count,
           (SELECT AVG(kf2.count) FROM keyword_frequency kf2
            WHERE kf2.keyword_id = kf.keyword_id
            AND kf2.date >= ? AND kf2.date < ?) as avg_count
        FROM keyword_frequency kf
        JOIN keywords k ON kf.keyword_id = k.id
        WHERE kf.date = ?""",
        (seven_days_ago, today, today),
    ).fetchall()
    conn.close()

    spikes = []
    for row in rows:
        avg = row["avg_count"] if row["avg_count"] and row["avg_count"] > 0 else 1.0
        ratio = row["today_count"] / avg
        if ratio >= threshold:
            spikes.append({
                "keyword_id": row["keyword_id"],
                "term": row["term"],
                "category": row["category"],
                "today_count": row["today_count"],
                "avg_7d": round(avg, 1),
                "spike_ratio": round(ratio, 1),
            })
    spikes.sort(key=lambda x: x["spike_ratio"], reverse=True)
    return spikes


def get_keyword_trend(keyword_id, days=14):
    """
    Get daily counts for a keyword over the last N days.
    Used for trend sparklines in the dashboard.
    """
    conn = get_connection()
    start_date = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = conn.execute(
        """SELECT date, count FROM keyword_frequency
        WHERE keyword_id = ? AND date >= ?
        ORDER BY date ASC""",
        (keyword_id, start_date),
    ).fetchall()
    conn.close()
    return [{"date": row["date"], "count": row["count"]} for row in rows]
