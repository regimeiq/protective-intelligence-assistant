"""
Spike detection for keyword frequency trends.
Identifies keywords with unusual activity levels using Z-score analysis.
"""

from datetime import date, datetime, timedelta

from database.init_db import get_connection


def _resolve_as_of_date(as_of_date=None):
    """Resolve optional date input to a datetime object."""
    if as_of_date is None:
        return datetime.utcnow()
    if isinstance(as_of_date, datetime):
        return as_of_date
    if isinstance(as_of_date, date):
        return datetime.combine(as_of_date, datetime.min.time())
    if isinstance(as_of_date, str):
        return datetime.strptime(as_of_date, "%Y-%m-%d")
    raise TypeError("as_of_date must be None, date, datetime, or YYYY-MM-DD string")


def detect_spikes(threshold=2.0, as_of_date=None):
    """
    Find keywords whose today count exceeds their 7-day average
    by the given threshold multiplier. Includes Z-score for statistical context.

    Args:
        threshold: Minimum ratio of today/average to qualify as a spike (default 2.0)
        as_of_date: Date anchor for trend comparison (None = today UTC)

    Returns:
        List of dicts with keyword info, spike details, and z-score,
        sorted by spike_ratio descending.
    """
    conn = get_connection()
    as_of_dt = _resolve_as_of_date(as_of_date)
    today = as_of_dt.strftime("%Y-%m-%d")
    seven_days_ago = (as_of_dt - timedelta(days=7)).strftime("%Y-%m-%d")

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

    spikes = []
    for row in rows:
        avg = row["avg_count"] if row["avg_count"] and row["avg_count"] > 0 else 1.0
        ratio = row["today_count"] / avg
        if ratio >= threshold:
            # Compute z-score for statistical context
            counts_rows = conn.execute(
                """SELECT count FROM keyword_frequency
                WHERE keyword_id = ? AND date >= ? AND date < ?""",
                (row["keyword_id"], seven_days_ago, today),
            ).fetchall()
            counts = [r["count"] for r in counts_rows]
            z_score = 0.0
            if len(counts) >= 3:
                mean = sum(counts) / len(counts)
                variance = sum((c - mean) ** 2 for c in counts) / len(counts)
                std_dev = max(variance**0.5, 0.5)
                z_score = round((row["today_count"] - mean) / std_dev, 2)

            spikes.append(
                {
                    "keyword_id": row["keyword_id"],
                    "term": row["term"],
                    "category": row["category"],
                    "today_count": row["today_count"],
                    "avg_7d": round(avg, 1),
                    "spike_ratio": round(ratio, 1),
                    "z_score": z_score,
                }
            )

    conn.close()
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
