"""Operational risk scoring for Protective Intelligence workflows."""

from datetime import timedelta

from analytics.risk_scoring import score_to_severity
from analytics.utils import parse_timestamp, utcnow

EP_CATEGORY_BOOST = {
    "protective_intel": 10.0,
    "insider_workplace": 8.0,
    "protest_disruption": 7.0,
    "travel_risk": 6.0,
    "poi": 9.0,
    "ioc": 1.5,
    "cti_optional": 2.0,
    "threat_actor": 2.5,
    "malware": 2.5,
    "vulnerability": 2.5,
}


def _compute_proximity_factor(conn, alert_id):
    rows = conn.execute(
        """SELECT distance_miles, within_radius
        FROM alert_proximity
        WHERE alert_id = ?""",
        (alert_id,),
    ).fetchall()
    if not rows:
        return 0.0
    if any(int(row["within_radius"] or 0) == 1 for row in rows):
        return 15.0
    min_distance = min(float(row["distance_miles"] or 9999) for row in rows)
    if min_distance <= 5:
        return 10.0
    if min_distance <= 15:
        return 6.0
    if min_distance <= 30:
        return 3.0
    return 0.0


def _compute_event_factor(conn, alert_id):
    rows = conn.execute(
        """SELECT ap.distance_miles
        FROM alert_proximity ap
        JOIN protected_locations pl ON pl.id = ap.protected_location_id
        JOIN events e ON e.lat IS NOT NULL AND e.lon IS NOT NULL
        WHERE ap.alert_id = ?
          AND datetime(e.start_dt) >= datetime('now')
          AND datetime(e.start_dt) <= datetime('now', '+7 days')""",
        (alert_id,),
    ).fetchall()
    if not rows:
        return 0.0
    min_distance = min(float(row["distance_miles"] or 9999) for row in rows)
    if min_distance <= 10:
        return 8.0
    if min_distance <= 25:
        return 4.0
    return 0.0


def _compute_poi_factor(conn, alert_id):
    count = conn.execute(
        "SELECT COUNT(*) AS c FROM poi_hits WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()["c"]
    if count <= 0:
        return 0.0
    return min(12.0, 6.0 + (count * 2.0))


def compute_operational_score(conn, alert_id):
    """Compute ORS for an alert and persist factor breakdown to alert_scores."""
    row = conn.execute(
        """SELECT a.id, a.keyword_id,
                  k.category,
                  s.keyword_weight, s.source_credibility,
                  s.frequency_factor, s.recency_factor
        FROM alerts a
        JOIN alert_scores s ON s.alert_id = a.id
        JOIN keywords k ON k.id = a.keyword_id
        WHERE a.id = ?
        ORDER BY s.computed_at DESC
        LIMIT 1""",
        (alert_id,),
    ).fetchone()
    if not row:
        return None

    category = (row["category"] or "").strip().lower()
    category_factor = EP_CATEGORY_BOOST.get(category, 0.0)
    proximity_factor = _compute_proximity_factor(conn, alert_id)
    event_factor = _compute_event_factor(conn, alert_id)
    poi_factor = _compute_poi_factor(conn, alert_id)

    base_score = (
        float(row["keyword_weight"] or 1.0)
        * float(row["frequency_factor"] or 1.0)
        * float(row["source_credibility"] or 0.5)
        * 20.0
    ) + (float(row["recency_factor"] or 0.1) * 10.0)

    ors_score = max(0.0, min(100.0, base_score + category_factor + proximity_factor + event_factor + poi_factor))
    ors_score = round(ors_score, 3)

    conn.execute(
        """UPDATE alert_scores
        SET category_factor = ?,
            proximity_factor = ?,
            event_factor = ?,
            poi_factor = ?,
            final_score = ?
        WHERE id = (
            SELECT id FROM alert_scores
            WHERE alert_id = ?
            ORDER BY computed_at DESC
            LIMIT 1
        )""",
        (category_factor, proximity_factor, event_factor, poi_factor, ors_score, alert_id),
    )
    conn.execute(
        "UPDATE alerts SET risk_score = ?, ors_score = ?, severity = ? WHERE id = ?",
        (ors_score, ors_score, score_to_severity(ors_score), alert_id),
    )
    return {
        "alert_id": alert_id,
        "ors_score": ors_score,
        "base_score": round(base_score, 3),
        "category_factor": category_factor,
        "proximity_factor": proximity_factor,
        "event_factor": event_factor,
        "poi_factor": poi_factor,
    }


def compute_event_risk_snapshots(conn):
    upcoming = conn.execute(
        """SELECT id FROM events
        WHERE datetime(start_dt) >= datetime('now')
          AND datetime(start_dt) <= datetime('now', '+7 days')"""
    ).fetchall()

    for event in upcoming:
        rows = conn.execute(
            """SELECT a.ors_score
            FROM alerts a
            JOIN alert_locations al ON al.alert_id = a.id
            JOIN events e ON e.id = ?
            WHERE a.duplicate_of IS NULL
              AND al.lat IS NOT NULL AND al.lon IS NOT NULL
              AND datetime(COALESCE(a.published_at, a.created_at)) >= datetime('now', '-7 days')""",
            (event["id"],),
        ).fetchall()
        scores = [float(row["ors_score"] or 0.0) for row in rows if row["ors_score"] is not None]
        if not scores:
            continue
        scores.sort()
        ors_mean = sum(scores) / len(scores)
        p95_idx = int(max(0, min(len(scores) - 1, round((len(scores) - 1) * 0.95))))
        ors_p95 = scores[p95_idx]
        conn.execute(
            """INSERT INTO event_risk_snapshots
            (event_id, computed_at, ors_mean, ors_p95, top_drivers_json)
            VALUES (?, ?, ?, ?, ?)""",
            (
                event["id"],
                utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                round(ors_mean, 3),
                round(ors_p95, 3),
                "[]",
            ),
        )
