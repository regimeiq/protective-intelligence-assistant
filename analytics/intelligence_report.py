"""
Intelligence Report Generator.
Produces structured analytical summaries from alert data.
Uses aggregation, ranking, and rule-based templates.
"""

import json
from datetime import datetime, timedelta

from analytics.spike_detection import detect_spikes
from database.init_db import get_connection


def generate_daily_report(report_date=None):
    """
    Generate an intelligence report for a given date (default: today).

    Returns a dict with:
        - executive_summary: str
        - top_risks: list of top-scoring alerts
        - emerging_themes: list of spiking keywords
        - active_threat_actors: list of mentioned actors
        - escalation_recommendations: list of actionable items
        - stats: dict with counts
    """
    conn = get_connection()
    if report_date is None:
        report_date = datetime.utcnow().strftime("%Y-%m-%d")

    next_date = (datetime.strptime(report_date, "%Y-%m-%d") + timedelta(days=1)).strftime(
        "%Y-%m-%d"
    )

    # --- Top risks: highest scored unique alerts from the period ---
    top_alerts = conn.execute(
        """SELECT a.id, a.title, a.risk_score, a.severity, a.matched_term,
           s.name as source_name, k.term as keyword, k.category
        FROM alerts a
        LEFT JOIN sources s ON a.source_id = s.id
        LEFT JOIN keywords k ON a.keyword_id = k.id
        WHERE a.created_at >= ? AND a.created_at < ?
        AND a.duplicate_of IS NULL
        ORDER BY a.risk_score DESC
        LIMIT 10""",
        (report_date, next_date),
    ).fetchall()

    # --- Counts by severity (unique alerts only) ---
    severity_counts = conn.execute(
        """SELECT severity, COUNT(*) as count FROM alerts
        WHERE created_at >= ? AND created_at < ?
        AND duplicate_of IS NULL
        GROUP BY severity""",
        (report_date, next_date),
    ).fetchall()
    severity_map = {row["severity"]: row["count"] for row in severity_counts}
    total = sum(severity_map.values())

    # --- Emerging themes (spiking keywords) ---
    spikes = detect_spikes(threshold=1.5, as_of_date=report_date)

    # --- Most mentioned keywords (unique alerts only) ---
    top_keywords = conn.execute(
        """SELECT k.term, k.category, COUNT(*) as mention_count
        FROM alerts a
        JOIN keywords k ON a.keyword_id = k.id
        WHERE a.created_at >= ? AND a.created_at < ?
        AND a.duplicate_of IS NULL
        GROUP BY k.id
        ORDER BY mention_count DESC
        LIMIT 5""",
        (report_date, next_date),
    ).fetchall()

    # --- Threat actor mentions (unique alerts only) ---
    actor_keywords = conn.execute(
        """SELECT k.term, COUNT(*) as count FROM alerts a
        JOIN keywords k ON a.keyword_id = k.id
        WHERE k.category = 'threat_actor'
        AND a.created_at >= ? AND a.created_at < ?
        AND a.duplicate_of IS NULL
        GROUP BY k.term ORDER BY count DESC""",
        (report_date, next_date),
    ).fetchall()

    # --- Cross-reference with threat_actors table ---
    active_actors = []
    for actor_kw in actor_keywords:
        matches = conn.execute(
            """SELECT name, aliases FROM threat_actors
            WHERE LOWER(name) LIKE ? OR LOWER(aliases) LIKE ?""",
            (f"%{actor_kw['term'].lower()}%", f"%{actor_kw['term'].lower()}%"),
        ).fetchall()
        active_actors.append(
            {
                "keyword": actor_kw["term"],
                "mentions": actor_kw["count"],
                "known_actors": [{"name": m["name"], "aliases": m["aliases"]} for m in matches],
            }
        )

    # --- Build executive summary ---
    critical_count = severity_map.get("critical", 0)
    high_count = severity_map.get("high", 0)
    executive_summary = _build_executive_summary(
        report_date,
        total,
        critical_count,
        high_count,
        [dict(a) for a in top_alerts[:3]],
        spikes[:3],
    )

    # --- Escalation recommendations ---
    escalations = _build_escalations([dict(a) for a in top_alerts], spikes, active_actors)

    report = {
        "report_date": report_date,
        "executive_summary": executive_summary,
        "top_risks": [dict(a) for a in top_alerts],
        "emerging_themes": spikes,
        "active_threat_actors": active_actors,
        "escalation_recommendations": escalations,
        "top_keywords": [dict(k) for k in top_keywords],
        "stats": {
            "total_alerts": total,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": severity_map.get("medium", 0),
            "low_count": severity_map.get("low", 0),
        },
    }

    # --- Persist to intelligence_reports table ---
    conn.execute(
        """INSERT INTO intelligence_reports
        (report_date, executive_summary, top_risks, emerging_themes,
         active_threat_actors, escalation_recommendations, total_alerts,
         critical_count, high_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(report_date) DO UPDATE SET
            executive_summary = excluded.executive_summary,
            top_risks = excluded.top_risks,
            emerging_themes = excluded.emerging_themes,
            active_threat_actors = excluded.active_threat_actors,
            escalation_recommendations = excluded.escalation_recommendations,
            total_alerts = excluded.total_alerts,
            critical_count = excluded.critical_count,
            high_count = excluded.high_count,
            generated_at = CURRENT_TIMESTAMP""",
        (
            report_date,
            executive_summary,
            json.dumps([dict(a) for a in top_alerts]),
            json.dumps(spikes),
            json.dumps(active_actors),
            json.dumps(escalations),
            total,
            critical_count,
            high_count,
        ),
    )
    conn.commit()
    conn.close()
    return report


def _build_executive_summary(report_date, total, critical, high, top_alerts, spikes):
    """Build a template-based executive summary string."""
    lines = []
    lines.append(f"Intelligence Summary for {report_date}:")
    lines.append(
        f"Monitoring detected {total} alert{'s' if total != 1 else ''}, including "
        f"{critical} critical and {high} high-priority item{'s' if high != 1 else ''}."
    )

    if critical > 0 and top_alerts:
        top_title = top_alerts[0].get("title", "Unknown")[:80]
        lines.append(
            f'Highest priority: "{top_title}" '
            f"(risk score: {top_alerts[0].get('risk_score', 0)})."
        )

    if spikes:
        spike_terms = ", ".join(s["term"] for s in spikes[:3])
        lines.append(f"Emerging activity detected for: {spike_terms}.")

    if critical == 0 and high == 0:
        lines.append("No items require immediate escalation at this time.")
    elif critical > 0:
        lines.append("Immediate review recommended for critical-severity items.")

    return " ".join(lines)


def _build_escalations(top_alerts, spikes, actors):
    """Build a list of escalation recommendations."""
    escalations = []

    # Critical alerts always escalate
    for alert in top_alerts:
        if alert.get("severity") == "critical":
            escalations.append(
                {
                    "priority": "IMMEDIATE",
                    "type": "critical_alert",
                    "title": alert.get("title", "")[:100],
                    "risk_score": alert.get("risk_score", 0),
                    "action": "Review and assess impact. Brief stakeholders within 1 hour.",
                }
            )

    # High-ratio spikes escalate
    for spike in spikes:
        if spike["spike_ratio"] >= 3.0:
            escalations.append(
                {
                    "priority": "HIGH",
                    "type": "frequency_spike",
                    "term": spike["term"],
                    "spike_ratio": spike["spike_ratio"],
                    "action": (
                        f"'{spike['term']}' activity is {spike['spike_ratio']}x above baseline. "
                        "Investigate root cause."
                    ),
                }
            )

    # Known threat actor activity escalates
    for actor in actors:
        if actor["known_actors"] and actor["mentions"] >= 2:
            actor_names = ", ".join(a["name"] for a in actor["known_actors"])
            escalations.append(
                {
                    "priority": "HIGH",
                    "type": "threat_actor_activity",
                    "actors": actor_names,
                    "mentions": actor["mentions"],
                    "action": (
                        f"Increased chatter referencing {actor_names}. "
                        "Cross-reference with IOC feeds."
                    ),
                }
            )

    priority_order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2}
    escalations.sort(key=lambda x: priority_order.get(x["priority"], 3))
    return escalations
