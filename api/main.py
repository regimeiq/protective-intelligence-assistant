import json
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.init_db import (
    get_connection, init_db, migrate_schema,
    seed_default_sources, seed_default_keywords, seed_threat_actors,
)

app = FastAPI(
    title="OSINT Threat Monitor API",
    description="Protective Intelligence REST API for threat prioritization, risk scoring, and analytical reporting",
    version="2.0.0",
)


# --- Models ---

class KeywordCreate(BaseModel):
    term: str
    category: str = "general"
    weight: float = 1.0


class AlertResponse(BaseModel):
    id: int
    title: str
    content: Optional[str]
    url: Optional[str]
    risk_score: Optional[float] = None
    severity: str
    reviewed: int
    created_at: str
    source_name: Optional[str] = None
    matched_term: Optional[str] = None


# --- Startup ---

@app.on_event("startup")
def startup():
    init_db()
    migrate_schema()
    seed_default_sources()
    seed_default_keywords()
    seed_threat_actors()


@app.get("/")
def root():
    return {"status": "online", "service": "OSINT Threat Monitor", "version": "2.0.0"}


# --- ALERTS ---

@app.get("/alerts")
def get_alerts(
    severity: Optional[str] = None,
    reviewed: Optional[int] = None,
    min_score: Optional[float] = None,
    sort_by: str = Query(default="risk_score", pattern="^(risk_score|created_at)$"),
    limit: int = Query(default=50, le=500),
    offset: int = 0,
):
    conn = get_connection()
    query = """
        SELECT a.id, a.title, a.content, a.url, a.risk_score, a.severity,
               a.reviewed, a.created_at,
               s.name as source_name, k.term as matched_term
        FROM alerts a
        LEFT JOIN sources s ON a.source_id = s.id
        LEFT JOIN keywords k ON a.keyword_id = k.id
        WHERE 1=1
    """
    params = []

    if severity:
        query += " AND a.severity = ?"
        params.append(severity)
    if reviewed is not None:
        query += " AND a.reviewed = ?"
        params.append(reviewed)
    if min_score is not None:
        query += " AND a.risk_score >= ?"
        params.append(min_score)

    query += f" ORDER BY a.{sort_by} DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    alerts = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(a) for a in alerts]


@app.get("/alerts/summary")
def get_alerts_summary():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as count FROM alerts").fetchone()["count"]
    by_severity = conn.execute(
        "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
    ).fetchall()
    by_source = conn.execute(
        """SELECT s.name, COUNT(*) as count FROM alerts a
        JOIN sources s ON a.source_id = s.id
        GROUP BY s.name ORDER BY count DESC"""
    ).fetchall()
    top_keywords = conn.execute(
        """SELECT k.term, COUNT(*) as count FROM alerts a
        JOIN keywords k ON a.keyword_id = k.id
        GROUP BY k.term ORDER BY count DESC LIMIT 10"""
    ).fetchall()
    unreviewed = conn.execute(
        "SELECT COUNT(*) as count FROM alerts WHERE reviewed = 0"
    ).fetchone()["count"]
    avg_score_row = conn.execute(
        "SELECT AVG(risk_score) as avg FROM alerts WHERE reviewed = 0"
    ).fetchone()
    avg_risk_score = round(avg_score_row["avg"], 1) if avg_score_row["avg"] else 0.0

    # Count active spikes
    from analytics.spike_detection import detect_spikes
    active_spikes = len(detect_spikes(threshold=2.0))

    conn.close()
    return {
        "total_alerts": total,
        "unreviewed": unreviewed,
        "avg_risk_score": avg_risk_score,
        "active_spikes": active_spikes,
        "by_severity": {row["severity"]: row["count"] for row in by_severity},
        "by_source": {row["name"]: row["count"] for row in by_source},
        "top_keywords": {row["term"]: row["count"] for row in top_keywords},
    }


@app.patch("/alerts/{alert_id}/review")
def mark_reviewed(alert_id: int):
    conn = get_connection()
    result = conn.execute(
        "UPDATE alerts SET reviewed = 1 WHERE id = ?", (alert_id,)
    )
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.commit()
    conn.close()
    return {"status": "reviewed", "alert_id": alert_id}


@app.get("/alerts/{alert_id}/score")
def get_alert_score(alert_id: int):
    """Get the score breakdown for a specific alert."""
    conn = get_connection()
    score = conn.execute(
        """SELECT * FROM alert_scores WHERE alert_id = ?
        ORDER BY computed_at DESC LIMIT 1""",
        (alert_id,),
    ).fetchone()
    if not score:
        conn.close()
        raise HTTPException(status_code=404, detail="Score not found for alert")
    conn.close()
    return dict(score)


@app.post("/alerts/rescore")
def trigger_rescore():
    """Re-score all unreviewed alerts with current weights and frequencies."""
    from analytics.risk_scoring import rescore_all_alerts
    conn = get_connection()
    count = rescore_all_alerts(conn)
    conn.close()
    return {"status": "complete", "alerts_rescored": count}


# --- INTELLIGENCE REPORTS ---

@app.get("/intelligence/daily")
def get_daily_report(date: Optional[str] = None):
    """Generate or retrieve the intelligence report for a given date."""
    from analytics.intelligence_report import generate_daily_report
    report = generate_daily_report(report_date=date)
    return report


@app.get("/intelligence/reports")
def list_reports(limit: int = Query(default=7, le=30)):
    """List recent intelligence reports."""
    conn = get_connection()
    reports = conn.execute(
        """SELECT id, report_date, total_alerts, critical_count, high_count, generated_at
        FROM intelligence_reports
        ORDER BY report_date DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in reports]


@app.get("/intelligence/reports/{report_date}")
def get_report(report_date: str):
    """Retrieve a specific day's intelligence report."""
    conn = get_connection()
    report = conn.execute(
        "SELECT * FROM intelligence_reports WHERE report_date = ?",
        (report_date,),
    ).fetchone()
    conn.close()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    result = dict(report)
    for field in ("top_risks", "emerging_themes", "active_threat_actors", "escalation_recommendations"):
        if result.get(field):
            result[field] = json.loads(result[field])
    return result


# --- ANALYTICS ---

@app.get("/analytics/spikes")
def get_spikes(threshold: float = Query(default=2.0, ge=1.0)):
    """Get keywords with unusual frequency spikes."""
    from analytics.spike_detection import detect_spikes
    return detect_spikes(threshold=threshold)


@app.get("/analytics/keyword-trend/{keyword_id}")
def get_keyword_trend_endpoint(keyword_id: int, days: int = Query(default=14, le=60)):
    """Get daily frequency trend for a specific keyword."""
    from analytics.spike_detection import get_keyword_trend
    return get_keyword_trend(keyword_id, days=days)


# --- KEYWORDS ---

@app.get("/keywords")
def get_keywords():
    conn = get_connection()
    keywords = conn.execute("SELECT * FROM keywords ORDER BY category, term").fetchall()
    conn.close()
    return [dict(k) for k in keywords]


@app.post("/keywords")
def add_keyword(keyword: KeywordCreate):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO keywords (term, category, weight) VALUES (?, ?, ?)",
            (keyword.term, keyword.category, keyword.weight),
        )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(status_code=409, detail="Keyword already exists")
    new_keyword = conn.execute(
        "SELECT * FROM keywords WHERE term = ?", (keyword.term,)
    ).fetchone()
    conn.close()
    return dict(new_keyword)


@app.delete("/keywords/{keyword_id}")
def delete_keyword(keyword_id: int):
    conn = get_connection()
    result = conn.execute("DELETE FROM keywords WHERE id = ?", (keyword_id,))
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Keyword not found")
    conn.commit()
    conn.close()
    return {"status": "deleted", "keyword_id": keyword_id}


@app.patch("/keywords/{keyword_id}/weight")
def update_keyword_weight(keyword_id: int, weight: float = Query(ge=0.1, le=5.0)):
    """Update a keyword's threat weight."""
    conn = get_connection()
    result = conn.execute(
        "UPDATE keywords SET weight = ? WHERE id = ?",
        (weight, keyword_id),
    )
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Keyword not found")
    conn.commit()
    conn.close()
    return {"status": "updated", "keyword_id": keyword_id, "weight": weight}


# --- SOURCES ---

@app.get("/sources")
def get_sources():
    conn = get_connection()
    sources = conn.execute("SELECT * FROM sources ORDER BY source_type, name").fetchall()
    conn.close()
    return [dict(s) for s in sources]


@app.patch("/sources/{source_id}/credibility")
def update_source_credibility(source_id: int, credibility_score: float = Query(ge=0.0, le=1.0)):
    """Update a source's credibility score."""
    conn = get_connection()
    result = conn.execute(
        "UPDATE sources SET credibility_score = ? WHERE id = ?",
        (credibility_score, source_id),
    )
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Source not found")
    conn.commit()
    conn.close()
    return {"status": "updated", "source_id": source_id, "credibility_score": credibility_score}


# --- THREAT ACTORS ---

@app.get("/threat-actors")
def get_threat_actors():
    conn = get_connection()
    actors = conn.execute(
        "SELECT * FROM threat_actors ORDER BY name"
    ).fetchall()
    conn.close()
    return [dict(a) for a in actors]
