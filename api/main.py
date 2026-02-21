import json
import os
import sys
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.init_db import (
    get_connection,
    init_db,
    migrate_schema,
    seed_default_keywords,
    seed_default_sources,
    seed_threat_actors,
)

app = FastAPI(
    title="OSINT Threat Monitor API",
    description="Protective Intelligence REST API — quantitative risk scoring, Bayesian credibility, Z-score anomaly detection, and structured analytical reporting",
    version="3.0.0",
)


# --- Models ---


class KeywordCreate(BaseModel):
    term: str
    category: str = "general"
    weight: float = 1.0


class ClassifyRequest(BaseModel):
    classification: str  # "true_positive" or "false_positive"


class AlertResponse(BaseModel):
    id: int
    title: str
    content: Optional[str]
    url: Optional[str]
    risk_score: Optional[float] = None
    severity: str
    reviewed: int
    published_at: Optional[str] = None
    created_at: str
    source_name: Optional[str] = None
    matched_term: Optional[str] = None


# --- Startup ---


@app.on_event("startup")
def startup():
    init_db()
    migrate_schema()
    conn = get_connection()
    source_count = conn.execute("SELECT COUNT(*) AS count FROM sources").fetchone()["count"]
    keyword_count = conn.execute("SELECT COUNT(*) AS count FROM keywords").fetchone()["count"]
    actor_count = conn.execute("SELECT COUNT(*) AS count FROM threat_actors").fetchone()["count"]
    conn.close()

    # Seed only on first-run empty tables; do not overwrite analyst-tuned values.
    if source_count == 0:
        seed_default_sources()
    if keyword_count == 0:
        seed_default_keywords()
    if actor_count == 0:
        seed_threat_actors()


@app.get("/")
def root():
    return {"status": "online", "service": "OSINT Threat Monitor", "version": "3.0.0"}


# --- ALERTS ---


@app.get("/alerts")
def get_alerts(
    severity: Optional[str] = None,
    reviewed: Optional[int] = None,
    min_score: Optional[float] = None,
    sort_by: str = Query(default="risk_score", pattern="^(risk_score|created_at|published_at)$"),
    limit: int = Query(default=50, le=500),
    offset: int = 0,
):
    conn = get_connection()
    query = """
        SELECT a.id, a.title, a.content, a.url, a.risk_score, a.severity,
               a.reviewed, a.published_at, a.created_at, a.content_hash, a.duplicate_of,
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
    unique = conn.execute(
        "SELECT COUNT(*) as count FROM alerts WHERE duplicate_of IS NULL"
    ).fetchone()["count"]
    by_severity = conn.execute(
        "SELECT severity, COUNT(*) as count FROM alerts WHERE duplicate_of IS NULL GROUP BY severity"
    ).fetchall()
    by_source = conn.execute(
        """SELECT s.name, COUNT(*) as count FROM alerts a
        JOIN sources s ON a.source_id = s.id
        WHERE a.duplicate_of IS NULL
        GROUP BY s.name ORDER BY count DESC"""
    ).fetchall()
    top_keywords = conn.execute(
        """SELECT k.term, COUNT(*) as count FROM alerts a
        JOIN keywords k ON a.keyword_id = k.id
        WHERE a.duplicate_of IS NULL
        GROUP BY k.term ORDER BY count DESC LIMIT 10"""
    ).fetchall()
    unreviewed = conn.execute(
        "SELECT COUNT(*) as count FROM alerts WHERE reviewed = 0 AND duplicate_of IS NULL"
    ).fetchone()["count"]
    avg_score_row = conn.execute(
        "SELECT AVG(risk_score) as avg FROM alerts WHERE reviewed = 0 AND duplicate_of IS NULL"
    ).fetchone()
    avg_risk_score = round(avg_score_row["avg"], 1) if avg_score_row["avg"] else 0.0

    # Count active spikes
    from analytics.spike_detection import detect_spikes

    active_spikes = len(detect_spikes(threshold=2.0))

    # Duplicate stats
    duplicates = total - unique

    conn.close()
    return {
        "total_alerts": total,
        "unique_alerts": unique,
        "duplicates": duplicates,
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
    result = conn.execute("UPDATE alerts SET reviewed = 1 WHERE id = ?", (alert_id,))
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.commit()
    conn.close()
    return {"status": "reviewed", "alert_id": alert_id}


@app.patch("/alerts/{alert_id}/classify")
def classify_alert(alert_id: int, body: ClassifyRequest):
    """
    Classify an alert as true_positive or false_positive.
    Updates the source's Bayesian credibility (alpha/beta).
    """
    from analytics.risk_scoring import update_source_credibility_bayesian

    if body.classification not in ("true_positive", "false_positive"):
        raise HTTPException(
            status_code=400,
            detail="classification must be 'true_positive' or 'false_positive'",
        )

    conn = get_connection()
    alert = conn.execute("SELECT source_id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    # Mark as reviewed
    conn.execute("UPDATE alerts SET reviewed = 1 WHERE id = ?", (alert_id,))

    # Update Bayesian credibility
    is_tp = body.classification == "true_positive"
    update_source_credibility_bayesian(conn, alert["source_id"], is_tp)

    conn.commit()

    # Return updated source credibility
    source = conn.execute(
        "SELECT name, credibility_score, bayesian_alpha, bayesian_beta, true_positives, false_positives FROM sources WHERE id = ?",
        (alert["source_id"],),
    ).fetchone()
    conn.close()

    return {
        "status": "classified",
        "alert_id": alert_id,
        "classification": body.classification,
        "source_name": source["name"],
        "updated_credibility": source["credibility_score"],
        "bayesian_alpha": source["bayesian_alpha"],
        "bayesian_beta": source["bayesian_beta"],
        "true_positives": source["true_positives"],
        "false_positives": source["false_positives"],
    }


@app.get("/alerts/{alert_id}/score")
def get_alert_score(
    alert_id: int,
    uncertainty: int = Query(default=0, ge=0, le=1),
    n: int = Query(default=500, ge=100, le=5000),
    force: int = Query(default=0, ge=0, le=1),
):
    """Get the score breakdown for a specific alert, including Monte Carlo interval stats."""
    from analytics.uncertainty import compute_uncertainty_for_alert

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

    payload = dict(score)
    if uncertainty == 1:
        try:
            payload["uncertainty"] = compute_uncertainty_for_alert(
                alert_id=alert_id,
                n=n,
                force=bool(force),
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
    return payload


@app.get("/alerts/{alert_id}/entities")
def get_alert_entities(alert_id: int):
    conn = get_connection()
    alert = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    entities = conn.execute(
        """SELECT id, entity_type, entity_value, created_at
        FROM alert_entities
        WHERE alert_id = ?
        ORDER BY entity_type, entity_value""",
        (alert_id,),
    ).fetchall()
    conn.close()
    return [dict(entity) for entity in entities]


@app.get("/alerts/{alert_id}/iocs")
def get_alert_iocs(alert_id: int):
    conn = get_connection()
    alert = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    iocs = conn.execute(
        """SELECT id, entity_type AS type, entity_value AS value
        FROM alert_entities
        WHERE alert_id = ?
          AND entity_type IN ('ipv4', 'domain', 'url', 'cve', 'md5', 'sha1', 'sha256')
        ORDER BY entity_type, entity_value""",
        (alert_id,),
    ).fetchall()
    conn.close()
    return [dict(ioc) for ioc in iocs]


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

    if date is not None:
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail="Invalid date format. Use YYYY-MM-DD.",
            ) from e
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
    for field in (
        "top_risks",
        "emerging_themes",
        "active_threat_actors",
        "escalation_recommendations",
        "top_entities",
        "new_cves",
    ):
        if result.get(field):
            result[field] = json.loads(result[field])
    return result


# --- ANALYTICS ---


@app.get("/analytics/spikes")
def get_spikes(
    threshold: float = Query(default=2.0, ge=1.0),
    date: Optional[str] = Query(default=None),
):
    """Get keywords with unusual frequency spikes (includes Z-score)."""
    from analytics.spike_detection import detect_spikes

    if date is not None:
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail="Invalid date format. Use YYYY-MM-DD.",
            ) from e
    return detect_spikes(threshold=threshold, as_of_date=date)


@app.get("/analytics/keyword-trend/{keyword_id}")
def get_keyword_trend_endpoint(keyword_id: int, days: int = Query(default=14, le=60)):
    """Get daily frequency trend for a specific keyword."""
    from analytics.spike_detection import get_keyword_trend

    return get_keyword_trend(keyword_id, days=days)


@app.get("/analytics/forecast/keyword/{keyword_id}")
def get_keyword_forecast(keyword_id: int, horizon: int = Query(default=7, ge=1, le=30)):
    """Forecast keyword frequency for the next N days."""
    from analytics.forecasting import forecast_keyword

    return forecast_keyword(keyword_id=keyword_id, horizon=horizon)


@app.get("/analytics/evaluation")
def get_evaluation_metrics(source_id: Optional[int] = None):
    """
    Compute and return precision/recall/F1 per source.
    Based on TP/FP classifications from alert reviews.
    """
    from analytics.risk_scoring import compute_evaluation_metrics

    conn = get_connection()
    if source_id is not None:
        source = conn.execute(
            "SELECT id FROM sources WHERE id = ?",
            (source_id,),
        ).fetchone()
        if not source:
            conn.close()
            raise HTTPException(status_code=404, detail="Source not found")
    results = compute_evaluation_metrics(conn, source_id=source_id)
    conn.close()
    return results


@app.get("/analytics/performance")
def get_performance_metrics(limit: int = Query(default=20, le=100)):
    """Get recent scraping performance benchmarks."""
    conn = get_connection()
    runs = conn.execute(
        """SELECT * FROM scrape_runs
        ORDER BY started_at DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in runs]


@app.get("/analytics/backtest")
def run_backtest():
    """
    Run scoring model backtest against golden dataset of known incidents.
    Compares multi-factor scoring vs naive baseline.
    """
    from analytics.backtesting import run_backtest

    return run_backtest()


@app.get("/analytics/duplicates")
def get_duplicate_stats():
    """Get content deduplication statistics."""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as count FROM alerts").fetchone()["count"]
    unique = conn.execute(
        "SELECT COUNT(*) as count FROM alerts WHERE duplicate_of IS NULL"
    ).fetchone()["count"]
    duplicates = total - unique

    # Top duplicate clusters (original alerts with most duplicates)
    clusters = conn.execute(
        """SELECT a.id, a.title, a.content_hash, COUNT(d.id) as dup_count
        FROM alerts a
        JOIN alerts d ON d.duplicate_of = a.id
        GROUP BY a.id
        ORDER BY dup_count DESC
        LIMIT 10"""
    ).fetchall()

    conn.close()
    return {
        "total_alerts": total,
        "unique_alerts": unique,
        "duplicates": duplicates,
        "dedup_ratio": round(duplicates / total, 4) if total > 0 else 0.0,
        "top_clusters": [dict(c) for c in clusters],
    }


@app.get("/analytics/graph")
def get_graph(
    days: int = Query(default=7, ge=1, le=30),
    min_score: float = Query(default=70.0, ge=0.0, le=100.0),
    limit_alerts: int = Query(default=500, ge=10, le=2000),
):
    """Build a compact link-analysis graph across sources, keywords, entities, and IOCs."""
    from analytics.graph import build_graph

    return build_graph(days=days, min_score=min_score, limit_alerts=limit_alerts)


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
    new_keyword = conn.execute("SELECT * FROM keywords WHERE term = ?", (keyword.term,)).fetchone()
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
    actors = conn.execute("SELECT * FROM threat_actors ORDER BY name").fetchall()
    conn.close()
    return [dict(a) for a in actors]
