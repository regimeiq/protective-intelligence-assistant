from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.init_db import get_connection, init_db, seed_default_sources, seed_default_keywords

app = FastAPI(
    title="OSINT Threat Monitor API",
    description="REST API for threat intelligence alerts and keyword management",
    version="1.0.0",
)


class KeywordCreate(BaseModel):
    term: str
    category: str = "general"


class KeywordResponse(BaseModel):
    id: int
    term: str
    category: str
    active: int


class AlertResponse(BaseModel):
    id: int
    title: str
    content: Optional[str]
    url: Optional[str]
    severity: str
    reviewed: int
    created_at: str
    source_name: Optional[str] = None
    matched_term: Optional[str] = None


@app.on_event("startup")
def startup():
    init_db()
    seed_default_sources()
    seed_default_keywords()


@app.get("/")
def root():
    return {"status": "online", "service": "OSINT Threat Monitor"}


# --- ALERTS ---

@app.get("/alerts")
def get_alerts(
    severity: Optional[str] = None,
    reviewed: Optional[int] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
):
    conn = get_connection()
    query = """
        SELECT a.id, a.title, a.content, a.url, a.severity, a.reviewed, a.created_at,
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

    query += " ORDER BY a.created_at DESC LIMIT ? OFFSET ?"
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

    conn.close()
    return {
        "total_alerts": total,
        "unreviewed": unreviewed,
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
            "INSERT INTO keywords (term, category) VALUES (?, ?)",
            (keyword.term, keyword.category),
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


# --- SOURCES ---

@app.get("/sources")
def get_sources():
    conn = get_connection()
    sources = conn.execute("SELECT * FROM sources ORDER BY source_type, name").fetchall()
    conn.close()
    return [dict(s) for s in sources]
