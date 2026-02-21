from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class KeywordCreate(BaseModel):
    term: str
    category: str = "general"


class KeywordResponse(BaseModel):
    id: int
    term: str
    category: str
    active: int
    created_at: str


class AlertResponse(BaseModel):
    id: int
    source_name: str
    keyword_term: str
    title: Optional[str]
    content: Optional[str]
    url: Optional[str]
    matched_term: str
    severity: str
    reviewed: int
    published_at: Optional[str]
    created_at: str


class AlertSummary(BaseModel):
    total_alerts: int
    by_severity: dict
    by_source: dict
    by_keyword: dict
    recent_24h: int


class SourceResponse(BaseModel):
    id: int
    name: str
    url: str
    source_type: str
    active: int


class ScrapeResult(BaseModel):
    new_alerts: int
    message: str
