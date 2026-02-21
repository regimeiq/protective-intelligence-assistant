"""EP enrichment pipeline executed after alert insertion."""

from analytics.ep_scoring import compute_operational_score
from analytics.location_enrichment import process_alert_locations
from analytics.poi_matching import process_alert_poi_hits
from analytics.tas_assessment import update_alert_tas

EP_LOCATION_TRIGGER_CATEGORIES = {
    "protective_intel",
    "protest_disruption",
    "travel_risk",
    "insider_workplace",
    "poi",
}


def process_ep_signals(conn, alert_id, title, content, keyword_category=None, baseline_score=0.0):
    text = f"{title or ''}\n{content or ''}".strip()
    poi_hits = process_alert_poi_hits(conn, alert_id, text)

    geocode_enabled = (
        bool(poi_hits)
        or (keyword_category or "").strip().lower() in EP_LOCATION_TRIGGER_CATEGORIES
        or float(baseline_score or 0.0) >= 75.0
    )
    locations = process_alert_locations(conn, alert_id, text, geocode_enabled=geocode_enabled)

    ors = compute_operational_score(conn, alert_id)
    tas = update_alert_tas(conn, alert_id)

    return {
        "poi_hits": poi_hits,
        "locations": locations,
        "ors": ors,
        "tas": tas,
    }
