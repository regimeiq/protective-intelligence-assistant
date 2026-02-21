# OSINT Threat Monitor -> Protective Intelligence Assistant

This project now defaults to a **Protective Intelligence / Executive Protection assistance workflow**:
- Protectee (POI) hit detection
- Facility proximity monitoring
- Event/travel-aware triage
- Operational Risk Score (ORS) + Threat Assessment Score (TAS)

The existing CTI pipeline remains available, but CTI is now an **optional keyword pack** (`cti_optional`) rather than the main product narrative.

## What It Does

### Core EP workflow
1. Collect alerts from safe sources (RSS/Reddit/Pastebin + optional ACLED)
2. Match EP taxonomy keywords
3. Extract IOCs/entities (regex first; optional spaCy location entities)
4. Match protectees (POIs) using aliases (conservative matching)
5. Resolve locations (regex + optional geocoding with cache/rate limiting)
6. Compute:
   - **ORS**: operational triage score for briefing/monitoring
   - **TAS**: TRAP-lite targeting escalation score per protectee
7. Produce EP-native daily report and travel briefs

## Scoring Model

### Operational Risk Score (ORS)
ORS is persisted as `alerts.ors_score` (and mirrored to `alerts.risk_score` for compatibility).

Drivers:
- recency
- source Bayesian credibility
- frequency anomaly (z-score)
- EP category factor
- proximity to protected locations
- event adjacency
- POI hit contribution

### Threat Assessment Score (TAS)
TAS is persisted as `alerts.tas_score` and `poi_assessments.tas_score`.

TRAP-lite flags:
- `fixation`
- `energy_burst`
- `leakage`
- `pathway`
- `targeting_specificity`

### Uncertainty
Single unified Monte Carlo engine in `analytics/uncertainty.py`.
- ORS intervals: `/alerts/{id}/score?uncertainty=1`
- TAS intervals: included in `poi_assessments.evidence_json.interval`

## Data Model (EP additions)

Added tables:
- `pois`, `poi_aliases`, `poi_hits`
- `protected_locations`, `alert_locations`, `alert_proximity`
- `events`, `event_risk_snapshots`
- `poi_assessments`
- `dispositions`
- `travel_briefs`
- `geocode_cache`
- `retention_log`

Existing CTI-compatible tables remain (`alerts`, `alert_scores`, `keyword_frequency`, etc.).

## Safe Source Policy

Shipped by default:
- RSS sources (State Dept / CDC / WHO / GDELT + optional CTI feeds)
- Reddit RSS
- Pastebin archive monitor
- Optional ACLED connector (env-gated)

Not shipped (stubs only):
- Telegram/chans collectors (`scraper/connectors/*_stub.py`)
- These require explicit legal/ToS compliance and approved auth/collection controls.

## Quickstart

```bash
git clone https://github.com/regimeiq/osint-threat-monitor.git
cd osint-threat-monitor
pip install -r requirements.txt

# Optional NER for GPE/LOC extraction
pip install "spacy>=3.7"
python -m spacy download en_core_web_sm

python run.py init
python run.py scrape
python run.py api
python run.py dashboard
```

### Smoke test

```bash
./scripts/smoke_test.sh
```

## Demo Pack

```bash
python run.py demo
```

Generates:
- `docs/demo_daily_report.md`
- `docs/demo_travel_brief.md`
- `docs/protectee_view.svg`
- `docs/map_view.svg`

## Watchlist Configuration

Main config file: `config/watchlist.yaml`

Sections:
- `keywords` (EP-first taxonomy)
  - `protective_intel`
  - `protest_disruption`
  - `travel_risk`
  - `insider_workplace`
  - `ioc` (supporting, not headline)
- `cti_optional` (keeps cyber terms available)
- `pois`
- `protected_locations`
- `events`
- `sources`

## API Highlights

### Existing endpoints (kept)
- `GET /alerts`
- `GET /alerts/{id}/score`
- `GET /alerts/{id}/entities`
- `GET /alerts/{id}/iocs`
- `GET /intelligence/daily`
- `GET /analytics/graph`

### EP endpoints
- `GET /pois`
- `POST /pois`
- `GET /pois/{id}/hits`
- `GET /pois/{id}/assessment`
- `GET /locations/protected`
- `POST /locations/protected`
- `GET /locations/protected/{id}/alerts`
- `GET /analytics/map`
- `POST /briefs/travel`
- `GET /briefs/travel`
- `POST /alerts/{id}/disposition`

### Example calls

```bash
# ORS/TAS breakdown + interval
curl "http://localhost:8000/alerts/1/score?uncertainty=1&n=500"

# IOC evidence (supporting)
curl "http://localhost:8000/alerts/1/iocs"

# POI assessment
curl "http://localhost:8000/pois/1/assessment?window_days=14"

# Travel brief
curl -X POST "http://localhost:8000/briefs/travel" \
  -H "Content-Type: application/json" \
  -d '{"destination":"San Francisco, CA","start_dt":"2026-02-21","end_dt":"2026-02-24"}'
```

## Governance

### Redaction
- `REDACT_PERSON_ENTITIES` (default `true`)
- Redacts POI/person names in export-like outputs (reports/briefs) while retaining internal storage.

### Retention
- `RAW_CONTENT_RETENTION_DAYS` (default `30`)
- Purge command:

```bash
python run.py purge
```

This nulls old raw alert content while preserving metadata/scores and logs actions in `retention_log`.

## Optional ACLED connector

Runs only when configured:
- `ACLED_API_KEY`
- `ACLED_EMAIL`

If missing, the collector logs skip and exits without error.

## Notes

- This is an analyst-assistance tool, not an autonomous enforcement or SaaS case platform.
- Location geocoding is cache-first (`geocode_cache`) and only triggered for relevant alerts (POI hits / high ORS / protest-travel categories).
