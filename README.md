# OSINT Threat Monitor — Protective Intelligence Platform

Automated threat intelligence platform that collects, processes, scores, and prioritizes open-source threat data using **statistically-grounded quantitative methods** — Z-score anomaly detection, Bayesian credibility learning, content deduplication, and backtested scoring models. Built for corporate security teams, executive protection analysts, and SOC operators who need structured, actionable intelligence — not just raw alerts.

## The Problem

Security teams drown in unstructured threat data. RSS feeds, Reddit threads, paste dumps — the volume is overwhelming, and most of it is noise. Traditional monitoring tools tell you *what happened*. This platform tells you *what matters right now and why* — with statistically defensible scoring that learns from analyst feedback.

## Who It's For

- **Corporate Security Teams** — monitor threats to brand, executives, and infrastructure
- **Executive Protection Analysts** — track threat actors, insider threats, and risk indicators
- **SOC Analysts** — triage and prioritize alerts with quantified risk scores
- **Threat Intelligence Teams** — automated collection with structured analytical output

## Intelligence Cycle

This platform implements the full intelligence cycle:

```
┌─────────────┐    ┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐    ┌─────────────┐
│  Collection  │───▶│  Processing │───▶│    Indicator      │───▶│ Prioritization  │───▶│  Escalation │
│              │    │             │    │    Matching        │    │                 │    │             │
│ RSS feeds    │    │ Normalize   │    │ Weighted keyword  │    │ Z-score anomaly │    │ Daily intel │
│ Reddit       │    │ Deduplicate │    │ matching with     │    │ detection +     │    │ reports     │
│ Pastebin     │    │ Hash + Fuzzy│    │ regex boundaries  │    │ Bayesian cred.  │    │ Escalation  │
│ (async)      │    │             │    │                    │    │ scoring         │    │ recs        │
└─────────────┘    └─────────────┘    └──────────────────┘    └─────────────────┘    └─────────────┘
```

## Key Capabilities

### Multi-Factor Risk Scoring Engine

Every alert receives a quantified 0-100 risk score based on:

```
Risk Score = (keyword_weight x frequency_factor x source_credibility x 20) + (recency_factor x 10)
```

| Factor | Range | Method | Description |
|--------|-------|--------|-------------|
| Keyword Weight | 0.1 - 5.0 | Manual | Threat severity of the matched term (zero-day = 5.0, dark web = 1.5) |
| Source Credibility | 0.0 - 1.0 | **Bayesian Beta** | Learned from TP/FP classifications: `alpha / (alpha + beta)` |
| Frequency Factor | 1.0 - 4.0 | **Z-Score** | `z = (today - mean_7d) / std_7d`, mapped to multiplier |
| Recency Factor | 0.1 - 1.0 | Linear decay | Over 7 days — newer alerts score higher |

Score-to-severity mapping: **90+ = Critical**, **70-89 = High**, **40-69 = Medium**, **0-39 = Low**

### Z-Score Anomaly Detection

Frequency spikes are detected using population Z-scores rather than simple ratios. The system computes `z = (today_count - mean_7d) / std_dev_7d` for each keyword, with a standard deviation floor of 0.5 to prevent near-zero division. Z-scores map to frequency multipliers: z <= 0 maps to 1.0x, z >= 4 maps to 4.0x. Falls back to simple ratio when fewer than 3 days of data exist.

### Bayesian Source Credibility

Source trustworthiness is modeled as a Beta distribution. Each source starts with a uniform prior (alpha=2, beta=2). When analysts classify alerts as true or false positives, the system updates:
- True positive: `alpha += 1` (source becomes more credible)
- False positive: `beta += 1` (source becomes less credible)

Credibility converges toward empirical precision as classifications accumulate.

### Monte Carlo Uncertainty (On-Demand)

`/alerts/{id}/score?uncertainty=1` computes and caches score intervals in `alert_score_intervals` (6-hour cache window by default):
- sampled: source credibility (`Beta(alpha, beta)`), keyword weight (`Normal(weight, sigma)` clipped to `[0.1, 5.0]`)
- deterministic: frequency factor and recency factor from the scored alert
- output: `mean`, `std`, `p05`, `p50`, `p95`, `method`

### Content Deduplication

Two-tier dedup pipeline prevents duplicate alerts from inflating risk signals:
1. **Fast path**: SHA-256 hash of normalized title+content (O(1) index lookup)
2. **Slow path**: Fuzzy title matching via SequenceMatcher (0.85 threshold, bounded to 200 same-day candidates)

Duplicates are stored with `duplicate_of` references but excluded from scoring, frequency counts, and intelligence reports.

### Async Ingestion

HTTP fetches use `aiohttp` for concurrent source collection. RSS and Reddit feeds are fetched in parallel; Pastebin stays sequential (rate-limited). If async fetch fails for a specific RSS source, the scraper attempts a sync fallback for that source. Falls back to full synchronous mode if aiohttp is unavailable. Performance metrics (duration, alerts/sec) are recorded per run.

### Backtesting Framework

8-incident golden dataset (SolarWinds, Log4Shell, MOVEit, Colonial Pipeline, Kaseya, ProxyLogon, PrintNightmare, CrowdStrike) validates the scoring model against a naive baseline (`keyword_weight x 20`). The backtest compares detection rates, mean scores, and severity accuracy.

### Evaluation Metrics

Per-source precision, recall, and F1 scores computed from analyst TP/FP classifications. Persisted to `evaluation_metrics` table for trend tracking.

### Daily Intelligence Reports

Automated structured analytical output including:
- Executive summary with prioritized risk narrative
- Top 10 risks ranked by score (unique alerts only, deduped)
- Emerging themes via Z-score spike detection
- Active threat actor cross-referencing (APT28, Lazarus, LockBit, etc.)
- Escalation recommendations with priority levels (IMMEDIATE / HIGH / MEDIUM)

### Threat Actor Correlation

Maintains a database of known threat actors (APT28, APT29, Lazarus Group, Sandworm, LockBit, BlackCat, etc.) and cross-references alert keyword matches to identify relevant actor activity.

### POI Watchlist (v0)

Person-of-interest monitoring uses the existing `keywords` table with category `poi`:
- one alias per keyword row
- higher default seed weight for `poi` terms (`4.0`)
- configurable via `config/watchlist.yaml` and the dashboard Configuration tab
- matching is keyword-based; ambiguous single-token aliases can create false positives, so defaults favor multi-token names

### Regex IOC Entity Extraction

Regex-based IOC extraction runs on alert title+content and stores artifacts in `alert_entities`:
- `ipv4`, `domain`, `url`, `cve`, `md5`, `sha1`, `sha256`
- unique per `(alert_id, entity_type, entity_value)`

Artifacts are exposed through `/alerts/{id}/entities` and displayed in the alert detail view.

## Example Scenario

> A supply chain attack is trending across multiple sources. The system detects "supply chain attack" with a Z-score of 3.2 (today's count is 3.2 standard deviations above the 7-day mean). The keyword has a weight of 4.0. A CISA alert (Bayesian credibility: 1.0 after 15 TP classifications) mentions it, producing a risk score of **94.2 (CRITICAL)**. The daily intelligence report flags it as an IMMEDIATE escalation item. An analyst classifies the alert as a true positive, which reinforces CISA's Bayesian credibility for future scoring.

## Architecture

```
[CISA RSS] [Krebs] [BleepingComputer] [Reddit] [Pastebin]
     │         │           │              │          │
     └─────────┴───────────┴──────────────┴──────────┘
                           │
                    ┌──────▼──────┐
                    │  Async      │  aiohttp concurrent fetch
                    │  Scrapers   │  RSS / Reddit / Pastebin
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Dedup +    │  SHA-256 hash + fuzzy title
                    │  Keyword    │  Regex word-boundary matching
                    │  Matching   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Risk       │  Z-score + Bayesian scoring
                    │  Scoring    │  with audit trail
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  SQLite DB  │  Alerts, scores, frequencies,
                    │ (11 tables) │  threat actors, reports, metrics
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐  ┌─▼──────┐  ┌──▼───────────┐
       │  FastAPI     │  │ Intel  │  │  Streamlit   │
       │  REST API    │  │ Report │  │  Dashboard   │
       │ (27 endpts)  │  │ Engine │  │  (9 tabs)    │
       └─────────────┘  └────────┘  └──────────────┘
```

## Tech Stack

| Layer | Tool |
|-------|------|
| Scraping | Feedparser, BeautifulSoup, aiohttp (async) |
| Analytics | Z-score, Bayesian Beta, SHA-256 dedup (Python stdlib + aiohttp) |
| API | FastAPI (27 endpoints) |
| Database | SQLite (11 tables) |
| Dashboard | Streamlit + Plotly |
| Container | Docker, docker-compose |
| Language | Python 3.11+ |

## Quickstart

```bash
git clone https://github.com/YOUR_USERNAME/osint-threat-monitor.git
cd osint-threat-monitor
pip install -r requirements.txt

# Optional: install spaCy small English model for NER (IOC regex works without this)
pip install "spacy>=3.7"
python -m spacy download en_core_web_sm

# Initialize database (seeds from config/watchlist.yaml; falls back to built-in defaults)
python run.py init

# Run scrapers to collect threat data
python run.py scrape

# Start API server (Terminal 1)
python run.py api

# Start dashboard (Terminal 2)
python run.py dashboard
```

- **API Docs:** http://localhost:8000/docs
- **Dashboard:** http://localhost:8501

### Smoke Test

```bash
./scripts/smoke_test.sh
```

### Config-Driven Seeding

`python run.py init` seeds `sources` and `keywords` from `config/watchlist.yaml` when the file exists.
If the file is missing or invalid, the app falls back to hardcoded default seed lists.

Expected shape:

```yaml
sources:
  rss:
    - name: "Source Name"
      url: "https://example.com/feed.xml"
    - name: "GDELT PI/EP Watch"
      gdelt_query: '("threat to CEO" OR swatting) AND (executive OR CEO)'
      credibility_score: 0.6
  reddit:
    - name: "r/example"
      url: "https://www.reddit.com/r/example/.rss"
  pastebin:
    - name: "Pastebin Archive"
      url: "https://pastebin.com/archive"

keywords:
  threat_actor:
    - "APT29"
  poi:
    - "Jane Doe"
    - term: "J. Doe"
      weight: 4.0
  protective_intel:
    - term: "death threat"
      weight: 5.0
  vulnerability:
    - "CVE"
  malware:
    - "ransomware"
  general:
    - "phishing"
```

Keyword entries accept either a string or an object with `term` and optional `weight`.
If `weight` is omitted, seeding uses `1.0` by default (`poi` defaults to `4.0`).

## Code Quality

```bash
pip install -r requirements-dev.txt
pre-commit install
pre-commit run --all-files
```

The repo is configured for `black`, `isort`, and `ruff` via `pyproject.toml`.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/alerts` | Retrieve alerts (filter by severity, score, review status) |
| GET | `/alerts/summary` | Aggregated metrics + avg risk score + spike count + dedup stats |
| GET | `/alerts/{id}/score` | Score breakdown; add `?uncertainty=1&n=500` for cached Monte Carlo interval |
| GET | `/alerts/{id}/entities` | Regex IOC entities for one alert (`entity_type`, `entity_value`) |
| GET | `/alerts/{id}/iocs` | IOC convenience view derived from `alert_entities` |
| PATCH | `/alerts/{id}/review` | Mark alert as reviewed |
| PATCH | `/alerts/{id}/classify` | Classify TP/FP — updates Bayesian source credibility |
| POST | `/alerts/rescore` | Re-score all unreviewed alerts |
| GET | `/intelligence/daily` | Generate daily intelligence report |
| GET | `/intelligence/reports` | List recent reports |
| GET | `/intelligence/reports/{date}` | Retrieve specific report |
| GET | `/analytics/spikes` | Detect keyword frequency spikes (with Z-scores) |
| GET | `/analytics/keyword-trend/{id}` | Keyword frequency over time |
| GET | `/analytics/forecast/keyword/{id}` | 7-day keyword forecast + quality metrics |
| GET | `/analytics/graph` | Link-analysis graph across sources/keywords/entities/IOCs |
| GET | `/analytics/evaluation` | Precision/recall/F1 per source |
| GET | `/analytics/performance` | Scraping run benchmarks (duration, alerts/sec) |
| GET | `/analytics/backtest` | Run backtest against golden dataset |
| GET | `/analytics/duplicates` | Content deduplication statistics |
| GET | `/keywords` | List all keywords with weights |
| POST | `/keywords` | Add keyword with category and weight |
| DELETE | `/keywords/{id}` | Remove keyword |
| PATCH | `/keywords/{id}/weight` | Update keyword threat weight |
| GET | `/sources` | List sources with Bayesian credibility scores |
| PATCH | `/sources/{id}/credibility` | Update source credibility |
| GET | `/threat-actors` | List known threat actors |

### Endpoint Examples

```bash
# Alert artifacts
curl "http://localhost:8000/alerts/1/entities"
curl "http://localhost:8000/alerts/1/iocs"

# Score with Monte Carlo uncertainty interval
curl "http://localhost:8000/alerts/1/score?uncertainty=1&n=500"

# Forecast keyword frequency
curl "http://localhost:8000/analytics/forecast/keyword/1?horizon=7"

# Link-analysis graph
curl "http://localhost:8000/analytics/graph?days=7&min_score=70&limit_alerts=500"
```

## Repo Structure

```
osint-threat-monitor/
├── analytics/
│   ├── risk_scoring.py          # Z-score + Bayesian multi-factor scoring engine
│   ├── uncertainty.py           # Cached Monte Carlo interval engine
│   ├── spike_detection.py       # Z-score keyword frequency spike detection
│   ├── intelligence_report.py   # Daily intelligence report generator
│   ├── entity_extraction.py     # Regex IOC extraction + storage
│   ├── dedup.py                 # SHA-256 + fuzzy content deduplication
│   └── backtesting.py           # Golden dataset backtesting framework
├── scraper/
│   ├── __init__.py              # Async orchestration + performance tracking
│   ├── rss_scraper.py           # RSS feed scraper (CISA, Krebs, BleepingComputer)
│   ├── reddit_scraper.py        # Reddit threat community scraper
│   └── pastebin_monitor.py      # Pastebin archive monitor
├── api/
│   └── main.py                  # FastAPI REST API (27 endpoints)
├── dashboard/
│   └── app.py                   # Streamlit dashboard (9 tabs)
├── database/
│   ├── init_db.py               # DB init, migration, seeding
│   └── schema.sql               # SQLite schema (11 tables)
├── config/
│   └── watchlist.yaml           # Reference keyword/source config
├── scripts/
│   └── smoke_test.sh            # Fresh-clone runnable smoke test
├── run.py                       # CLI entry point
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Database Schema

| Table | Purpose |
|-------|---------|
| `sources` | Intelligence sources with Bayesian credibility (alpha/beta/TP/FP) |
| `keywords` | Watchlist terms with threat weights |
| `alerts` | Matched threat alerts with risk scores and content hashes |
| `alert_scores` | Score audit trail (weight breakdown + Z-score point estimate) |
| `keyword_frequency` | Daily keyword match counts (for Z-score spike detection) |
| `intelligence_reports` | Persisted daily analytical summaries |
| `threat_actors` | Known threat actor profiles |
| `evaluation_metrics` | Per-source precision/recall/F1 over time |
| `scrape_runs` | Scraping performance benchmarks (duration, alerts/sec) |
| `alert_entities` | Regex IOC entities linked to alerts |
| `alert_score_intervals` | On-demand uncertainty interval cache |

## Roadmap

- [x] Multi-source scraping (RSS, Reddit, Pastebin)
- [x] SQLite database with structured schema (11 tables)
- [x] FastAPI REST API (27 endpoints)
- [x] Keyword matching engine with regex boundaries
- [x] Streamlit dashboard with interactive charts (9 tabs)
- [x] Multi-factor risk scoring engine
- [x] Z-score anomaly detection for frequency spikes
- [x] Bayesian source credibility learning (Beta distribution)
- [x] Content deduplication (SHA-256 + fuzzy title matching)
- [x] Async scraping with aiohttp
- [x] Backtesting framework (golden dataset validation)
- [x] Precision/recall/F1 evaluation metrics
- [x] TP/FP classification with Bayesian feedback loop
- [x] Scraping performance tracking
- [x] Daily intelligence reports with escalation recommendations
- [x] Threat actor correlation
- [x] Score audit trail
- [ ] Dark web forum integration
- [ ] PDF/CSV export for reporting
- [ ] Email/Slack alerting on critical scores
- [x] Regex IOC extraction + `alert_entities` storage
- [ ] IOC feed integration (STIX/TAXII)

## License

MIT
