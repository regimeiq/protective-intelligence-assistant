# OSINT Threat Monitor — Protective Intelligence Platform

Automated threat intelligence platform that collects, processes, scores, and prioritizes open-source threat data. Built for corporate security teams, executive protection analysts, and SOC operators who need structured, actionable intelligence — not just raw alerts.

## The Problem

Security teams drown in unstructured threat data. RSS feeds, Reddit threads, paste dumps — the volume is overwhelming, and most of it is noise. Traditional monitoring tools tell you *what happened*. This platform tells you *what matters right now and why*.

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
│ RSS feeds    │    │ Normalize   │    │ Weighted keyword  │    │ Multi-factor    │    │ Daily intel │
│ Reddit       │    │ Deduplicate │    │ matching with     │    │ risk scoring    │    │ reports     │
│ Pastebin     │    │ Extract     │    │ regex boundaries  │    │ engine          │    │ Escalation  │
│              │    │             │    │                    │    │                 │    │ recs        │
└─────────────┘    └─────────────┘    └──────────────────┘    └─────────────────┘    └─────────────┘
```

## Key Capabilities

### Multi-Factor Risk Scoring Engine
Every alert receives a quantified 0-100 risk score based on:

```
Risk Score = (keyword_weight x frequency_factor x source_credibility x 20) + (recency_factor x 10)
```

| Factor | Range | Description |
|--------|-------|-------------|
| Keyword Weight | 0.1 - 5.0 | Threat severity of the matched term (zero-day = 5.0, dark web = 1.5) |
| Source Credibility | 0.0 - 1.0 | Trustworthiness of the source (CISA = 1.0, Pastebin = 0.2) |
| Frequency Factor | 1.0+ | Spike multiplier — today's count vs 7-day rolling average |
| Recency Factor | 0.1 - 1.0 | Linear decay over 7 days — newer alerts score higher |

Score-to-severity mapping: **90+ = Critical**, **70-89 = High**, **40-69 = Medium**, **0-39 = Low**

### Daily Intelligence Reports
Automated structured analytical output including:
- Executive summary with prioritized risk narrative
- Top 10 risks ranked by score
- Emerging themes via frequency spike detection
- Active threat actor cross-referencing (APT28, Lazarus, LockBit, etc.)
- Escalation recommendations with priority levels (IMMEDIATE / HIGH / MEDIUM)

### Frequency Spike Detection
Identifies keywords with abnormal activity levels by comparing real-time counts against rolling 7-day baselines. A keyword normally appearing 2x/day that spikes to 10x triggers escalation.

### Threat Actor Correlation
Maintains a database of known threat actors (APT28, APT29, Lazarus Group, Sandworm, LockBit, BlackCat, etc.) and cross-references alert keyword matches to identify relevant actor activity.

## Example Scenario

> A supply chain attack is trending across multiple sources. The system detects "supply chain attack" spiking 4x above its 7-day baseline. The keyword has a weight of 4.0. A CISA alert (credibility: 1.0) mentions it, producing a risk score of **90.0 (CRITICAL)**. The daily intelligence report flags it as an IMMEDIATE escalation item with the recommendation: "Review and assess impact. Brief stakeholders within 1 hour."

## Architecture

```
[CISA RSS] [Krebs] [BleepingComputer] [Reddit] [Pastebin]
     │         │           │              │          │
     └─────────┴───────────┴──────────────┴──────────┘
                           │
                    ┌──────▼──────┐
                    │   Scrapers  │  RSS / Reddit / Pastebin
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Keyword    │  Regex word-boundary matching
                    │  Matching   │  against configurable watchlist
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Risk       │  Multi-factor scoring engine
                    │  Scoring    │  with audit trail
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  SQLite DB  │  Alerts, scores, frequencies,
                    │             │  threat actors, reports
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐  ┌─▼──────┐  ┌──▼───────────┐
       │  FastAPI     │  │ Intel  │  │  Streamlit   │
       │  REST API    │  │ Report │  │  Dashboard   │
       │  (18 endpoints)│ │ Engine │  │  (5 tabs)    │
       └─────────────┘  └────────┘  └──────────────┘
```

## Tech Stack

| Layer | Tool |
|-------|------|
| Scraping | Feedparser, BeautifulSoup, Requests |
| Analytics | Custom risk scoring engine (Python stdlib) |
| API | FastAPI (18 endpoints) |
| Database | SQLite (7 tables) |
| Dashboard | Streamlit + Plotly |
| Container | Docker, docker-compose |
| Language | Python 3.11+ |

## Quickstart

```bash
git clone https://github.com/YOUR_USERNAME/osint-threat-monitor.git
cd osint-threat-monitor
pip install -r requirements.txt

# Initialize database with sources, keywords, and threat actors
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

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/alerts` | Retrieve alerts (filter by severity, score, review status) |
| GET | `/alerts/summary` | Aggregated metrics + avg risk score + spike count |
| GET | `/alerts/{id}/score` | Score breakdown for a specific alert |
| PATCH | `/alerts/{id}/review` | Mark alert as reviewed |
| POST | `/alerts/rescore` | Re-score all unreviewed alerts |
| GET | `/intelligence/daily` | Generate daily intelligence report |
| GET | `/intelligence/reports` | List recent reports |
| GET | `/intelligence/reports/{date}` | Retrieve specific report |
| GET | `/analytics/spikes` | Detect keyword frequency spikes |
| GET | `/analytics/keyword-trend/{id}` | Keyword frequency over time |
| GET | `/keywords` | List all keywords with weights |
| POST | `/keywords` | Add keyword with category and weight |
| DELETE | `/keywords/{id}` | Remove keyword |
| PATCH | `/keywords/{id}/weight` | Update keyword threat weight |
| GET | `/sources` | List sources with credibility scores |
| PATCH | `/sources/{id}/credibility` | Update source credibility |
| GET | `/threat-actors` | List known threat actors |

## Repo Structure

```
osint-threat-monitor/
├── analytics/
│   ├── risk_scoring.py          # Multi-factor risk scoring engine
│   ├── spike_detection.py       # Keyword frequency spike detection
│   └── intelligence_report.py   # Daily intelligence report generator
├── scraper/
│   ├── rss_scraper.py           # RSS feed scraper (CISA, Krebs, BleepingComputer)
│   ├── reddit_scraper.py        # Reddit threat community scraper
│   └── pastebin_monitor.py      # Pastebin archive monitor
├── api/
│   └── main.py                  # FastAPI REST API (18 endpoints)
├── dashboard/
│   └── app.py                   # Streamlit dashboard (5 tabs)
├── database/
│   ├── init_db.py               # DB init, migration, seeding
│   └── schema.sql               # SQLite schema (7 tables)
├── config/
│   └── watchlist.yaml           # Reference keyword/source config
├── run.py                       # CLI entry point
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Database Schema

| Table | Purpose |
|-------|---------|
| `sources` | Intelligence sources with credibility scores |
| `keywords` | Watchlist terms with threat weights |
| `alerts` | Matched threat alerts with risk scores |
| `alert_scores` | Score audit trail (weight breakdown per alert) |
| `keyword_frequency` | Daily keyword match counts (for spike detection) |
| `intelligence_reports` | Persisted daily analytical summaries |
| `threat_actors` | Known threat actor profiles |

## Roadmap

- [x] Multi-source scraping (RSS, Reddit, Pastebin)
- [x] SQLite database with structured schema
- [x] FastAPI REST API
- [x] Keyword matching engine with regex boundaries
- [x] Streamlit dashboard with interactive charts
- [x] Multi-factor risk scoring engine
- [x] Frequency spike detection
- [x] Daily intelligence reports with escalation recommendations
- [x] Threat actor correlation
- [x] Score audit trail
- [ ] Dark web forum integration
- [ ] PDF/CSV export for reporting
- [ ] Email/Slack alerting on critical scores
- [ ] NLP-based entity extraction
- [ ] IOC feed integration (STIX/TAXII)

## License

MIT
