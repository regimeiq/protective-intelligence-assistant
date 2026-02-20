## Overview

Open-source threat intelligence monitoring tool that scrapes public feeds for keyword-matched threat indicators, stores structured alerts in a database, and serves results through a REST API and interactive dashboard.

Built for security analysts and threat intelligence teams who need automated, centralized monitoring across multiple open-source channels.

## Features

- **Multi-source scraping** — RSS feeds (CISA, BleepingComputer, Krebs on Security), Reddit, Pastebin, and social media monitoring
- **Keyword watchlists** — configurable threat indicators, actor names, and IOCs for targeted alerting
- **REST API (FastAPI)** — endpoints for managing watchlists, retrieving alerts, and querying threat data
- **SQLite database** — structured storage for sources, keywords, alerts, and threat actors with full timestamps
- **Streamlit dashboard** — alert triage view, keyword hit frequency, source breakdown, and trend analysis
- **Dockerized** — single `docker-compose up` to run the full stack

## Tech Stack

| Layer | Tool |
|-------|------|
| Scraping | BeautifulSoup, Selenium, Feedparser |
| API | FastAPI |
| Database | SQLite |
| Dashboard | Streamlit |
| Container | Docker, docker-compose |
| Language | Python 3.11+ |

## Architecture

```
[RSS/Reddit/Pastebin/Social] → Scraper → Database → API → Dashboard
                                           ↑
                                    Keyword Watchlist
```

## Quickstart

```bash
git clone https://github.com/RegimeIQ/osint-threat-monitor.git
cd osint-threat-monitor
docker-compose up
```

- API: `http://localhost:8000/docs`
- Dashboard: `http://localhost:8501`

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/alerts` | Retrieve matched threat alerts |
| GET | `/alerts/summary` | Aggregated alert data for dashboard |
| POST | `/keywords` | Add keywords to watchlist |
| DELETE | `/keywords/{id}` | Remove keyword from watchlist |
| GET | `/sources` | List active intelligence sources |

## Repo Structure

```
osint-threat-monitor/
├── scraper/
│   ├── rss_scraper.py
│   ├── reddit_scraper.py
│   ├── pastebin_monitor.py
│   └── social_scraper.py
├── api/
│   ├── main.py
│   └── models.py
├── dashboard/
│   └── app.py
├── database/
│   ├── init_db.py
│   └── schema.sql
├── config/
│   └── watchlist.yaml
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Configuration

Edit `config/watchlist.yaml` to define monitoring parameters:

```yaml
keywords:
  - "threat actor"
  - "data breach"
  - "ransomware"
  - "credential leak"

sources:
  rss:
    - https://www.cisa.gov/news.xml
    - https://krebsonsecurity.com/feed/
    - https://www.bleepingcomputer.com/feed/
  reddit:
    - cybersecurity
    - netsec
    - threatintel
```

## Roadmap

- [ ] Scraper layer — RSS, Reddit, Pastebin
- [ ] Database schema and init
- [ ] FastAPI endpoints
- [ ] Keyword matching engine
- [ ] Streamlit dashboard
- [ ] Docker containerization
- [ ] Social media monitoring
- [ ] Alert severity scoring
- [ ] Dark web forum integration
- [ ] Export to PDF/CSV for reporting

## License

MIT
