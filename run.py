"""
OSINT Threat Monitor - Entry Point

Usage:
    python run.py init        Initialize DB and seed from config/watchlist.yaml (fallback defaults)
    python run.py scrape      Run all scrapers
    python run.py api         Start FastAPI server
    python run.py dashboard   Start Streamlit dashboard
    python run.py purge       Purge raw content older than retention window
    python run.py demo        Load fixtures and generate demo EP artifacts
    python run.py all         Start API + Dashboard (requires separate terminal for each)
"""

import subprocess
import sys

from database.init_db import (
    init_db,
    migrate_schema,
    purge_raw_content,
    seed_default_events,
    seed_default_keywords,
    seed_default_pois,
    seed_default_protected_locations,
    seed_default_sources,
    seed_threat_actors,
)
from scraper import run_all_scrapers


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1].lower()

    if command == "init":
        init_db()
        migrate_schema()
        seed_default_sources()
        seed_default_keywords()
        seed_default_pois()
        seed_default_protected_locations()
        seed_default_events()
        seed_threat_actors()

    elif command == "scrape":
        init_db()
        migrate_schema()
        run_all_scrapers()

    elif command == "api":
        init_db()
        migrate_schema()
        subprocess.run(
            ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
        )

    elif command == "dashboard":
        subprocess.run(["streamlit", "run", "dashboard/app.py", "--server.port", "8501"])

    elif command == "purge":
        init_db()
        migrate_schema()
        purge_raw_content()

    elif command == "demo":
        from analytics.demo_pack import run_demo_pack

        init_db()
        migrate_schema()
        seed_default_sources()
        seed_default_keywords()
        seed_default_pois()
        seed_default_protected_locations()
        seed_default_events()
        seed_threat_actors()
        result = run_demo_pack()
        print("Demo artifacts generated:")
        print(f"  - {result['report_path']}")
        print(f"  - {result['brief_path']}")

    elif command == "all":
        print("Run in separate terminals:")
        print("  Terminal 1: python run.py api")
        print("  Terminal 2: python run.py dashboard")
        print("\nOr use: docker compose up")

    else:
        print(f"Unknown command: {command}")
        print(__doc__)


if __name__ == "__main__":
    main()
