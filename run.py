"""
OSINT Threat Monitor - Entry Point

Usage:
    python run.py init        Initialize database with default sources and keywords
    python run.py scrape      Run all scrapers
    python run.py api         Start FastAPI server
    python run.py dashboard   Start Streamlit dashboard
    python run.py all         Start API + Dashboard (requires separate terminal for each)
"""

import sys
import subprocess
from database.init_db import init_db, seed_default_sources, seed_default_keywords
from scraper import run_all_scrapers


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1].lower()

    if command == "init":
        init_db()
        seed_default_sources()
        seed_default_keywords()

    elif command == "scrape":
        init_db()
        run_all_scrapers()

    elif command == "api":
        init_db()
        subprocess.run(
            ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
        )

    elif command == "dashboard":
        subprocess.run(
            ["streamlit", "run", "dashboard/app.py", "--server.port", "8501"]
        )

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
