#!/usr/bin/env bash
set -euo pipefail

echo "=== Smoke Test ==="

echo "1. Init database..."
python run.py init

echo "2. Run demo pack..."
python run.py demo

echo "3. Compile check..."
python -m py_compile api/main.py
python -m py_compile analytics/sitrep.py
python -m py_compile analytics/behavioral_assessment.py
python -m py_compile scraper/social_media_monitor.py
python -m py_compile database/init_db.py

echo "=== Smoke Test PASSED ==="
