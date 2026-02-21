#!/usr/bin/env bash
set -euo pipefail

python run.py init
python run.py scrape
python -m py_compile api/main.py dashboard/app.py

echo "Smoke test passed."
