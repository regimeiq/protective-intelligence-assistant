#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
#  Deterministic "clone → demo" script
#
#  Usage:
#    ./scripts/demo.sh          # init + demo + print next-step URLs
#    ./scripts/demo.sh --run    # init + demo + start API & dashboard
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "═══════════════════════════════════════════════════════════════"
echo "  Protective Intelligence Assistant — Demo Setup"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── 1. Install dependencies (if not already present) ────────────────
echo "[1/3] Checking dependencies..."
python -c "import fastapi, streamlit, aiohttp" 2>/dev/null || {
    echo "       Installing requirements..."
    pip install -q -r requirements.txt
}

# ── 2. Initialize DB + seed + load demo fixtures ────────────────────
echo "[2/3] Initializing database and loading demo fixtures..."
python run.py init
python run.py demo

# ── 3. Report results ──────────────────────────────────────────────
echo "[3/3] Done."
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Demo artifacts:"
echo "    docs/demo_daily_report.md   — EP daily intelligence report"
echo "    docs/demo_travel_brief.md   — Travel brief (San Francisco)"
echo "    docs/protectee_view.svg     — Protectee TAS view mockup"
echo "    docs/map_view.svg           — Facility/alert map mockup"
echo ""

if [[ "${1:-}" == "--run" ]]; then
    echo "  Starting API + Dashboard..."
    echo "    API:       http://localhost:8000"
    echo "    Dashboard: http://localhost:8501"
    echo "    Docs:      http://localhost:8000/docs"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    # Start API in background, dashboard in foreground
    python run.py api &
    API_PID=$!
    trap "kill $API_PID 2>/dev/null" EXIT
    sleep 2
    python run.py dashboard
else
    echo "  Next steps:"
    echo "    Terminal 1:  python run.py api        → http://localhost:8000"
    echo "    Terminal 2:  python run.py dashboard   → http://localhost:8501"
    echo "═══════════════════════════════════════════════════════════════"
fi
