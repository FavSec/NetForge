#!/bin/bash
# NetForge launcher — run from the netforge/ project directory
# Usage: ./start.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/venv"
SERVER="$SCRIPT_DIR/server.py"

# First-run setup
if [ ! -d "$VENV" ]; then
  echo "⚙  First run — creating virtual environment..."
  python3 -m venv "$VENV"
  source "$VENV/bin/activate"
  echo "📦 Installing dependencies (flask, flask-cors, scapy)..."
  pip install -q flask flask-cors scapy
  echo "✅ Setup complete."
else
  source "$VENV/bin/activate"
fi

# Kill any stale process on 5050
if lsof -ti:5050 &>/dev/null; then
  echo "🔄 Port 5050 in use — restarting..."
  kill "$(lsof -ti:5050)" 2>/dev/null
  sleep 0.5
fi

echo ""
echo "┌──────────────────────────────────────────┐"
echo "│  NetForge backend  →  http://localhost:5050  │"
echo "│  Press Ctrl+C to stop                    │"
echo "└──────────────────────────────────────────┘"
echo ""

python3 "$SERVER"
