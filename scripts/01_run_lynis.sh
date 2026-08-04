#!/usr/bin/env bash
#
# 01_run_lynis.sh - Run a Lynis system audit and save the report.
#
# Usage:
#   sudo bash scripts/01_run_lynis.sh baseline
#   sudo bash scripts/01_run_lynis.sh hardened
#
# The phase argument ("baseline" or "hardened") is used to name the saved
# report so the analysis pipeline can find it.
#
# Lynis is read-only: it never changes the system, it only audits it.
#
set -euo pipefail

PHASE="${1:-baseline}"
if [[ "$PHASE" != "baseline" && "$PHASE" != "hardened" ]]; then
  echo "Usage: sudo bash $0 [baseline|hardened]"
  exit 1
fi

# Directory to collect reports (created if missing).
OUT_DIR="${OUT_DIR:-$HOME/hardening-data}"
mkdir -p "$OUT_DIR"

echo "[*] Ensuring Lynis is installed..."
if ! command -v lynis >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y lynis
fi

echo "[*] Running Lynis audit (phase: $PHASE)..."
# --quiet reduces interactive output; the machine-readable report is what we use.
lynis audit system --quiet || true

# Lynis writes its machine-readable report here by default.
SRC="/var/log/lynis-report.dat"
DEST="$OUT_DIR/lynis-report-$PHASE.dat"

if [[ ! -f "$SRC" ]]; then
  echo "[!] Expected report not found at $SRC"
  exit 1
fi

cp "$SRC" "$DEST"
echo "[+] Saved Lynis report to: $DEST"

# Print the headline index for immediate feedback.
INDEX="$(grep -E '^hardening_index=' "$DEST" | cut -d'=' -f2 || echo '?')"
echo "[+] Hardening index (this phase): $INDEX"
