#!/usr/bin/env bash
#
# 02_run_openscap.sh - Run an OpenSCAP evaluation against the CIS benchmark
# and save the results XML.
#
# Usage:
#   sudo bash scripts/02_run_openscap.sh baseline
#   sudo bash scripts/02_run_openscap.sh hardened
#
# NOTE ON UBUNTU 22.04:
# The older ssg-debderived / ssg-base packages are NOT available in the
# standard 22.04 repositories. This script therefore installs the OpenSCAP
# scanner (libopenscap8) and downloads the official SCAP Security Guide
# content (which contains the CIS Ubuntu 22.04 datastream) directly from the
# ComplianceAsCode GitHub release. This is the method that works reliably.
#
set -euo pipefail

PHASE="${1:-baseline}"
if [[ "$PHASE" != "baseline" && "$PHASE" != "hardened" ]]; then
  echo "Usage: sudo bash $0 [baseline|hardened]"
  exit 1
fi

OUT_DIR="${OUT_DIR:-$HOME/hardening-data}"
mkdir -p "$OUT_DIR"

SSG_VERSION="0.1.73"
SSG_DIR="$HOME/scap-security-guide-${SSG_VERSION}"
SSG_ZIP="$HOME/scap-security-guide-${SSG_VERSION}.zip"
SSG_URL="https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip"

echo "[*] Ensuring the OpenSCAP scanner is installed..."
if ! command -v oscap >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y libopenscap8 unzip wget
fi

echo "[*] Ensuring SCAP content is present..."
if [[ ! -d "$SSG_DIR" ]]; then
  if [[ ! -f "$SSG_ZIP" ]]; then
    echo "[*] Downloading SCAP Security Guide ${SSG_VERSION} (~160 MB)..."
    wget -q "$SSG_URL" -O "$SSG_ZIP"
  fi
  echo "[*] Unzipping SCAP content..."
  unzip -q "$SSG_ZIP" -d "$HOME"
fi

DS="$(find "$SSG_DIR" -name 'ssg-ubuntu2204-ds.xml' 2>/dev/null | head -n1 || true)"
if [[ -z "$DS" ]]; then
  echo "[!] Could not find ssg-ubuntu2204-ds.xml under $SSG_DIR"
  exit 1
fi
echo "[+] Using SCAP datastream: $DS"

PROFILE="${PROFILE:-cis_level1_server}"
RESULTS="$OUT_DIR/openscap-results-$PHASE.xml"
REPORT_HTML="$OUT_DIR/openscap-report-$PHASE.html"

echo "[*] Running OpenSCAP evaluation (phase: $PHASE, profile: $PROFILE)..."
oscap xccdf eval \
  --profile "$PROFILE" \
  --results-arf "$RESULTS" \
  --report "$REPORT_HTML" \
  "$DS" || true

if [[ ! -f "$RESULTS" ]]; then
  echo "[!] Results file was not produced: $RESULTS"
  exit 1
fi

echo "[+] Saved OpenSCAP results to : $RESULTS"
echo "[+] Saved human-readable report: $REPORT_HTML"
