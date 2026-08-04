"""Central configuration: paths and constants used across the pipeline."""
from pathlib import Path

# Project root = parent of the src/ directory
ROOT = Path(__file__).resolve().parent.parent

DATA_RAW = ROOT / "data" / "raw"
DATA_PROCESSED = ROOT / "data" / "processed"
SAMPLE_REPORTS = ROOT / "sample_reports"
FIGURES = ROOT / "results" / "figures"

# Expected report filenames for the real workflow.
# Phase is either "baseline" (before hardening) or "hardened" (after).
LYNIS_REPORT = "lynis-report-{phase}.dat"
OPENSCAP_REPORT = "openscap-results-{phase}.xml"

PHASES = ("baseline", "hardened")

# Ensure output dirs exist when the module is imported.
for _d in (DATA_PROCESSED, FIGURES):
    _d.mkdir(parents=True, exist_ok=True)
