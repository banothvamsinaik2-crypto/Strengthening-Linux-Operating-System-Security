"""
Compare baseline and hardened scan results and compute the improvement.

This module ties the two parsers together. It loads the Lynis and OpenSCAP
reports for both phases (baseline and hardened), builds a single structured
comparison, and saves it as JSON so it can be reused by the visualiser and
cited directly in the dissertation.

The comparison is the core experimental result of the project: it expresses,
in numbers, how much the system improved.

Usage:
    from src.analysis import build_comparison, save_comparison
    comp = build_comparison(lynis_base, lynis_hard, scap_base, scap_hard)
    save_comparison(comp)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from src import config


def _delta(before, after):
    """Return after - before when both are numbers, else None."""
    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
        return round(after - before, 1)
    return None


def build_comparison(
    lynis_base: Dict,
    lynis_hard: Dict,
    scap_base: Dict,
    scap_hard: Dict,
) -> Dict:
    """Assemble a structured before/after comparison from parsed reports."""
    li_b = lynis_base.get("hardening_index")
    li_h = lynis_hard.get("hardening_index")
    comp_b = scap_base.get("compliance_percent")
    comp_h = scap_hard.get("compliance_percent")

    comparison = {
        "lynis": {
            "hardening_index": {
                "baseline": li_b,
                "hardened": li_h,
                "delta": _delta(li_b, li_h),
            },
            "warnings": {
                "baseline": lynis_base.get("warning_count"),
                "hardened": lynis_hard.get("warning_count"),
                "delta": _delta(lynis_base.get("warning_count"),
                                lynis_hard.get("warning_count")),
            },
            "suggestions": {
                "baseline": lynis_base.get("suggestion_count"),
                "hardened": lynis_hard.get("suggestion_count"),
                "delta": _delta(lynis_base.get("suggestion_count"),
                                lynis_hard.get("suggestion_count")),
            },
        },
        "openscap": {
            "compliance_percent": {
                "baseline": comp_b,
                "hardened": comp_h,
                "delta": _delta(comp_b, comp_h),
            },
            "passed": {
                "baseline": scap_base.get("passed"),
                "hardened": scap_hard.get("passed"),
                "delta": _delta(scap_base.get("passed"), scap_hard.get("passed")),
            },
            "failed": {
                "baseline": scap_base.get("failed"),
                "hardened": scap_hard.get("failed"),
                "delta": _delta(scap_base.get("failed"), scap_hard.get("failed")),
            },
            "fail_by_severity": {
                "baseline": scap_base.get("fail_by_severity", {}),
                "hardened": scap_hard.get("fail_by_severity", {}),
            },
        },
    }
    comparison["summary"] = _summarise(comparison)
    return comparison


def _summarise(c: Dict) -> Dict:
    """Produce a few plain-English headline numbers for the report."""
    li = c["lynis"]["hardening_index"]
    sc = c["openscap"]["compliance_percent"]
    warn = c["lynis"]["warnings"]
    return {
        "lynis_index_gain": li["delta"],
        "openscap_compliance_gain": sc["delta"],
        "warnings_resolved": (
            -warn["delta"] if isinstance(warn["delta"], (int, float)) else None
        ),
        "headline": _headline(li, sc),
    }


def _headline(li: Dict, sc: Dict) -> str:
    parts = []
    if li["baseline"] is not None and li["hardened"] is not None:
        parts.append(
            f"Lynis hardening index rose from {li['baseline']} to "
            f"{li['hardened']} (+{li['delta']})."
        )
    if sc["baseline"] is not None and sc["hardened"] is not None:
        parts.append(
            f"OpenSCAP CIS compliance rose from {sc['baseline']}% to "
            f"{sc['hardened']}% (+{sc['delta']} points)."
        )
    return " ".join(parts) if parts else "No comparable metrics were found."


def save_comparison(comparison: Dict, path: Path = None) -> Path:
    """Write the comparison dict to JSON and return the path."""
    path = path or (config.DATA_PROCESSED / "comparison.json")
    path.write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    return path
