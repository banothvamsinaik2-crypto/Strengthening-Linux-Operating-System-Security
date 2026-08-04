"""
Parse a Lynis report file (lynis-report.dat) into structured data.

Lynis writes a machine-readable report to /var/log/lynis-report.dat. It is a
simple key=value format, where some keys repeat (e.g. warning[]= and
suggestion[]=). This parser extracts the metrics we care about for the
dissertation:

    - hardening_index       (int, 0-100)
    - tests_performed       (int)
    - warnings              (list[str])
    - suggestions           (list[str])
    - warning_count         (int)
    - suggestion_count      (int)

Usage:
    from src.lynis_parser import parse_lynis_report
    data = parse_lynis_report("data/raw/lynis-report-baseline.dat")
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Union


def _clean(value: str) -> str:
    """Lynis encodes fields separated by '|'. Strip and tidy them."""
    return value.strip().strip("|").replace("|", " ").strip()


def parse_lynis_report(path: Union[str, Path]) -> Dict:
    """Read a Lynis .dat report and return a dict of structured metrics."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Lynis report not found: {path}")

    result: Dict[str, object] = {
        "hardening_index": None,
        "tests_performed": None,
        "warnings": [],
        "suggestions": [],
        "lynis_version": None,
        "os": None,
    }

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            if key == "hardening_index":
                result["hardening_index"] = _to_int(value)
            elif key == "lynis_version":
                result["lynis_version"] = value
            elif key == "os_fullname":
                result["os"] = value
            elif key == "tests_executed":
                # tests_executed is a long pipe-separated list; count entries
                result["tests_performed"] = len(
                    [t for t in value.split("|") if t.strip()]
                )
            elif key.startswith("warning[]"):
                result["warnings"].append(_clean(value))
            elif key.startswith("suggestion[]"):
                result["suggestions"].append(_clean(value))

    result["warning_count"] = len(result["warnings"])
    result["suggestion_count"] = len(result["suggestions"])
    return result


def _to_int(value: str):
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m src.lynis_parser <path-to-report.dat>")
        raise SystemExit(1)
    print(json.dumps(parse_lynis_report(sys.argv[1]), indent=2))
