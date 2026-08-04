"""
Parse an OpenSCAP results file into structured data.

When OpenSCAP evaluates a system against SCAP content (e.g. a CIS profile) using

    oscap xccdf eval --results-arf openscap-results.xml ...

it produces an XML results document containing one <rule-result> per rule, each
with a <result> element whose text is "pass", "fail", "notapplicable", etc.,
and an associated severity ("high", "medium", "low", "unknown").

This parser counts those results so we can compute a compliance percentage and a
severity breakdown of the failures, which is the OpenSCAP side of the
before/after comparison.

It is namespace-agnostic: SCAP XML uses several XCCDF namespaces across versions,
so we match on the *local* tag name rather than the fully-qualified name. This
keeps the parser working across OpenSCAP / content versions.

Usage:
    from src.openscap_parser import parse_openscap_report
    data = parse_openscap_report("data/raw/openscap-results-baseline.xml")
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Dict, Union

# Results that count as "scored" for the compliance percentage.
# notapplicable / notchecked / informational are excluded from the denominator,
# mirroring how OpenSCAP itself reports a score.
_PASS = {"pass", "fixed"}
_FAIL = {"fail", "error"}
_IGNORE = {"notapplicable", "notchecked", "notselected", "informational", "unknown"}


def _local(tag: str) -> str:
    """Strip the XML namespace from a tag, returning the local name."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_openscap_report(path: Union[str, Path]) -> Dict:
    """Read an OpenSCAP results XML file and return structured metrics."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"OpenSCAP report not found: {path}")

    tree = ET.parse(path)
    root = tree.getroot()

    passed = failed = other = 0
    fail_by_severity: Counter = Counter()
    pass_by_severity: Counter = Counter()

    for elem in root.iter():
        if _local(elem.tag) != "rule-result":
            continue
        severity = (elem.get("severity") or "unknown").lower()

        result_text = None
        for child in elem:
            if _local(child.tag) == "result":
                result_text = (child.text or "").strip().lower()
                break
        if result_text is None:
            continue

        if result_text in _PASS:
            passed += 1
            pass_by_severity[severity] += 1
        elif result_text in _FAIL:
            failed += 1
            fail_by_severity[severity] += 1
        else:
            other += 1

    scored = passed + failed
    compliance = round((passed / scored) * 100, 1) if scored else 0.0

    return {
        "passed": passed,
        "failed": failed,
        "not_applicable": other,
        "total_scored": scored,
        "compliance_percent": compliance,
        "fail_by_severity": dict(fail_by_severity),
        "pass_by_severity": dict(pass_by_severity),
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m src.openscap_parser <path-to-results.xml>")
        raise SystemExit(1)
    print(json.dumps(parse_openscap_report(sys.argv[1]), indent=2))
