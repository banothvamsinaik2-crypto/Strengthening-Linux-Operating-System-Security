"""
Main entry point for the OS hardening analysis pipeline.

Two modes:

    python -m src.main --demo
        Run the full pipeline on the bundled sample reports. No VM required.
        Useful for development and for demonstrating the tool in a viva.

    python -m src.main --analyze
        Run on the *real* reports you collected from the VM, expected in
        data/raw/ with these filenames:
            lynis-report-baseline.dat
            lynis-report-hardened.dat
            openscap-results-baseline.xml
            openscap-results-hardened.xml

Both modes parse the reports, build the before/after comparison, save it as
JSON, generate the charts, and print a plain-English summary.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src import config
from src.lynis_parser import parse_lynis_report
from src.openscap_parser import parse_openscap_report
from src.analysis import build_comparison, save_comparison
from src.visualize import generate_all


def _resolve(source_dir: Path):
    """Return the four expected report paths inside source_dir."""
    return {
        "lynis_base": source_dir / "lynis-report-baseline.dat",
        "lynis_hard": source_dir / "lynis-report-hardened.dat",
        "scap_base": source_dir / "openscap-results-baseline.xml",
        "scap_hard": source_dir / "openscap-results-hardened.xml",
    }


def run(source_dir: Path) -> int:
    paths = _resolve(source_dir)

    missing = [str(p) for p in paths.values() if not p.exists()]
    if missing:
        print("ERROR: the following report files were not found:")
        for m in missing:
            print(f"  - {m}")
        print("\nMake sure all four reports are present, or run with --demo.")
        return 1

    print(f"Reading reports from: {source_dir}\n")
    lynis_base = parse_lynis_report(paths["lynis_base"])
    lynis_hard = parse_lynis_report(paths["lynis_hard"])
    scap_base = parse_openscap_report(paths["scap_base"])
    scap_hard = parse_openscap_report(paths["scap_hard"])

    comparison = build_comparison(lynis_base, lynis_hard, scap_base, scap_hard)
    json_path = save_comparison(comparison)
    figures = generate_all(comparison)

    print("=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    print(comparison["summary"]["headline"])
    s = comparison["summary"]
    print(f"\n  Lynis index gain        : +{s['lynis_index_gain']}")
    print(f"  OpenSCAP compliance gain: +{s['openscap_compliance_gain']} points")
    print(f"  Warnings resolved       : {s['warnings_resolved']}")
    print("=" * 60)
    print(f"\nComparison JSON : {json_path}")
    print("Figures written :")
    for f in figures:
        print(f"  - {f}")
    print("\nDone.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="OS hardening before/after analysis pipeline.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--demo", action="store_true",
                       help="Run on bundled sample reports (no VM needed).")
    group.add_argument("--analyze", action="store_true",
                       help="Run on real reports in data/raw/.")
    args = parser.parse_args(argv)

    # Default to demo if nothing specified, for a friendly first run.
    source = config.SAMPLE_REPORTS if (args.demo or not args.analyze) \
        else config.DATA_RAW
    return run(source)


if __name__ == "__main__":
    sys.exit(main())
