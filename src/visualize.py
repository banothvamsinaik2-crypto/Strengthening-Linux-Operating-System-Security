"""
Generate charts from the before/after comparison.

Produces four figures saved as PNGs into results/figures/:

    1. lynis_index.png        - Lynis hardening index, baseline vs hardened
    2. openscap_compliance.png- OpenSCAP CIS compliance %, baseline vs hardened
    3. lynis_findings.png     - Warnings & suggestions, baseline vs hardened
    4. severity_breakdown.png - Failed rules by severity, baseline vs hardened

The styling is deliberately clean and print-friendly so the figures can be
dropped straight into the dissertation.

Usage:
    from src.visualize import generate_all
    paths = generate_all(comparison)
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")  # headless backend; no display needed
import matplotlib.pyplot as plt

from src import config

# University-of-Roehampton-ish palette: green baseline-to-hardened story.
BASELINE_COLOR = "#C0504D"   # muted red  = "before / weaker"
HARDENED_COLOR = "#0A5C36"   # green       = "after / stronger"
GRID_COLOR = "#DDDDDD"


def _style(ax):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.yaxis.grid(True, color=GRID_COLOR, linewidth=0.8)
    ax.set_axisbelow(True)


def _annotate_bars(ax, bars):
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f"{height:g}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", va="bottom", fontsize=10, fontweight="bold")


def _paired_bar(title, ylabel, baseline, hardened, filename, ymax=None):
    fig, ax = plt.subplots(figsize=(6, 4.2))
    bars = ax.bar(["Baseline", "Hardened"], [baseline, hardened],
                  color=[BASELINE_COLOR, HARDENED_COLOR], width=0.55)
    _annotate_bars(ax, bars)
    _style(ax)
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    ax.set_ylabel(ylabel, fontsize=11)
    if ymax:
        ax.set_ylim(0, ymax)
    fig.tight_layout()
    path = config.FIGURES / filename
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _grouped_bar(title, categories, baseline_vals, hardened_vals, filename):
    import numpy as np
    x = np.arange(len(categories))
    width = 0.38
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    b1 = ax.bar(x - width / 2, baseline_vals, width, label="Baseline",
                color=BASELINE_COLOR)
    b2 = ax.bar(x + width / 2, hardened_vals, width, label="Hardened",
                color=HARDENED_COLOR)
    _annotate_bars(ax, b1)
    _annotate_bars(ax, b2)
    _style(ax)
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend(frameon=False)
    fig.tight_layout()
    path = config.FIGURES / filename
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def generate_all(comparison: Dict) -> List[Path]:
    """Generate every figure and return the list of written paths."""
    paths = []

    li = comparison["lynis"]["hardening_index"]
    paths.append(_paired_bar(
        "Lynis Hardening Index", "Index (0\u2013100)",
        li["baseline"], li["hardened"], "lynis_index.png", ymax=100))

    sc = comparison["openscap"]["compliance_percent"]
    paths.append(_paired_bar(
        "OpenSCAP CIS Compliance", "Compliance (%)",
        sc["baseline"], sc["hardened"], "openscap_compliance.png", ymax=100))

    warn = comparison["lynis"]["warnings"]
    sugg = comparison["lynis"]["suggestions"]
    paths.append(_grouped_bar(
        "Lynis Findings", ["Warnings", "Suggestions"],
        [warn["baseline"], sugg["baseline"]],
        [warn["hardened"], sugg["hardened"]],
        "lynis_findings.png"))

    sev_b = comparison["openscap"]["fail_by_severity"]["baseline"]
    sev_h = comparison["openscap"]["fail_by_severity"]["hardened"]
    order = ["high", "medium", "low"]
    labels = [s.capitalize() for s in order]
    paths.append(_grouped_bar(
        "OpenSCAP Failed Rules by Severity", labels,
        [sev_b.get(s, 0) for s in order],
        [sev_h.get(s, 0) for s in order],
        "severity_breakdown.png"))

    return paths
