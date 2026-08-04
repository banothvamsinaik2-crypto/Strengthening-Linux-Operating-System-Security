# OS Hardening and Vulnerability Assessment via Benchmarking and Lynis

MSc Cybersecurity Dissertation Project

This project hardens an **Ubuntu Server 22.04 LTS** system against the **CIS
Benchmark**, audits the system **before and after** hardening using **Lynis**
and **OpenSCAP**, and quantifies the security improvement using a Python
analysis pipeline.

> New here? Read **PROJECT_GUIDE.pdf** first — it explains the whole project in
> plain English and walks through how to run everything step by step.

## Headline result (real experiment)

| Metric | Baseline | Hardened | Change |
|--------|----------|----------|--------|
| Lynis Hardening Index (0–100) | 56 | 66 | +10 |
| OpenSCAP CIS Compliance | 56.2% | 69.8% | +13.6 pts |
| OpenSCAP rules passed | 132 | 169 | +37 |
| OpenSCAP rules failed | 103 | 73 | −30 |

The reports that produced these numbers are included in `data/raw/`, so the
analysis below is fully reproducible out of the box.

## What this project measures

| Metric | Source | Meaning |
|--------|--------|---------|
| Lynis Hardening Index (0–100) | Lynis | Overall system hardening score |
| Lynis warnings / suggestions | Lynis | Count of issues to fix |
| OpenSCAP pass/fail rules | OpenSCAP + CIS SCAP content | Benchmark compliance % |
| Severity breakdown | OpenSCAP | High/Medium/Low failed rules |

The core experimental result is the **delta** between a baseline scan and a
post-hardening scan.

## Repository layout

```
project/
├── README.md
├── PROJECT_GUIDE.pdf             # Plain-English guide — read this first
├── requirements.txt
├── scripts/
│   ├── 01_run_lynis.sh         # Run Lynis audit, save report
│   ├── 02_run_openscap.sh      # Run OpenSCAP CIS scan, save report
│   └── 03_harden.sh            # Apply CIS-aligned hardening controls
├── src/
│   ├── config.py               # Paths and constants
│   ├── lynis_parser.py         # Parse lynis .dat report -> structured data
│   ├── openscap_parser.py      # Parse OpenSCAP ARF/XML -> structured data
│   ├── analysis.py             # Before/after comparison + metrics
│   ├── visualize.py            # Generate charts
│   └── main.py                 # Orchestrator / CLI entry point
├── sample_reports/             # Synthetic before/after reports for demo
├── data/
│   ├── raw/                    # REAL reports from the experiment live here
│   └── processed/              # Parsed JSON output
└── results/
    └── figures/                # Generated charts
```

## Quick start — reproduce the real results (no VM needed)

The real scan reports are already in `data/raw/`. To regenerate the metrics
and charts from them:

```bash
pip install -r requirements.txt
python -m src.main --analyze
```

Output: `data/processed/comparison.json` plus four charts in
`results/figures/`.

To instead run on the bundled synthetic demo reports (placeholder numbers, not
the real experiment):

```bash
python -m src.main --demo
```

## Full workflow — run your own experiment on a VM

You need your own Ubuntu Server 22.04 VM for this part. PROJECT_GUIDE.pdf has the
detailed walkthrough; the short version:

1. Set up an Ubuntu Server 22.04 LTS VM in VirtualBox (2 GB RAM, 2 CPU, 25 GB
   disk, install OpenSSH server). Take a snapshot called `baseline-clean`.
2. Get this project onto the VM (a VirtualBox **Shared Folder** is the easiest
   way — copy/paste into the VM often does not work).
3. Baseline scans:
   ```bash
   sudo bash scripts/01_run_lynis.sh baseline
   sudo bash scripts/02_run_openscap.sh baseline
   ```
4. Apply hardening:
   ```bash
   sudo bash scripts/03_harden.sh
   ```
5. Post-hardening scans:
   ```bash
   sudo bash scripts/01_run_lynis.sh hardened
   sudo bash scripts/02_run_openscap.sh hardened
   ```
6. Copy the four reports into `data/raw/`, then run the analysis:
   ```bash
   python -m src.main --analyze
   ```

### Practical tips (save yourself time)

- **OpenSCAP content**: `02_run_openscap.sh` downloads the CIS SCAP content
  (~160 MB) straight from GitHub on first run. The old `ssg-debderived` /
  `ssg-base` apt packages do **not** exist on Ubuntu 22.04 — this script
  deliberately avoids them.
- **Tilde key**: if `~` types the wrong character on your keyboard, use
  `$HOME` instead (e.g. `cd $HOME/hardening-data`). The scripts already use
  `$HOME` throughout.
- **Reports land in** `$HOME/hardening-data/` (and Lynis also writes to
  `/var/log` / `/root` when run with sudo). Check the script output for the
  exact saved path.

## Requirements

- Python 3.8+ with `pandas` and `matplotlib` (`pip install -r requirements.txt`)
- For the VM experiment: Ubuntu Server 22.04 LTS, `lynis`, `libopenscap8`

## Author

[Your Name] — MSc Cybersecurity, University of Roehampton London
