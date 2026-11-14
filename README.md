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

## Weekly and daily updates on project

**Week 1**
Read around the subject and settled on the topic. Agreed with my supervisor that I would focus on hardening a Linux server and, more importantly, on measuring the result properly rather than just describing the settings I had changed. 
**Week 2**
Searched for sources and pulled together around twenty five papers on Linux hardening, the CIS Benchmarks and SCAP, and started building the reference list. I noticed early on that almost every study relied on a single tool.
**Week 3**
Wrote the proposal. Set out the aim, the objectives and three research questions. Cut the scope down to CIS Level 1 on one Ubuntu Server so that it was realistic in the time I had available. The project ran over twelve weeks. I kept this record as I went along so that I could see whether I was keeping pace with my plan. What follows is what I actually worked on each week rather than what I had first intended, and a few of the weeks ran over. Week What I worked on Week 1 Read around the subject and settled on the topic. Agreed with my supervisor that I would focus on hardening a Linux server and, more importantly, on measuring the result properly rather than just describing the settings I had changed. Week 2 Searched for sources and pulled together around twenty five papers on Linux hardening, the CIS Benchmarks and SCAP, and started building the reference list. I noticed early on that almost every study relied on a single tool. Week 3 Wrote the proposal. Set out the aim, the objectives and three research questions. Cut the scope down to CIS Level 1 on one Ubuntu Server so that it was realistic in the time I had available.
**Week 4**
Drafted the literature review and built a table comparing the main studies side by side. Laying them out that way made the gap obvious: hardly any of them used two independent tools, and very few published a method that somebody else could repeat.
**Week 5**
Built the lab. Installed VirtualBox and set up an Ubuntu Server 22.04 machine with 2 GB of memory, two processors and a 25 GB disk. Saved a snapshot called baseline-clean so that I could always return to the same starting point.
**Week 6**
Installed Lynis and OpenSCAP and spent the week learning how to use them properly. The CIS content was the awkward part, because the apt packages do not exist for 22.04, so I downloaded the rule file from the ComplianceAsCode project instead. I also prepared for the mid point review.
**Week 7**
Ran the baseline scans on the clean system. Lynis returned a hardening index of 56, and OpenSCAP reported 56.2 per cent compliance with 132 rules passing and 103 failing. Saved both reports untouched so they could not be altered later.
**Week 8**
Wrote the hardening script in Bash. Most of my time went on the safety side of it: the script backs up every file before it changes anything, and it tests the SSH configuration before restarting the service, so that one mistake cannot lock me out of the machine. 
**Week 9**
Applied the hardening and scanned the system again. Lynis rose to 66 and compliance to 69.8 per cent, with failures falling from 103 to 73. I then went through the rules that still failed so that I could explain in the report why they were still there. 
**Week 10**
Built the Python pipeline, mainly so that I was not copying numbers out by hand and making mistakes. It reads both reports, works out the difference between before and after, and produces the tables and charts on its own. 
**Week 11**
Wrote the methodology, implementation and results chapters. Placed the charts into the text and checked that every figure I quoted matched what was actually recorded in the saved reports. 
**Week 12**
Finished the discussion and conclusion, tidied the reference list, sorted out the contents pages and the formatting, read the whole report through and submitted it.

**Part 2 — Revision and updated version**

After discussing the report with my supervisor, she asked me to strengthen a number of areas in it. Rather than only rewriting the text, I decided to set the whole experiment up again from scratch, so that I could add further screenshots as supporting evidence and satisfy myself that the results repeated. The six days below cover that work. 
**Tue 27 Oct**
Went through each of the points I had been asked to address and wrote them out on paper so that I could see them all together. Decided to redo the experiment from scratch rather than simply edit the writing. Downloaded VirtualBox and the Ubuntu image that evening, ready to start the next morning. 
**Wed 28 Oct**
Rebuilt the virtual machine from nothing. Windows blocked the installer at first and I had to turn off Smart App Control, and the first boot appeared to freeze on the network adapter line until I reset it. Ended the day with a clean system and a fresh snapshot. 
**Thu 29 Oct**
Installed both tools again and downloaded the CIS content, then ran the baseline scans. Lynis came back as 56 and OpenSCAP as 56.2 per cent, the same as the first time, which was a relief. Took clear screenshots of every result as I went. 
**Fri 30 Oct**
Ran the hardening script and scanned the system again. 66 and 69.8 per cent, matching the original figures. Captured the after screenshots so that every measurement had a before and after pair I could point to in the report.
**Sat 31 Oct**
Spent the day on the writing. Added clear research questions, a section on why the work matters and who benefits from it, the reasoning behind using two tools instead of one, a summary of the literature with a comparison table, the case for the Python pipeline, an explanation of the metrics, the purpose of the Bash scripts with a sample, and an explanation of the hardening index and CIS compliance.
**Sun 1 Nov**
Added the extra screenshots into the report as supporting evidence, with a short note under each one, and collected the full set together in an appendix. Renumbered the tables, corrected the contents, list of figures and list of tables, then read the report through one last time.


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

Vamsi Naik Banoth — MSc Cybersecurity, University of Roehampton London
