"""
Generate realistic sample reports so the pipeline can be run end-to-end
without a VM. These mimic the structure of genuine Lynis .dat and OpenSCAP
ARF XML files closely enough that the real parsers handle them unchanged.

Numbers are chosen to reflect typical real-world outcomes reported in the
literature: a baseline Lynis index around 57 rising to ~82 after CIS Level 1
hardening, and OpenSCAP CIS compliance rising from roughly 40% to ~78%.

Run:  python sample_reports/make_samples.py
"""
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---- Lynis sample .dat ---------------------------------------------------
LYNIS_WARNINGS_BASE = [
    "AUTH-9286|User accounts with suggested password aging|",
    "SSH-7408|SSH root login is permitted|",
    "FIRE-4512|iptables module(s) loaded, but no rules active|",
    "KRNL-5820|core dumps are not restricted|",
    "LOGG-2154|auditd is not enabled|",
]
LYNIS_SUGGESTIONS_BASE = [
    "BOOT-5122|Set a password on the GRUB bootloader|",
    "AUTH-9230|Configure password hashing rounds|",
    "AUTH-9262|Install a PAM module for password strength testing|",
    "SSH-7408|Harden SSH configuration (MaxAuthTries, X11Forwarding)|",
    "NETW-3200|Disable uncommon network protocols|",
    "KRNL-6000|Adjust sysctl values for kernel hardening|",
    "FILE-6310|Mount /tmp with noexec,nosuid,nodev|",
    "FIRE-4513|Enable a host-based firewall|",
    "HRDN-7220|Install a malware scanner|",
    "ACCT-9622|Enable process accounting|",
    "TIME-3104|Configure an NTP/chrony time source|",
    "PKGS-7370|Install a package audit tool (debsums)|",
]
LYNIS_SUGGESTIONS_HARD = [
    "BOOT-5122|Set a password on the GRUB bootloader|",
    "HRDN-7220|Install a malware scanner|",
    "PKGS-7370|Run a package integrity check periodically|",
]


def write_lynis(phase, index, warnings, suggestions):
    lines = [
        "# Lynis Report",
        "lynis_version=3.0.9",
        "os_fullname=Ubuntu 22.04.4 LTS",
        "os_version=22.04",
        f"hardening_index={index}",
        # a short fake list of executed tests to give tests_executed a value
        "tests_executed=" + "|".join(f"TEST-{i:04d}" for i in range(1, 266)),
    ]
    for w in warnings:
        lines.append(f"warning[]={w}")
    for s in suggestions:
        lines.append(f"suggestion[]={s}")
    out = HERE / f"lynis-report-{phase}.dat"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


# ---- OpenSCAP sample ARF XML --------------------------------------------
def write_openscap(phase, n_pass, sev_fail):
    """sev_fail = dict like {'high':4,'medium':9,'low':6}."""
    rules = []
    rid = 0
    for _ in range(n_pass):
        rid += 1
        sev = random.choice(["low", "medium", "high"])
        rules.append(
            f'    <rule-result idref="rule_{rid}" severity="{sev}">\n'
            f"      <result>pass</result>\n"
            f"    </rule-result>"
        )
    for sev, count in sev_fail.items():
        for _ in range(count):
            rid += 1
            rules.append(
                f'    <rule-result idref="rule_{rid}" severity="{sev}">\n'
                f"      <result>fail</result>\n"
                f"    </rule-result>"
            )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<arf:asset-report-collection '
        'xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1" '
        'xmlns="http://checklists.nist.gov/xccdf/1.2">\n'
        "  <TestResult>\n"
        + "\n".join(rules)
        + "\n  </TestResult>\n"
        "</arf:asset-report-collection>\n"
    )
    out = HERE / f"openscap-results-{phase}.xml"
    out.write_text(xml, encoding="utf-8")
    return out


if __name__ == "__main__":
    random.seed(42)  # reproducible samples

    # Baseline: weak system
    write_lynis("baseline", 57, LYNIS_WARNINGS_BASE, LYNIS_SUGGESTIONS_BASE)
    # ~40% compliance: 60 pass, 90 fail (high/med/low)
    write_openscap("baseline", 60, {"high": 22, "medium": 41, "low": 27})

    # Hardened: strong system
    write_lynis("hardened", 82, ["FIRE-4512|Review residual firewall rule|"],
                LYNIS_SUGGESTIONS_HARD)
    # ~78% compliance: 117 pass, 33 fail
    write_openscap("hardened", 117, {"high": 3, "medium": 16, "low": 14})

    print("Sample reports generated in", HERE)
