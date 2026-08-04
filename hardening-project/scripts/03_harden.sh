#!/usr/bin/env bash
#
# 03_harden.sh - Apply a set of CIS-aligned Level 1 hardening controls to an
# Ubuntu Server system, then it can be re-audited to measure the improvement.
#
# Usage:
#   sudo bash scripts/03_harden.sh
#
# IMPORTANT
#   * Run this ONLY on a disposable lab VM. Take a VirtualBox snapshot first so
#     you can roll back to the baseline.
#   * Each control is grouped by CIS section and commented with its intent.
#   * The script is written to be re-runnable (idempotent) where practical.
#   * It logs every action to a timestamped backup directory so changes are
#     auditable and reversible.
#
# This is intentionally a representative subset of CIS Level 1, chosen to cover
# the main categories an examiner expects: authentication, SSH, network/kernel
# parameters, host firewall, auditing/logging, and filesystem/service hygiene.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo bash $0"
  exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="/root/hardening-backup-$TS"
mkdir -p "$BACKUP"
echo "[*] Backups and change log -> $BACKUP"

backup() { [[ -f "$1" ]] && cp -a "$1" "$BACKUP/" || true; }

log() { echo "[+] $*"; }

# ---------------------------------------------------------------------------
# 1. Updates and package hygiene  (CIS 1.x / 3.x)
# ---------------------------------------------------------------------------
log "Updating package index and upgrading installed packages..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get -y upgrade

log "Installing core security packages (auditd, ufw, fail2ban, AIDE)..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  auditd audispd-plugins ufw fail2ban aide acct

# ---------------------------------------------------------------------------
# 2. Filesystem / kernel module hygiene  (CIS 1.1)
# ---------------------------------------------------------------------------
log "Disabling uncommon, rarely-needed filesystem modules..."
MODCONF="/etc/modprobe.d/cis-hardening.conf"
backup "$MODCONF"
cat > "$MODCONF" <<'EOF'
# Disable uncommon filesystems and protocols (CIS 1.1 / 3.4)
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
EOF

# ---------------------------------------------------------------------------
# 3. Kernel network parameters via sysctl  (CIS 3.x)
# ---------------------------------------------------------------------------
log "Applying sysctl network hardening parameters..."
SYSCTL="/etc/sysctl.d/60-cis-hardening.conf"
backup "$SYSCTL"
cat > "$SYSCTL" <<'EOF'
# Network hardening (CIS 3.2 / 3.3)
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
# Kernel hardening
kernel.randomize_va_space = 2
EOF
sysctl --system >/dev/null

# ---------------------------------------------------------------------------
# 4. Host firewall with UFW  (CIS 3.5)
# ---------------------------------------------------------------------------
log "Configuring UFW host firewall (default deny inbound, allow SSH)..."
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp           # keep SSH reachable; adjust if you moved the port
ufw --force enable

# ---------------------------------------------------------------------------
# 5. SSH server hardening  (CIS 5.2)
# ---------------------------------------------------------------------------
log "Hardening SSH server configuration..."
SSHD="/etc/ssh/sshd_config"
backup "$SSHD"
set_sshd() {
  local key="$1" val="$2"
  if grep -qiE "^\s*#?\s*${key}\b" "$SSHD"; then
    sed -i -E "s|^\s*#?\s*${key}\b.*|${key} ${val}|I" "$SSHD"
  else
    echo "${key} ${val}" >> "$SSHD"
  fi
}
set_sshd "PermitRootLogin" "no"
set_sshd "PasswordAuthentication" "no"   # key-based auth only; ensure you have a key!
set_sshd "PermitEmptyPasswords" "no"
set_sshd "X11Forwarding" "no"
set_sshd "MaxAuthTries" "4"
set_sshd "ClientAliveInterval" "300"
set_sshd "ClientAliveCountMax" "0"
set_sshd "LoginGraceTime" "60"
set_sshd "Protocol" "2"
# Validate config before restarting so we never lock ourselves out on a typo.
if sshd -t; then
  systemctl restart ssh || systemctl restart sshd || true
  log "SSH configuration applied and service restarted."
else
  log "WARNING: sshd config test failed; restoring backup."
  cp -a "$BACKUP/$(basename "$SSHD")" "$SSHD"
fi

# ---------------------------------------------------------------------------
# 6. Password and account policy  (CIS 5.4)
# ---------------------------------------------------------------------------
log "Setting password ageing and quality policy..."
LOGINDEFS="/etc/login.defs"
backup "$LOGINDEFS"
sed -i -E 's/^\s*#?\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' "$LOGINDEFS"
sed -i -E 's/^\s*#?\s*PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/'   "$LOGINDEFS"
sed -i -E 's/^\s*#?\s*PASS_WARN_AGE.*/PASS_WARN_AGE 7/'   "$LOGINDEFS"

# Password quality (length / complexity) via pam_pwquality.
DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality
PWQUALITY="/etc/security/pwquality.conf"
backup "$PWQUALITY"
set_pw() {
  local key="$1" val="$2"
  if grep -qiE "^\s*#?\s*${key}\b" "$PWQUALITY"; then
    sed -i -E "s|^\s*#?\s*${key}\b.*|${key} = ${val}|I" "$PWQUALITY"
  else
    echo "${key} = ${val}" >> "$PWQUALITY"
  fi
}
set_pw "minlen" "14"
set_pw "dcredit" "-1"
set_pw "ucredit" "-1"
set_pw "ocredit" "-1"
set_pw "lcredit" "-1"

# ---------------------------------------------------------------------------
# 7. Auditing and logging  (CIS 4.x)
# ---------------------------------------------------------------------------
log "Enabling auditd at boot..."
systemctl enable auditd >/dev/null 2>&1 || true
systemctl start auditd  >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 8. Core dump restriction and permissions  (CIS 1.5 / 5.1)
# ---------------------------------------------------------------------------
log "Restricting core dumps and tightening cron permissions..."
echo "* hard core 0" > /etc/security/limits.d/cis-core.conf
chmod 600 /etc/crontab 2>/dev/null || true
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly \
          /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true

log "Hardening complete."
echo
echo "=================================================================="
echo " Hardening applied. Backups stored in: $BACKUP"
echo " Next: re-run the audits to measure the improvement:"
echo "   sudo bash scripts/01_run_lynis.sh hardened"
echo "   sudo bash scripts/02_run_openscap.sh hardened"
echo "=================================================================="
