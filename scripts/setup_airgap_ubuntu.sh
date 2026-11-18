#!/usr/bin/env bash
set -euo pipefail

echo "=== Veritas Ledger: Ubuntu Hyper-V Air-Gap & KDPA 2019 Hardening Setup ==="

if [[ $EUID -ne 0 ]]; then
  echo "Please run with sudo: sudo ./scripts/setup_airgap_ubuntu.sh"
  exit 1
fi

echo "[1/5] Configuring UFW firewall to block ALL incoming and outgoing network traffic (loopback only)..."
ufw --force reset
ufw default deny incoming
ufw default deny outgoing
ufw allow in on lo
ufw allow out on lo
ufw --force enable

echo "[2/5] Creating read-only forensic evidence mount directory at /mnt/forensic_evidence..."
mkdir -p /mnt/forensic_evidence
chmod 750 /mnt/forensic_evidence

echo "[3/5] Generating hardened .env bound strictly to 127.0.0.1..."
MASTER_KEY=$(openssl rand -hex 32)
cat << EOF > .env
NODE_ENV=production
BIND_HOST=127.0.0.1
AIRGAP_LOCKDOWN=true
LOCAL_ONLY_DETERMINISTIC=true
KDPA_2019_STRICT_MODE=true
ALLOWED_EVIDENCE_DIR=/mnt/forensic_evidence
VAULT_MASTER_KEY=${MASTER_KEY}
EOF
chmod 600 .env

echo "[4/5] Building production bundle..."
npm install
npm run build

echo "[5/5] Complete! Verify Hyper-V Network Adapter is disconnected or set to Private Switch."
echo "Start the isolated forensic server with: npm start"
echo "Access locally inside the VM at: http://127.0.0.1:3000"
