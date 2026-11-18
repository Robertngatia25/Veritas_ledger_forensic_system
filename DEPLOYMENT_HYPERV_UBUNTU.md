# Veritas Ledger — Air-Gapped Ubuntu Hyper-V, Local Machine & GitHub Deployment Guide

This guide explains how to deploy **Veritas Ledger** on your **local machine** or inside an **isolated Ubuntu 24.04 LTS Hyper-V Virtual Machine** with **no upload size limits (15 GB+ `.bak` databases)**, **strict network lockdown** (zero external access points), and **Kenya Data Protection Act, 2019 (KDPA 2019)** compliance.

---

## 1. Pushing & Pulling via GitHub

On your workstation or staging environment before disconnecting the Hyper-V VM from the network:

```bash
# Push your customized repository to GitHub (private repo recommended)
git init
git add .
git commit -m "Veritas Ledger Forensic Audit & KDPA 2019 Air-Gap System"
git branch -M main
git remote add origin https://github.com/<YOUR_ORG>/veritas-ledger-forensic.git
git push -u origin main
```

Note: `.gitignore` automatically excludes `vault_storage/` and `.env` so encrypted case data and keys are **never** pushed to GitHub.

---

## 2. Installing on Windows Hyper-V (Ubuntu 24.04 LTS)

### Step A: Provision the Hyper-V Virtual Machine
1. Open **Hyper-V Manager** on Windows (`virtmgmt.msc`).
2. Click **New → Virtual Machine**:
   - **Generation**: Generation 2 (UEFI)
   - **Memory**: `8192 MB` minimum (disable Dynamic Memory during large 15 GB cryptographic hashing for consistent performance)
   - **Virtual Hard Disk**: At least `45 GB` (if encrypting a second copy of a 15 GB `.bak`) or `25 GB` (if using zero-copy read-only mount)
   - **Network**: Temporarily attach **Default Switch** ONLY to install Ubuntu, Node.js, and clone from GitHub. We will disconnect it in Step C.
3. Install **Ubuntu 24.04 LTS Desktop** (so you can access the dashboard locally via browser at `http://127.0.0.1:3000` with zero network exposure).

### Step B: Install Dependencies & Clone from GitHub (Inside Ubuntu VM)
```bash
sudo apt update && sudo apt install -y git curl ufw build-essential

# Install Node.js 22 LTS
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs

# Clone the repository
git clone https://github.com/<YOUR_ORG>/veritas-ledger-forensic.git
cd veritas-ledger-forensic
npm install
npm run build
```

### Step C: Air-Gap Network Lockdown (Block All Access Points)
Run the included hardening script (`./scripts/setup_airgap_ubuntu.sh`) or execute manually:

```bash
# 1. Disable ALL incoming AND outgoing network traffic via UFW (loopback only)
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw allow in on lo
sudo ufw allow out on lo
sudo ufw --force enable
sudo ufw status verbose
```

Then in **Hyper-V Manager → VM Settings → Network Adapter**, set Virtual Switch to **Not connected** (or **Private virtual switch**). At this point, the VM cannot communicate with the LAN or Internet.

### Step D: Configure Loopback-Only `.env` & KDPA 2019 Strict Mode
```bash
cat << 'EOF' > .env
NODE_ENV=production
BIND_HOST=127.0.0.1
AIRGAP_LOCKDOWN=true
LOCAL_ONLY_DETERMINISTIC=true
KDPA_2019_STRICT_MODE=true
ALLOWED_EVIDENCE_DIR=/mnt/forensic_evidence
VAULT_MASTER_KEY=$(openssl rand -hex 32)
EOF
chmod 600 .env
```

- `BIND_HOST=127.0.0.1`: Express listens **only** on loopback. No external IP or LAN host can reach port 3000.
- `AIRGAP_LOCKDOWN=true`: Application middleware rejects any non-loopback socket IP with `403 Forbidden` and blocks outbound URL fetches.
- `LOCAL_ONLY_DETERMINISTIC=true`: Disables all outbound Gemini API calls so **zero bytes** ever leave the VM (strict compliance with **Kenya Data Protection Act, 2019 Section 48** cross-border transfer restrictions).
  *(If you later run in a controlled internet-connected enclave with ODPC cross-border authorization, set `LOCAL_ONLY_DETERMINISTIC=false` and add `GEMINI_API_KEY`; PII redaction under KDPA Section 25(c) remains active automatically.)*

---

## 3. Mounting & Processing Your 15 GB `.bak` Database

To avoid copying 15 GB across HTTP:
1. Place the 15 GB `.bak` file onto a secondary Hyper-V `.vhdx` disk (or read-only ISO/USB passthrough) and attach it to the Ubuntu VM.
2. Mount it **read-only** so source evidence cannot be modified (ISO/IEC 27037 integrity):
   ```bash
   sudo mkdir -p /mnt/forensic_evidence
   sudo mount -o ro,noexec,nosuid /dev/sdb1 /mnt/forensic_evidence
   ```
3. Start Veritas Ledger:
   ```bash
   npm start
   ```
4. Open the browser **inside the Ubuntu VM** at `http://127.0.0.1:3000`.
5. Sign in, open **RDBMS .bak Assessment**, and either:
   - Enter `/mnt/forensic_evidence/your_15gb_database.bak` in **Direct Local / Hyper-V Mounted File Reference** (computes full 15 GB SHA-256 & SHA-512 in constant ~48 MB RAM and inspects header, sampled catalog windows, tables, timestamps, and KDPA 2019 PII columns), **or**
   - Use **Stream Upload .bak (No Size Limit)** to stream the file in 8 MB chunks into the chunked AES-256-GCM vault.

---

## 4. Running as a Hardened Systemd Service (Optional)

```bash
sudo tee /etc/systemd/system/veritas-ledger.service > /dev/null << 'EOF'
[Unit]
Description=Veritas Ledger Forensic Audit Vault (Loopback Isolated)
After=local-fs.target

[Service]
Type=simple
User=forensic
WorkingDirectory=/home/forensic/veritas-ledger-forensic
ExecStart=/usr/bin/npm start
Restart=on-failure
PrivateNetwork=false
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/home/forensic/veritas-ledger-forensic/vault_storage

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now veritas-ledger
```

---

## 5. Kenya Data Protection Act, 2019 (KDPA) Checklist

- **Section 25 (Principles)**: Purpose-bound investigator login, immutable audit logging of every view/export, and automated PII redaction.
- **Section 31 (DPIA)**: Automated table & column discovery flags Personal Data (`email`, `phone`, `dob`) and Sensitive Personal Data (`national_id`, `kra_pin`, `passport`, `biometric`, `iban`).
- **Section 41 (Security Safeguards)**: AES-256-GCM encrypted vault, scrypt key derivation, PBKDF2-SHA256 authentication, and SHA-256 hash-chained logs.
- **Section 43 (72-Hour ODPC Breach Notification)**: Holistic audit scanner surfaces unauthorized `sa`/sysadmin off-hours modifications and trigger bypasses for rapid ODPC reporting assessment.
- **Section 48 (Cross-Border Restrictions)**: `LOCAL_ONLY_DETERMINISTIC=true` + UFW network lockdown keeps 100% of database bytes inside Kenya / on-premise Hyper-V host.
