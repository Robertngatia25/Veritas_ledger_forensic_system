# Veritas Ledger — Forensic Audit Trail & RDBMS Integrity System

Enterprise forensic audit trail, ISO/IEC 27037 chain of custody, AES-256-GCM encrypted evidence vault, streaming multi-GB `.bak` architectural analyzer (15 GB+ capable), online/offline Excel cross-referencing, and **Kenya Data Protection Act, 2019 (KDPA 2019)** compliance platform.

## Quick Start (Local Machine or Isolated Ubuntu Hyper-V VM)

```bash
git clone <YOUR_GITHUB_REPO_URL>
cd veritas-ledger-forensic
npm install
cp .env.example .env
npm run build
npm start
```

For full **15 GB+ `.bak` streaming**, **Hyper-V Private Switch air-gap isolation**, **UFW network lockdown**, and **Kenya Data Protection Act, 2019** hardening instructions, see [`DEPLOYMENT_HYPERV_UBUNTU.md`](./DEPLOYMENT_HYPERV_UBUNTU.md) or run:

```bash
chmod +x scripts/setup_airgap_ubuntu.sh
sudo ./scripts/setup_airgap_ubuntu.sh
```
