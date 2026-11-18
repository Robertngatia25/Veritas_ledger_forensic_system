import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  Lock,
  Server,
  ShieldCheck,
} from 'lucide-react';
import type { SecurityComplianceConfig } from '../types/forensic';

interface DeploymentSecurityViewProps {
  token: string;
  securityConfig: SecurityComplianceConfig | null;
  onSecurityConfigUpdated: (config: SecurityComplianceConfig, auditLogs?: unknown[]) => void;
}

const HYPERV_SETUP_COMMANDS = `# 1. Inside Ubuntu 24.04 LTS (Hyper-V Generation 2 VM, Private Virtual Switch)
sudo apt update && sudo apt install -y git curl ufw build-essential

# 2. Install Node.js 22 LTS
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs

# 3. Lock Down All Network Interfaces (Loopback-Only Isolation)
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw allow in on lo
sudo ufw allow out on lo
sudo ufw --force enable
sudo ufw status verbose

# 4. Clone Repository & Configure Air-Gapped Local Vault
git clone https://github.com/<YOUR_ORG>/veritas-ledger-forensic.git
cd veritas-ledger-forensic
npm install
npm run build

# 5. Create Hardened .env (Bind Strictly to 127.0.0.1)
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

# 6. Mount 15 GB+ Evidence Drive Read-Only & Launch
sudo mkdir -p /mnt/forensic_evidence
# Example: sudo mount -o ro,noexec,nosuid /dev/sdb1 /mnt/forensic_evidence
npm start`;

export const DeploymentSecurityView: React.FC<DeploymentSecurityViewProps> = ({
  token,
  securityConfig,
  onSecurityConfigUpdated,
}) => {
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleSetting = async (
    key: 'airgapLockdown' | 'localDeterministicOnly' | 'kdpaStrictMode' | 'maskPiiBeforeAi',
    nextVal: boolean
  ) => {
    setError(null);
    setSaving(true);
    try {
      const res = await fetch('/api/security/config', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ [key]: nextVal }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Failed to update security posture.');
        return;
      }
      onSecurityConfigUpdated(data.securityConfig, data.auditLogs);
    } catch {
      setError('Network error updating security configuration.');
    } finally {
      setSaving(false);
    }
  };

  const handleCopyCommands = async () => {
    await navigator.clipboard.writeText(HYPERV_SETUP_COMMANDS);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadSetupScript = () => {
    const blob = new Blob([`#!/usr/bin/env bash\nset -euo pipefail\n\n${HYPERV_SETUP_COMMANDS}\n`], {
      type: 'text/x-shellscript;charset=utf-8;',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'setup_airgap_ubuntu.sh';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Network Isolation & KDPA 2019 Controls */}
      <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <h1 className="text-xl font-semibold text-slate-900">
              Kenya Data Protection Act, 2019 &amp; Air-Gap Network Lockdown
            </h1>
            <p className="mt-1 text-xs text-slate-600 max-w-3xl leading-relaxed">
              Enforce strict loopback-only network isolation, PII minimization before AI calls, and zero cross-border data egress for your 15 GB+ enterprise database investigation on Ubuntu Hyper-V.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-700 shrink-0">
            <Lock className="w-4 h-4 text-slate-500" />
            <span>Bind: {securityConfig?.bindHost || '0.0.0.0'}:3000</span>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-md flex items-start gap-2 text-xs text-red-800">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {securityConfig && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 border border-slate-200 rounded-md flex items-start justify-between gap-4">
              <div>
                <div className="text-sm font-semibold text-slate-900">
                  Air-Gap Loopback Lockdown
                </div>
                <p className="mt-1 text-xs text-slate-600">
                  Rejects all non-localhost (<span className="font-mono">127.0.0.1</span>) connections and blocks outbound external URL fetches. Enable on your local Ubuntu Hyper-V VM (keep off when accessing via cloud proxy).
                </p>
              </div>
              <button
                type="button"
                disabled={saving}
                onClick={() => toggleSetting('airgapLockdown', !securityConfig.airgapLockdown)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 border transition-colors ${
                  securityConfig.airgapLockdown
                    ? 'bg-slate-900 text-white border-slate-900'
                    : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                }`}
              >
                {securityConfig.airgapLockdown ? 'Locked (127.0.0.1)' : 'Enable Lockdown'}
              </button>
            </div>

            <div className="p-4 border border-slate-200 rounded-md flex items-start justify-between gap-4">
              <div>
                <div className="text-sm font-semibold text-slate-900">
                  100% Local Deterministic Mode (Zero AI Egress)
                </div>
                <p className="mt-1 text-xs text-slate-600">
                  Disables all outbound Gemini API calls and runs deterministic local reports. Guarantees strict compliance with Kenya DPA 2019 Section 48 cross-border transfer prohibitions.
                </p>
              </div>
              <button
                type="button"
                disabled={saving}
                onClick={() =>
                  toggleSetting('localDeterministicOnly', !securityConfig.localDeterministicOnly)
                }
                className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 border transition-colors ${
                  securityConfig.localDeterministicOnly
                    ? 'bg-emerald-700 text-white border-emerald-700'
                    : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                }`}
              >
                {securityConfig.localDeterministicOnly ? 'Offline Local Only' : 'Enable Zero-Egress'}
              </button>
            </div>

            <div className="p-4 border border-slate-200 rounded-md flex items-start justify-between gap-4">
              <div>
                <div className="text-sm font-semibold text-slate-900">
                  KDPA 2019 PII Redaction Filter
                </div>
                <p className="mt-1 text-xs text-slate-600">
                  Automatically masks emails, IPv4 addresses, KRA PINs, MSISDNs, and IBANs prior to AI architectural assessment (Section 25(c) Data Minimization).
                </p>
              </div>
              <button
                type="button"
                disabled={saving}
                onClick={() => toggleSetting('maskPiiBeforeAi', !securityConfig.maskPiiBeforeAi)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 border transition-colors ${
                  securityConfig.maskPiiBeforeAi
                    ? 'bg-blue-700 text-white border-blue-700'
                    : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                }`}
              >
                {securityConfig.maskPiiBeforeAi ? 'Masking Active' : 'Enable Masking'}
              </button>
            </div>

            <div className="p-4 border border-slate-200 rounded-md flex items-start justify-between gap-4">
              <div>
                <div className="text-sm font-semibold text-slate-900">
                  KDPA 2019 Strict Compliance Mode
                </div>
                <p className="mt-1 text-xs text-slate-600">
                  Includes statutory Kenya DPA 2019 Sections 25, 31, 41, 43, and 48 findings in all PDF/JSON assessments and DPIA checks.
                </p>
              </div>
              <button
                type="button"
                disabled={saving}
                onClick={() => toggleSetting('kdpaStrictMode', !securityConfig.kdpaStrictMode)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 border transition-colors ${
                  securityConfig.kdpaStrictMode
                    ? 'bg-blue-700 text-white border-blue-700'
                    : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                }`}
              >
                {securityConfig.kdpaStrictMode ? 'Strict KDPA Active' : 'Enable KDPA Mode'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Kenya Data Protection Act 2019 Matrix */}
      {securityConfig && (
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-blue-700" />
            <h2 className="text-base font-semibold text-slate-900">
              Kenya Data Protection Act, 2019 (KDPA) Compliance Posture
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
                  <th className="py-3 px-4 whitespace-nowrap">Statutory Section</th>
                  <th className="py-3 px-3 whitespace-nowrap">Principle / Obligation</th>
                  <th className="py-3 px-3 whitespace-nowrap">Status</th>
                  <th className="py-3 px-4">Control Verification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {securityConfig.kdpaPrinciples.map((p, idx) => (
                  <tr key={idx} className="hover:bg-slate-50">
                    <td className="py-3 px-4 font-mono font-semibold text-slate-900 whitespace-nowrap">
                      {p.section}
                    </td>
                    <td className="py-3 px-3 font-medium text-slate-900">{p.principle}</td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        {p.status === 'Compliant' ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                        ) : (
                          <AlertTriangle
                            className={`w-3.5 h-3.5 shrink-0 ${
                              p.status === 'Action Required' ? 'text-red-700' : 'text-amber-700'
                            }`}
                          />
                        )}
                        <span
                          className={`font-semibold ${
                            p.status === 'Compliant'
                              ? 'text-emerald-700'
                              : p.status === 'Action Required'
                                ? 'text-red-700'
                                : 'text-amber-700'
                          }`}
                        >
                          {p.status}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-600">{p.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Ubuntu Hyper-V, Localhost & GitHub Hardening Guide */}
      <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-slate-700" />
            <h2 className="text-base font-semibold text-slate-900">
              Ubuntu Hyper-V Air-Gapped Installation &amp; Network Isolation Guide
            </h2>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleCopyCommands}
              className="px-3 py-1.5 bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-medium rounded-md flex items-center gap-1.5 whitespace-nowrap"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>{copied ? 'Copied' : 'Copy Commands'}</span>
            </button>
            <button
              type="button"
              onClick={handleDownloadSetupScript}
              className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium rounded-md flex items-center gap-1.5 whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download setup_airgap_ubuntu.sh</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs text-slate-600 leading-relaxed">
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-md">
            <h3 className="font-semibold text-slate-900">1. Hyper-V VM Isolation</h3>
            <p className="mt-1.5">
              Create a <strong>Generation 2 Ubuntu 24.04 LTS</strong> VM with at least 8 GB RAM and 40+ GB VHDX. After installing Node.js and cloning from GitHub, switch the Hyper-V Virtual Switch to <strong>Private</strong> (or disconnect the virtual NIC) so the VM has zero external network exposure while processing the 15 GB database.
            </p>
          </div>
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-md">
            <h3 className="font-semibold text-slate-900">2. Block All Network Access Points</h3>
            <p className="mt-1.5">
              Configure <span className="font-mono">BIND_HOST=127.0.0.1</span> and <span className="font-mono">AIRGAP_LOCKDOWN=true</span> in <span className="font-mono">.env</span>, and apply UFW (<span className="font-mono">ufw default deny incoming &amp;&amp; ufw default deny outgoing</span>, loopback <span className="font-mono">lo</span> only). Open <span className="font-mono">http://127.0.0.1:3000</span> strictly inside the VM browser.
            </p>
          </div>
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-md">
            <h3 className="font-semibold text-slate-900">3. Mount 15 GB Database Read-Only</h3>
            <p className="mt-1.5">
              Attach a secondary VHDX or ISO containing the 15 GB <span className="font-mono">.bak</span> file and mount with <span className="font-mono">mount -o ro,noexec,nosuid</span> at <span className="font-mono">/mnt/forensic_evidence</span>. Use <strong>Direct Local Path Ingestion</strong> in the <span className="font-mono">.bak</span> tab to stream-hash and analyze all 15 GB with zero duplication.
            </p>
          </div>
        </div>

        <pre className="p-4 bg-slate-900 text-slate-100 rounded-md font-mono text-[11px] overflow-x-auto leading-relaxed">
          {HYPERV_SETUP_COMMANDS}
        </pre>
      </div>
    </div>
  );
};
