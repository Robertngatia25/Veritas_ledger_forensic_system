import React from 'react';
import { AlertTriangle, CheckCircle2, Lock, RefreshCw, ShieldCheck } from 'lucide-react';
import type { EvidenceItem, VaultStatus } from '../types/forensic';

interface ChainOfCustodyViewProps {
  evidenceItems: EvidenceItem[];
  vaultStatus: VaultStatus | null;
  onVerifyChain: () => void;
  verifying: boolean;
}

export const ChainOfCustodyView: React.FC<ChainOfCustodyViewProps> = ({
  evidenceItems,
  vaultStatus,
  onVerifyChain,
  verifying,
}) => {
  return (
    <div className="space-y-6">
      {/* Encrypted Vault & Hash Chain Verification Card */}
      <div className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-5 border-b border-slate-200">
          <div>
            <h1 className="text-xl font-semibold text-slate-900">
              Digital Evidence Chain of Custody &amp; Encrypted Vault
            </h1>
            <p className="mt-1 text-xs text-slate-600 max-w-3xl leading-relaxed">
              Compliant with ISO/IEC 27037 guidelines for identification, collection, acquisition, and preservation of digital evidence. Every artifact is hashed with SHA-256 &amp; SHA-512 and sealed in AES-256-GCM encrypted storage.
            </p>
          </div>

          <button
            type="button"
            onClick={onVerifyChain}
            disabled={verifying}
            className="px-4 py-2.5 bg-blue-700 hover:bg-blue-800 disabled:bg-blue-400 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            <span>{verifying ? 'Verifying Hashes...' : 'Verify Hash Chain Integrity'}</span>
          </button>
        </div>

        {vaultStatus && (
          <div className="mt-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 text-xs">
            <div>
              <div className="text-slate-500">Cryptographic Chain Status</div>
              <div className="mt-1.5 flex items-center gap-1.5 font-semibold">
                {vaultStatus.chainIntact ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                    <span className="text-emerald-700">Intact &amp; Verified</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 text-red-700" />
                    <span className="text-red-700">
                      Broken at Seq #{vaultStatus.brokenAtSequenceId}
                    </span>
                  </>
                )}
              </div>
            </div>

            <div>
              <div className="text-slate-500">At-Rest Encryption</div>
              <div className="mt-1.5 font-mono text-slate-900 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-slate-500" />
                <span>{vaultStatus.encryptionAlgorithm}</span>
              </div>
              <div className="mt-0.5 text-[11px] text-slate-500">{vaultStatus.keyDerivation}</div>
            </div>

            <div>
              <div className="text-slate-500">Sealed Audit Blocks</div>
              <div className="mt-1.5 font-mono tabular-nums text-base font-semibold text-slate-900">
                {vaultStatus.totalSealedLogEntries}
              </div>
              <div className="mt-0.5 text-[11px] text-slate-500">
                Last verified {vaultStatus.lastVerifiedUtc.replace('T', ' ').slice(0, 19)}Z
              </div>
            </div>

            <div>
              <div className="text-slate-500">Tip Block Hash (SHA-256)</div>
              <div
                className="mt-1.5 font-mono text-[11px] text-slate-800 break-all"
                title={vaultStatus.tipHash}
              >
                {vaultStatus.tipHash}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Evidence Artifacts Ledger */}
      <div className="space-y-4">
        {evidenceItems.map((item) => (
          <div key={item.evidenceId} className="bg-white border border-slate-200 rounded-lg p-6">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 pb-4 border-b border-slate-200">
              <div>
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                  <span className="font-mono font-semibold text-slate-900">{item.evidenceId}</span>
                  <span aria-hidden="true">·</span>
                  <span>{item.fileType}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono tabular-nums">{item.byteSize.toLocaleString()} bytes</span>
                </div>
                <h2 className="mt-1 text-base font-semibold text-slate-900">{item.fileName}</h2>
              </div>

              <div className="flex items-center gap-2 text-xs font-medium text-emerald-700 shrink-0">
                <ShieldCheck className="w-4 h-4" />
                <span>{item.cipherSuite}</span>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
              <div>
                <div className="text-slate-500">SHA-256 Digest</div>
                <div className="mt-1 font-mono text-[11px] text-slate-900 break-all bg-slate-50 p-2 rounded border border-slate-200">
                  {item.sha256}
                </div>
              </div>
              <div>
                <div className="text-slate-500">SHA-512 Digest</div>
                <div className="mt-1 font-mono text-[11px] text-slate-700 break-all bg-slate-50 p-2 rounded border border-slate-200">
                  {item.sha512}
                </div>
              </div>
            </div>

            <div className="mt-5">
              <h3 className="text-xs font-semibold text-slate-900 mb-2.5">
                Custody Provenance Log
              </h3>
              <div className="border border-slate-200 rounded-md overflow-hidden">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
                      <th className="py-2 px-3">Timestamp (UTC)</th>
                      <th className="py-2 px-3">Stage</th>
                      <th className="py-2 px-3">Custodian / Engine</th>
                      <th className="py-2 px-3">Action Notes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {item.custodyEvents.map((ce, idx) => (
                      <tr key={idx}>
                        <td className="py-2 px-3 font-mono tabular-nums text-slate-700 whitespace-nowrap">
                          {ce.timestampUtc.replace('T', ' ').slice(0, 19)}Z
                        </td>
                        <td className="py-2 px-3 font-medium text-slate-900 whitespace-nowrap">
                          {ce.stage}
                        </td>
                        <td className="py-2 px-3 text-slate-800 whitespace-nowrap">{ce.actor}</td>
                        <td className="py-2 px-3 text-slate-600">{ce.notes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
