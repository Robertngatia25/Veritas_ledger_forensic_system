import React from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Database,
  FileSpreadsheet,
  Lock,
  Search,
  ShieldAlert,
} from 'lucide-react';
import type {
  AuditEvent,
  BakAnalysisResult,
  CrossRefSummary,
  EvidenceItem,
  HolisticFinding,
  VaultStatus,
} from '../types/forensic';
import { ForensicHeatMap } from './ForensicHeatMap';

export type NavSection =
  | 'overview'
  | 'audit-trail'
  | 'bak-analyzer'
  | 'excel-crossref'
  | 'chain-of-custody'
  | 'forensic-enquiry'
  | 'deployment-security';

interface OverviewDashboardProps {
  token: string;
  auditLogs: AuditEvent[];
  holisticFindings: HolisticFinding[];
  crossRef: CrossRefSummary | null;
  bakAnalyses: BakAnalysisResult[];
  evidenceItems: EvidenceItem[];
  vaultStatus: VaultStatus | null;
  onNavigate: (section: NavSection) => void;
  onRunHolisticScan: () => void;
  scanning: boolean;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  token,
  auditLogs,
  holisticFindings,
  crossRef,
  bakAnalyses,
  evidenceItems,
  vaultStatus,
  onNavigate,
  onRunHolisticScan,
  scanning,
}) => {
  const criticalFindings = holisticFindings.filter((f) => f.severity === 'Critical').length;
  const varianceValue = crossRef?.totalVarianceValue ?? 0;
  const discrepancyCount = crossRef?.discrepancyCount ?? 0;

  return (
    <div className="space-y-8">
      {/* Primary Hero Summary & Action Strip */}
      <div className="bg-white border border-slate-200 rounded-lg p-6 lg:p-8 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div className="max-w-2xl">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <span>Case Reference: ERP-FIN-2026-Q4</span>
            <span aria-hidden="true">·</span>
            <span>ISO/IEC 27037 &amp; ALCOA+ Compliance Scope</span>
          </div>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-slate-900 [text-wrap:balance]">
            Forensic Audit Posture &amp; Database Integrity Summary
          </h1>
          <p className="mt-2 text-sm text-slate-600 leading-relaxed">
            Inspect immutable hash-chained logs, detect backdated or out-of-sequence database timestamps, reconcile transaction codes against your online Excel register, and process Enterprise RDBMS <span className="font-mono text-slate-800">.bak</span> backups.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={onRunHolisticScan}
            disabled={scanning}
            className="px-4 py-2.5 bg-blue-700 hover:bg-blue-800 disabled:bg-blue-400 text-white text-sm font-medium rounded-md transition-colors whitespace-nowrap"
          >
            {scanning ? 'Scanning Timestamps...' : 'Run Holistic Timestamp Audit'}
          </button>
          <button
            type="button"
            onClick={() => onNavigate('bak-analyzer')}
            className="px-4 py-2.5 bg-white hover:bg-slate-50 text-slate-900 border border-slate-300 text-sm font-medium rounded-md transition-colors whitespace-nowrap"
          >
            Process .bak Backup
          </button>
        </div>
      </div>

      {/* 4-Column KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500">
            <span>Sealed Audit Records</span>
            <Lock className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900 font-mono tabular-nums">
            {auditLogs.length.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs">
            {vaultStatus?.chainIntact ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                <span className="text-emerald-700 font-medium">SHA-256 Hash Chain Intact</span>
              </>
            ) : (
              <>
                <AlertTriangle className="w-3.5 h-3.5 text-red-700 shrink-0" />
                <span className="text-red-700 font-medium">Chain Integrity Alert</span>
              </>
            )}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500">
            <span>Holistic Timestamp Anomalies</span>
            <ShieldAlert className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900 font-mono tabular-nums">
            {holisticFindings.length}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs">
            <AlertTriangle className={`w-3.5 h-3.5 shrink-0 ${criticalFindings > 0 ? 'text-red-700' : 'text-emerald-700'}`} />
            <span className={criticalFindings > 0 ? 'text-red-700 font-medium' : 'text-emerald-700 font-medium'}>
              {criticalFindings} Critical Temporal / Sequence Issues
            </span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500">
            <span>Excel Cross-Ref Exposure</span>
            <FileSpreadsheet className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900 font-mono tabular-nums">
            ${varianceValue.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs text-amber-700 font-medium">
            <span>{discrepancyCount} Transaction Code Mismatch(es)</span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500">
            <span>Encrypted Evidence Locker</span>
            <Database className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900 font-mono tabular-nums">
            {evidenceItems.length}
          </div>
          <div className="mt-2 text-xs text-slate-600">
            AES-256-GCM · {bakAnalyses.length} .bak Assessment(s)
          </div>
        </div>
      </div>

      {/* Interactive Forensic Change & Anomaly Concentration Heat Map */}
      <ForensicHeatMap auditLogs={auditLogs} token={token} />

      {/* Main Split: Priority Findings Table + Investigation Workflows */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">
                Priority Forensic Findings
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Automated temporal causality, sequence gap, and privilege bypass detection across RDBMS logs.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('audit-trail')}
              className="text-xs font-medium text-blue-700 hover:text-blue-800 flex items-center gap-1 whitespace-nowrap shrink-0"
            >
              <span>Inspect Full Logs</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-slate-200">
            {holisticFindings.slice(0, 6).map((finding) => (
              <div key={finding.findingId} className="px-6 py-4 hover:bg-slate-50 transition-colors">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs">
                    <span
                      className={`font-semibold ${
                        finding.severity === 'Critical'
                          ? 'text-red-700'
                          : finding.severity === 'Warning'
                            ? 'text-amber-700'
                            : 'text-emerald-700'
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <span className="text-slate-300" aria-hidden="true">·</span>
                    <span className="text-slate-600 font-medium">{finding.category}</span>
                    <span className="text-slate-300" aria-hidden="true">·</span>
                    <span className="font-mono text-slate-500">{finding.findingId}</span>
                  </div>
                  <span className="font-mono text-xs text-slate-500">{finding.affectedTarget}</span>
                </div>
                <h3 className="mt-1.5 text-sm font-semibold text-slate-900">{finding.title}</h3>
                <p className="mt-1 text-xs text-slate-600 leading-relaxed">{finding.evidenceSummary}</p>
                <div className="mt-2 text-xs text-slate-500">
                  Standard: <span className="text-slate-700">{finding.standardReference}</span>
                </div>
              </div>
            ))}
            {holisticFindings.length === 0 && (
              <div className="px-6 py-10 text-center text-sm text-slate-500">
                No temporal or sequence anomalies found in the active dataset.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Quick Forensic Workflows */}
        <div className="bg-white border border-slate-200 rounded-lg divide-y divide-slate-200">
          <div className="px-6 py-4">
            <h2 className="text-base font-semibold text-slate-900">Investigation Modules</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Direct access to evidence processing and compliance workflows.
            </p>
          </div>

          <button
            type="button"
            onClick={() => onNavigate('bak-analyzer')}
            className="w-full text-left px-6 py-4 hover:bg-slate-50 transition-colors flex items-start justify-between gap-3"
          >
            <div>
              <div className="text-sm font-semibold text-slate-900">Enterprise RDBMS .bak Assessment</div>
              <p className="mt-1 text-xs text-slate-600">
                Upload SQL Server <span className="font-mono">.bak</span> or <span className="font-mono">.sql</span> backups for binary MTF inspection and Gemini architectural review.
              </p>
            </div>
            <Database className="w-4 h-4 text-blue-700 shrink-0 mt-1" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate('excel-crossref')}
            className="w-full text-left px-6 py-4 hover:bg-slate-50 transition-colors flex items-start justify-between gap-3"
          >
            <div>
              <div className="text-sm font-semibold text-slate-900">Online Excel Cross-Reference</div>
              <p className="mt-1 text-xs text-slate-600">
                Connect an online spreadsheet URL or upload <span className="font-mono">.xlsx/.csv</span> to verify transaction codes and monetary amounts.
              </p>
            </div>
            <FileSpreadsheet className="w-4 h-4 text-blue-700 shrink-0 mt-1" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate('forensic-enquiry')}
            className="w-full text-left px-6 py-4 hover:bg-slate-50 transition-colors flex items-start justify-between gap-3"
          >
            <div>
              <div className="text-sm font-semibold text-slate-900">AI Forensic Enquiry &amp; Reports</div>
              <p className="mt-1 text-xs text-slate-600">
                Query logs with Gemini AI and generate comprehensive PDF &amp; CSV compliance reports.
              </p>
            </div>
            <Search className="w-4 h-4 text-blue-700 shrink-0 mt-1" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate('chain-of-custody')}
            className="w-full text-left px-6 py-4 hover:bg-slate-50 transition-colors flex items-start justify-between gap-3"
          >
            <div>
              <div className="text-sm font-semibold text-slate-900">Chain of Custody &amp; Encrypted Vault</div>
              <p className="mt-1 text-xs text-slate-600">
                Verify AES-256-GCM storage integrity and SHA-256/SHA-512 digital evidence provenance.
              </p>
            </div>
            <Lock className="w-4 h-4 text-blue-700 shrink-0 mt-1" />
          </button>
        </div>
      </div>
    </div>
  );
};
