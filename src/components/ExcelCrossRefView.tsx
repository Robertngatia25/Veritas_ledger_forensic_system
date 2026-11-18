import React, { useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileSpreadsheet,
  Link2,
  RefreshCw,
  Sparkles,
  Upload,
  X,
} from 'lucide-react';
import type { CrossRefSummary, ExcelTransactionRow } from '../types/forensic';

interface ExcelCrossRefViewProps {
  token: string;
  excelRegister: {
    sheetName: string;
    sheetSha256: string;
    loadedAtUtc: string;
    rows: ExcelTransactionRow[];
  };
  lastCrossRef: CrossRefSummary | null;
  onCrossRefUpdated: (payload: {
    excelRegister?: {
      sheetName: string;
      sheetSha256: string;
      loadedAtUtc: string;
      rows: ExcelTransactionRow[];
    };
    lastCrossRef: CrossRefSummary;
    evidenceItems?: unknown[];
    auditLogs?: unknown[];
  }) => void;
  onExportCrossRefCsv: () => void;
}

export const ExcelCrossRefView: React.FC<ExcelCrossRefViewProps> = ({
  token,
  excelRegister,
  lastCrossRef,
  onCrossRefUpdated,
  onExportCrossRefCsv,
}) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [sheetUrl, setSheetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState<'all' | 'discrepancies' | 'matched'>('all');
  const [error, setError] = useState<string | null>(null);
  const [synthesizing, setSynthesizing] = useState(false);
  const [aiSynthesis, setAiSynthesis] = useState<string | null>(null);
  const [aiSynthesisError, setAiSynthesisError] = useState<string | null>(null);

  const handleRunAiSynthesis = async () => {
    setAiSynthesisError(null);
    setSynthesizing(true);
    try {
      const res = await fetch('/api/ai/crossref-synthesis', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setAiSynthesisError(data.error || 'Failed to run AI fraud & variance synthesis.');
        return;
      }
      setAiSynthesis(data.synthesis || '');
      if (lastCrossRef && Array.isArray(data.auditLogs)) {
        onCrossRefUpdated({
          lastCrossRef,
          auditLogs: data.auditLogs,
        });
      }
    } catch {
      setAiSynthesisError('Network error running AI cross-reference synthesis.');
    } finally {
      setSynthesizing(false);
    }
  };

  const handleFetchUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sheetUrl.trim()) return;
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/crossref/fetch-url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ url: sheetUrl.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Unable to fetch online spreadsheet.');
        return;
      }
      onCrossRefUpdated(data);
    } catch {
      setError('Network error fetching online spreadsheet.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    setError(null);
    setLoading(true);
    try {
      const buf = await file.arrayBuffer();
      const res = await fetch('/api/crossref/upload-sheet-raw', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/octet-stream',
          'x-file-name': encodeURIComponent(file.name),
        },
        body: buf,
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Failed to parse workbook.');
        return;
      }
      onCrossRefUpdated(data);
    } catch {
      setError('Failed to upload spreadsheet.');
    } finally {
      setLoading(false);
    }
  };

  const handleReconcile = async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/crossref/reconcile', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Reconciliation failed.');
        return;
      }
      onCrossRefUpdated(data);
    } catch {
      setError('Failed to reconcile transaction codes.');
    } finally {
      setLoading(false);
    }
  };

  const discrepancies = lastCrossRef?.discrepancies || [];
  const filteredRows = discrepancies.filter((d) => {
    if (statusFilter === 'discrepancies') return d.status !== 'MATCHED_VERIFIED';
    if (statusFilter === 'matched') return d.status === 'MATCHED_VERIFIED';
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Online Sheet Connection & Upload */}
      <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-slate-900">
              Online Excel Sheet Transaction Cross-Reference
            </h1>
            <p className="mt-1 text-xs text-slate-600 max-w-3xl leading-relaxed">
              Cross-reference database transaction codes against an authoritative online Excel / Google Sheets link or uploaded <span className="font-mono">.xlsx/.csv</span> register to detect monetary variances, phantom transactions, replay duplicates, and timestamp mismatches.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={handleRunAiSynthesis}
              disabled={synthesizing || !lastCrossRef}
              className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <Sparkles className="w-3.5 h-3.5 text-blue-300" />
              <span>{synthesizing ? 'Synthesizing...' : 'Run AI Fraud Synthesis'}</span>
            </button>
            <button
              type="button"
              onClick={handleReconcile}
              disabled={loading}
              className="px-3.5 py-2 bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Re-Run Reconciliation</span>
            </button>
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              disabled={loading}
              className="px-3.5 py-2 bg-blue-700 hover:bg-blue-800 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Upload .xlsx / .csv</span>
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".xlsx,.xls,.csv"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFileUpload(f);
                e.target.value = '';
              }}
            />
          </div>
        </div>

        <form onSubmit={handleFetchUrl} className="flex flex-col sm:flex-row gap-2.5 pt-4 border-t border-slate-200">
          <div className="relative flex-1">
            <Link2 className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="url"
              value={sheetUrl}
              onChange={(e) => setSheetUrl(e.target.value)}
              placeholder="Paste public Google Sheets URL, OneDrive CSV link, or direct .xlsx/.csv URL..."
              className="w-full pl-9 pr-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !sheetUrl.trim()}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            {loading ? 'Fetching Sheet...' : 'Fetch & Cross-Reference URL'}
          </button>
        </form>

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-md flex items-start gap-2 text-xs text-red-800">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500 pt-1">
          <FileSpreadsheet className="w-4 h-4 text-slate-400" />
          <span>Active Sheet: <strong className="text-slate-800">{excelRegister.sheetName}</strong></span>
          <span aria-hidden="true">·</span>
          <span className="font-mono tabular-nums">{excelRegister.rows.length} Authorized Rows</span>
          <span aria-hidden="true">·</span>
          <span className="font-mono truncate max-w-xs" title={excelRegister.sheetSha256}>
            SHA-256: {excelRegister.sheetSha256.slice(0, 20)}...
          </span>
        </div>
      </div>

      {/* Summary Strip */}
      {lastCrossRef && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white border border-slate-200 rounded-lg p-4">
            <div className="text-xs text-slate-500">DB Unique TXN Codes</div>
            <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-slate-900">
              {lastCrossRef.totalDbTransactions}
            </div>
          </div>
          <div className="bg-white border border-slate-200 rounded-lg p-4">
            <div className="text-xs text-slate-500">Matched &amp; Verified</div>
            <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-emerald-700">
              {lastCrossRef.matchedCount}
            </div>
          </div>
          <div className="bg-white border border-slate-200 rounded-lg p-4">
            <div className="text-xs text-slate-500">Integrity Discrepancies</div>
            <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-red-700">
              {lastCrossRef.discrepancyCount}
            </div>
          </div>
          <div className="bg-white border border-slate-200 rounded-lg p-4">
            <div className="text-xs text-slate-500">Total Absolute Variance</div>
            <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-slate-900">
              ${lastCrossRef.totalVarianceValue.toLocaleString(undefined, { minimumFractionDigits: 2 })}
            </div>
          </div>
        </div>
      )}

      {/* Gemini AI Cross-Reference Fraud & Variance Synthesis */}
      {aiSynthesisError && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2 text-xs text-red-800">
          <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
          <span>{aiSynthesisError}</span>
        </div>
      )}

      {aiSynthesis && (
        <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-2.5">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
              <Sparkles className="w-4 h-4 text-blue-700" />
              <span>Gemini AI Cross-Reference Fraud &amp; Control Variance Synthesis</span>
            </div>
            <button
              type="button"
              onClick={() => setAiSynthesis(null)}
              className="text-slate-400 hover:text-slate-700"
              aria-label="Dismiss AI fraud synthesis"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="text-xs text-slate-700 whitespace-pre-wrap leading-relaxed">
            {aiSynthesis}
          </div>
        </div>
      )}

      {/* Reconciliation Table */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
          <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
            <button
              type="button"
              onClick={() => setStatusFilter('all')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                statusFilter === 'all' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
              }`}
            >
              All ({discrepancies.length})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('discrepancies')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                statusFilter === 'discrepancies' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
              }`}
            >
              Discrepancies Only ({discrepancies.filter((d) => d.status !== 'MATCHED_VERIFIED').length})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('matched')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                statusFilter === 'matched' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
              }`}
            >
              Verified Matches ({discrepancies.filter((d) => d.status === 'MATCHED_VERIFIED').length})
            </button>
          </div>

          <button
            type="button"
            onClick={onExportCrossRefCsv}
            disabled={!lastCrossRef}
            className="px-3.5 py-2 bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Reconciliation CSV</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-semibold text-slate-600">
                <th className="py-3 px-4 whitespace-nowrap">Transaction Code</th>
                <th className="py-3 px-3 whitespace-nowrap">Verification Status</th>
                <th className="py-3 px-3 text-right whitespace-nowrap">DB Amount</th>
                <th className="py-3 px-3 text-right whitespace-nowrap">Excel Amount</th>
                <th className="py-3 px-3 text-right whitespace-nowrap">Variance</th>
                <th className="py-3 px-4">Forensic Reconciliation Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-xs">
              {filteredRows.map((row) => (
                <tr key={row.transactionCode} className="hover:bg-slate-50">
                  <td className="py-3 px-4 font-mono font-semibold text-slate-900 whitespace-nowrap">
                    {row.transactionCode}
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      {row.status === 'MATCHED_VERIFIED' ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                      ) : (
                        <AlertTriangle
                          className={`w-3.5 h-3.5 shrink-0 ${
                            row.severity === 'Critical' ? 'text-red-700' : 'text-amber-700'
                          }`}
                        />
                      )}
                      <span
                        className={`font-semibold ${
                          row.status === 'MATCHED_VERIFIED'
                            ? 'text-emerald-700'
                            : row.severity === 'Critical'
                              ? 'text-red-700'
                              : 'text-amber-700'
                        }`}
                      >
                        {row.status}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-800 whitespace-nowrap">
                    {row.dbAmount !== undefined ? `$${row.dbAmount.toLocaleString(undefined, { minimumFractionDigits: 2 })}` : '—'}
                  </td>
                  <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-800 whitespace-nowrap">
                    {row.excelAmount !== undefined ? `$${row.excelAmount.toLocaleString(undefined, { minimumFractionDigits: 2 })}` : '—'}
                  </td>
                  <td
                    className={`py-3 px-3 text-right font-mono tabular-nums font-semibold whitespace-nowrap ${
                      row.varianceAmount && Math.abs(row.varianceAmount) > 0
                        ? 'text-red-700'
                        : 'text-slate-500'
                    }`}
                  >
                    {row.varianceAmount !== undefined
                      ? `$${row.varianceAmount.toLocaleString(undefined, { minimumFractionDigits: 2 })}`
                      : '—'}
                  </td>
                  <td className="py-3 px-4 text-slate-700 leading-relaxed min-w-[280px]">
                    {row.details}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
