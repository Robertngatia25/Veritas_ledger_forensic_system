import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Download,
  FileText,
  RefreshCw,
  Search,
  Sparkles,
  X,
} from 'lucide-react';
import type { AuditCategory, AuditEvent, AuditSeverity } from '../types/forensic';

interface EventAiExplanation {
  riskAssessment: string;
  fraudSchemeClassification: string;
  temporalVerdict: string;
  recommendedAction: string;
}

const VALID_SEVERITIES: ReadonlyArray<'All' | AuditSeverity> = [
  'All',
  'Critical',
  'Warning',
  'Nominal',
];

const VALID_CATEGORIES: ReadonlyArray<'All' | AuditCategory> = [
  'All',
  'Authentication',
  'DML / Schema Change',
  'Timestamp Anomaly',
  'Cross-Ref Discrepancy',
  'Evidence Custody',
  'System & Vault',
];

interface AuditTrailExplorerProps {
  token: string;
  auditLogs: AuditEvent[];
  onRunHolisticScan: () => void;
  scanning: boolean;
  onExportCsv: (filteredLogs: AuditEvent[]) => void;
  onExportPdf: () => void;
  onAuditLogsUpdated?: (logs: AuditEvent[]) => void;
}

export const AuditTrailExplorer: React.FC<AuditTrailExplorerProps> = ({
  token,
  auditLogs,
  onRunHolisticScan,
  scanning,
  onExportCsv,
  onExportPdf,
  onAuditLogsUpdated,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'All' | AuditSeverity>('All');
  const [categoryFilter, setCategoryFilter] = useState<'All' | AuditCategory>('All');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // AI Smart Filter state
  const [nlQuery, setNlQuery] = useState('');
  const [nlFiltering, setNlFiltering] = useState(false);
  const [nlInterpretation, setNlInterpretation] = useState<string | null>(null);
  const [nlError, setNlError] = useState<string | null>(null);

  // Per-event AI Explanation state
  const [explanationsById, setExplanationsById] = useState<Record<string, EventAiExplanation>>({});
  const [explainingId, setExplainingId] = useState<string | null>(null);
  const [explainErrorsById, setExplainErrorsById] = useState<Record<string, string>>({});

  const handleApplyNlFilter = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!nlQuery.trim()) return;
    setNlError(null);
    setNlFiltering(true);
    try {
      const res = await fetch('/api/ai/nl-filter', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ query: nlQuery.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setNlError(data.error || 'Unable to parse AI filter query.');
        return;
      }
      const f = data.filter || {};
      const nextSeverity = VALID_SEVERITIES.includes(f.severity) ? f.severity : 'All';
      const nextCategory = VALID_CATEGORIES.includes(f.category) ? f.category : 'All';
      setSearchQuery(typeof f.searchText === 'string' ? f.searchText : '');
      setSeverityFilter(nextSeverity);
      setCategoryFilter(nextCategory);
      setNlInterpretation(
        f.explanation ||
          `Applied severity=${nextSeverity}, category=${nextCategory}${f.searchText ? `, keyword="${f.searchText}"` : ''}.`
      );
    } catch {
      setNlError('Network error translating natural-language filter.');
    } finally {
      setNlFiltering(false);
    }
  };

  const handleExplainEvent = async (eventId: string) => {
    setExplainErrorsById((prev) => {
      const next = { ...prev };
      delete next[eventId];
      return next;
    });
    setExplainingId(eventId);
    try {
      const res = await fetch('/api/ai/explain-event', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ eventId }),
      });
      const data = await res.json();
      if (!res.ok) {
        setExplainErrorsById((prev) => ({
          ...prev,
          [eventId]: data.error || 'Unable to generate AI event explanation.',
        }));
        return;
      }
      if (data.explanation) {
        setExplanationsById((prev) => ({ ...prev, [eventId]: data.explanation }));
      }
      if (Array.isArray(data.auditLogs) && onAuditLogsUpdated) {
        onAuditLogsUpdated(data.auditLogs);
      }
    } catch {
      setExplainErrorsById((prev) => ({
        ...prev,
        [eventId]: 'Network error explaining audit event.',
      }));
    } finally {
      setExplainingId(null);
    }
  };

  const filteredLogs = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return [...auditLogs]
      .sort((a, b) => b.sequenceId - a.sequenceId)
      .filter((log) => {
        if (severityFilter !== 'All' && log.severity !== severityFilter) return false;
        if (categoryFilter !== 'All' && log.category !== categoryFilter) return false;
        if (dateFrom) {
          const fromMs = Date.parse(dateFrom);
          if (!Number.isNaN(fromMs) && Date.parse(log.timestampUtc) < fromMs) return false;
        }
        if (dateTo) {
          const toMs = Date.parse(dateTo) + 86400000;
          if (!Number.isNaN(toMs) && Date.parse(log.timestampUtc) > toMs) return false;
        }
        if (!q) return true;
        const haystack = [
          log.id,
          String(log.sequenceId),
          log.actor,
          log.actorRole,
          log.sourceIp,
          log.action,
          log.targetObject,
          log.transactionCode || '',
          log.sqlStatement || '',
          log.recordHash,
          log.anomalyFlags.join(' '),
        ]
          .join(' ')
          .toLowerCase();
        return haystack.includes(q);
      });
  }, [auditLogs, searchQuery, severityFilter, categoryFilter, dateFrom, dateTo]);

  return (
    <div className="space-y-6">
      {/* Toolbar & Controls */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-slate-900">
              Searchable Timestamped Audit Trail
            </h1>
            <p className="text-xs text-slate-500 mt-1">
              Cryptographically linked event ledger ({filteredLogs.length} of {auditLogs.length} records shown). Click any row to inspect before/after payloads and SHA-256 chain hashes.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={onRunHolisticScan}
              disabled={scanning}
              className="px-3.5 py-2 bg-blue-700 hover:bg-blue-800 disabled:bg-blue-400 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
              <span>{scanning ? 'Scanning...' : 'Verify Timestamps'}</span>
            </button>
            <button
              type="button"
              onClick={() => onExportCsv(filteredLogs)}
              className="px-3.5 py-2 bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
            <button
              type="button"
              onClick={onExportPdf}
              className="px-3.5 py-2 bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export PDF</span>
            </button>
          </div>
        </div>

        {/* AI Smart Natural-Language Filter */}
        <form onSubmit={handleApplyNlFilter} className="pt-3 border-t border-slate-200 space-y-2">
          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <Sparkles className="w-4 h-4 text-blue-700 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={nlQuery}
                onChange={(e) => setNlQuery(e.target.value)}
                placeholder='AI Smart Filter: e.g. "critical timestamp anomalies on gl_journal_entries" or "sa updates"...'
                className="w-full pl-9 pr-3 py-2 text-xs bg-slate-50 border border-slate-300 rounded-md focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
              />
            </div>
            <button
              type="submit"
              disabled={nlFiltering || !nlQuery.trim()}
              className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white text-xs font-medium rounded-md transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <Sparkles className="w-3.5 h-3.5 text-blue-300" />
              <span>{nlFiltering ? 'Translating...' : 'AI Smart Filter'}</span>
            </button>
          </div>

          {nlError && (
            <div className="text-xs text-red-700 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span>{nlError}</span>
            </div>
          )}

          {nlInterpretation && (
            <div className="px-3 py-2 bg-slate-50 border border-slate-200 rounded-md flex items-center justify-between gap-3 text-xs text-slate-700">
              <div>
                <span className="font-semibold text-slate-900">AI Filter Applied:</span>{' '}
                <span>{nlInterpretation}</span>
              </div>
              <button
                type="button"
                onClick={() => setNlInterpretation(null)}
                className="text-slate-400 hover:text-slate-700 shrink-0"
                aria-label="Dismiss AI filter interpretation"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </form>

        {/* Search & Filters */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 pt-3 border-t border-slate-200">
          <div className="md:col-span-5 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search actor, TXN code, SQL, target table, or SHA-256 hash..."
              className="w-full pl-9 pr-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
            />
          </div>

          <div className="md:col-span-3">
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as 'All' | AuditCategory)}
              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            >
              <option value="All">All Categories</option>
              <option value="Authentication">Authentication</option>
              <option value="DML / Schema Change">DML / Schema Change</option>
              <option value="Timestamp Anomaly">Timestamp Anomaly</option>
              <option value="Cross-Ref Discrepancy">Cross-Ref Discrepancy</option>
              <option value="Evidence Custody">Evidence Custody</option>
              <option value="System & Vault">System &amp; Vault</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              aria-label="Filter from date"
              className="w-full px-2.5 py-2 text-xs bg-white border border-slate-300 rounded-md font-mono focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="md:col-span-2">
            <input
              type="date"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              aria-label="Filter to date"
              className="w-full px-2.5 py-2 text-xs bg-white border border-slate-300 rounded-md font-mono focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {/* Interactive Severity Segmented Filter */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
            {(['All', 'Critical', 'Warning', 'Nominal'] as const).map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  severityFilter === sev
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {(searchQuery || severityFilter !== 'All' || categoryFilter !== 'All' || dateFrom || dateTo || nlInterpretation) && (
            <button
              type="button"
              onClick={() => {
                setSearchQuery('');
                setSeverityFilter('All');
                setCategoryFilter('All');
                setDateFrom('');
                setDateTo('');
                setNlQuery('');
                setNlInterpretation(null);
                setNlError(null);
              }}
              className="text-xs font-medium text-blue-700 hover:text-blue-800"
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* High-Density Audit Log Table */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-semibold text-slate-600">
                <th className="py-3 px-4 w-8"></th>
                <th className="py-3 px-3 whitespace-nowrap">Seq #</th>
                <th className="py-3 px-3 whitespace-nowrap">Business Timestamp (UTC)</th>
                <th className="py-3 px-3 whitespace-nowrap">Actor / Principal</th>
                <th className="py-3 px-3 whitespace-nowrap">Action &amp; Object</th>
                <th className="py-3 px-3 whitespace-nowrap">TXN Code</th>
                <th className="py-3 px-3 text-right whitespace-nowrap">Amount</th>
                <th className="py-3 px-4 whitespace-nowrap">Integrity State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-xs">
              {filteredLogs.map((log) => {
                const isExpanded = expandedId === log.id;
                return (
                  <React.Fragment key={log.id}>
                    <tr
                      onClick={() => setExpandedId(isExpanded ? null : log.id)}
                      className="hover:bg-slate-50 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 px-4 text-slate-400">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4" />
                        ) : (
                          <ChevronRight className="w-4 h-4" />
                        )}
                      </td>
                      <td className="py-2.5 px-3 font-mono tabular-nums text-slate-700 whitespace-nowrap">
                        #{log.sequenceId}
                      </td>
                      <td className="py-2.5 px-3 font-mono tabular-nums text-slate-800 whitespace-nowrap">
                        {log.timestampUtc.replace('T', ' ').replace('.000Z', 'Z')}
                      </td>
                      <td className="py-2.5 px-3 text-slate-800 max-w-[200px] truncate">
                        {log.actor}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-medium text-slate-900">{log.action}</div>
                        <div className="font-mono text-[11px] text-slate-500">{log.targetObject}</div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-700 whitespace-nowrap">
                        {log.transactionCode || '—'}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-900 whitespace-nowrap">
                        {typeof log.amount === 'number'
                          ? `$${log.amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}`
                          : '—'}
                      </td>
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          {log.severity === 'Critical' ? (
                            <AlertTriangle className="w-3.5 h-3.5 text-red-700 shrink-0" />
                          ) : log.severity === 'Warning' ? (
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-700 shrink-0" />
                          ) : (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                          )}
                          <span
                            className={`font-medium ${
                              log.severity === 'Critical'
                                ? 'text-red-700'
                                : log.severity === 'Warning'
                                  ? 'text-amber-700'
                                  : 'text-emerald-700'
                            }`}
                          >
                            {log.severity}
                          </span>
                          {log.anomalyFlags.length > 0 && (
                            <span className="text-slate-500 font-mono">
                              ({log.anomalyFlags.length})
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>

                    {isExpanded && (
                      <tr className="bg-slate-50">
                        <td colSpan={8} className="px-6 py-5 border-t border-slate-200">
                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            <div className="space-y-3">
                              <div className="text-xs font-semibold text-slate-900">
                                Forensic Provenance &amp; Temporal Telemetry
                              </div>
                              <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                                <dt className="text-slate-500">Event ID</dt>
                                <dd className="font-mono text-slate-800">{log.id}</dd>
                                <dt className="text-slate-500">System Recorded UTC</dt>
                                <dd className="font-mono tabular-nums text-slate-800">{log.recordedAtUtc}</dd>
                                <dt className="text-slate-500">Actor Role / IP</dt>
                                <dd className="font-mono text-slate-800">
                                  {log.actorRole} · {log.sourceIp}
                                </dd>
                                <dt className="text-slate-500">Category</dt>
                                <dd className="text-slate-800">{log.category}</dd>
                                <dt className="text-slate-500">Previous Block Hash</dt>
                                <dd className="font-mono text-[11px] text-slate-600 break-all">
                                  {log.prevHash}
                                </dd>
                                <dt className="text-slate-500">Current Record Hash</dt>
                                <dd className="font-mono text-[11px] text-slate-900 break-all">
                                  {log.recordHash}
                                </dd>
                              </dl>

                              {log.anomalyFlags.length > 0 && (
                                <div className="pt-2">
                                  <div className="text-xs font-semibold text-red-700">
                                    Triggered Anomaly Flags
                                  </div>
                                  <div className="mt-1 font-mono text-xs text-red-800">
                                    {log.anomalyFlags.join(' · ')}
                                  </div>
                                </div>
                              )}
                            </div>

                            <div className="space-y-3">
                              {log.sqlStatement && (
                                <div>
                                  <div className="text-xs font-semibold text-slate-900">
                                    Captured SQL / Operation
                                  </div>
                                  <pre className="mt-1.5 p-3 bg-slate-900 text-slate-100 rounded-md font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                                    {log.sqlStatement}
                                  </pre>
                                </div>
                              )}

                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div>
                                  <div className="text-xs font-semibold text-slate-700">Before State</div>
                                  <pre className="mt-1 p-2.5 bg-white border border-slate-200 rounded-md font-mono text-[11px] text-slate-700 overflow-x-auto">
                                    {log.beforeState ? JSON.stringify(log.beforeState, null, 2) : 'NULL (New Row)'}
                                  </pre>
                                </div>
                                <div>
                                  <div className="text-xs font-semibold text-slate-700">After State</div>
                                  <pre className="mt-1 p-2.5 bg-white border border-slate-200 rounded-md font-mono text-[11px] text-slate-700 overflow-x-auto">
                                    {log.afterState ? JSON.stringify(log.afterState, null, 2) : 'NULL'}
                                  </pre>
                                </div>
                              </div>
                            </div>
                          </div>

                          {/* Per-Event Gemini AI Forensic Explanation */}
                          <div className="mt-5 pt-4 border-t border-slate-200 space-y-3">
                            <div className="flex flex-wrap items-center justify-between gap-3">
                              <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                                <Sparkles className="w-3.5 h-3.5 text-blue-700" />
                                <span>Gemini AI Event Forensics &amp; Temporal Context</span>
                              </div>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleExplainEvent(log.id);
                                }}
                                disabled={explainingId === log.id}
                                className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
                              >
                                <Sparkles className="w-3.5 h-3.5 text-blue-300" />
                                <span>
                                  {explainingId === log.id
                                    ? 'Analyzing Event...'
                                    : explanationsById[log.id]
                                      ? 'Re-Analyze Event'
                                      : 'Explain Event with AI'}
                                </span>
                              </button>
                            </div>

                            {explainErrorsById[log.id] && (
                              <div className="p-2.5 bg-red-50 border border-red-200 rounded-md text-xs text-red-800 flex items-center gap-2">
                                <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
                                <span>{explainErrorsById[log.id]}</span>
                              </div>
                            )}

                            {explanationsById[log.id] && (
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-white border border-slate-200 rounded-md p-4 text-xs">
                                <div>
                                  <div className="font-semibold text-slate-900">Risk Assessment</div>
                                  <p className="mt-1 text-slate-700 leading-relaxed">
                                    {explanationsById[log.id].riskAssessment}
                                  </p>
                                </div>
                                <div>
                                  <div className="font-semibold text-slate-900">Fraud Scheme Classification</div>
                                  <p className="mt-1 text-slate-700 leading-relaxed">
                                    {explanationsById[log.id].fraudSchemeClassification}
                                  </p>
                                </div>
                                <div>
                                  <div className="font-semibold text-slate-900">Temporal Causality Verdict</div>
                                  <p className="mt-1 text-slate-700 leading-relaxed">
                                    {explanationsById[log.id].temporalVerdict}
                                  </p>
                                </div>
                                <div>
                                  <div className="font-semibold text-slate-900">Recommended Auditor Action</div>
                                  <p className="mt-1 text-slate-700 leading-relaxed">
                                    {explanationsById[log.id].recommendedAction}
                                  </p>
                                </div>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}

              {filteredLogs.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-sm text-slate-500">
                    No audit trail records match your current search or filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
