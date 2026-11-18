import React, { useState } from 'react';
import { AlertTriangle, FileText, Send, Sparkles } from 'lucide-react';
import type { ComprehensiveReport } from '../types/forensic';

interface ForensicEnquiryViewProps {
  token: string;
  activeReport: ComprehensiveReport | null;
  onReportGenerated: (report: ComprehensiveReport, auditLogs?: unknown[]) => void;
  onExportPdf: (report: ComprehensiveReport | null) => void;
}

const PRESET_ENQUIRIES = [
  'Identify every database entry with suspected timestamp backdating or sequence inversion, and explain the forensic proof.',
  'Cross-reference the Excel transaction variances with off-hours sysadmin activity to assess potential fraud schemes under ACFE standards.',
  'Evaluate whether the database logs comply with ALCOA+ contemporaneous and attributable data integrity principles.',
  'Summarize the key RDBMS architectural weaknesses discovered and provide prioritized SQL Server / PostgreSQL remediation steps.',
];

export const ForensicEnquiryView: React.FC<ForensicEnquiryViewProps> = ({
  token,
  activeReport,
  onReportGenerated,
  onExportPdf,
}) => {
  const [question, setQuestion] = useState('');
  const [messages, setMessages] = useState<{ role: 'auditor' | 'analyst'; text: string; ts: string }[]>([]);
  const [asking, setAsking] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [caseTitle, setCaseTitle] = useState('Enterprise ERP Financial Ledger & Backup Forensic Audit');
  const [error, setError] = useState<string | null>(null);

  const submitEnquiry = async (promptText: string) => {
    const q = promptText.trim();
    if (!q) return;
    setError(null);
    setAsking(true);
    setMessages((prev) => [...prev, { role: 'auditor', text: q, ts: new Date().toISOString() }]);
    setQuestion('');

    try {
      const res = await fetch('/api/ai/enquiry', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ question: q }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Forensic enquiry failed.');
        return;
      }
      setMessages((prev) => [
        ...prev,
        { role: 'analyst', text: data.answer, ts: new Date().toISOString() },
      ]);
    } catch {
      setError('Network error communicating with Gemini forensic service.');
    } finally {
      setAsking(false);
    }
  };

  const handleGenerateReport = async () => {
    setError(null);
    setGeneratingReport(true);
    try {
      const res = await fetch('/api/ai/comprehensive-report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ caseTitle }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Failed to generate comprehensive forensic report.');
        return;
      }
      onReportGenerated(data.report, data.auditLogs);
    } catch {
      setError('Network error while generating compliance report.');
    } finally {
      setGeneratingReport(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Comprehensive Compliance Report Builder */}
      <div className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
          <div className="flex-1 max-w-2xl">
            <h1 className="text-xl font-semibold text-slate-900">
              Comprehensive Forensic Findings Report &amp; AI Enquiry
            </h1>
            <p className="mt-1 text-xs text-slate-600 leading-relaxed">
              Synthesize all audit logs, timestamp tampering detections, Excel transaction variances, and <span className="font-mono">.bak</span> architectural assessments into a formal compliance report using Gemini AI.
            </p>
            <div className="mt-4">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Compliance Report Case Title
              </label>
              <input
                type="text"
                value={caseTitle}
                onChange={(e) => setCaseTitle(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={handleGenerateReport}
              disabled={generatingReport}
              className="px-4 py-2.5 bg-blue-700 hover:bg-blue-800 disabled:bg-blue-400 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>
                {generatingReport ? 'Synthesizing Report...' : 'Generate Comprehensive Report'}
              </span>
            </button>
            <button
              type="button"
              onClick={() => onExportPdf(activeReport)}
              className="px-4 py-2.5 bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export PDF Package</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md flex items-start gap-2 text-xs text-red-800">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Rendered Comprehensive Report */}
      {activeReport && (
        <div className="bg-white border border-slate-200 rounded-lg divide-y divide-slate-200">
          <div className="p-6">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
              <span className="font-mono">{activeReport.reportId}</span>
              <span className="font-mono tabular-nums">
                Generated {activeReport.generatedAtUtc} · {activeReport.generatedBy}
              </span>
            </div>
            <h2 className="mt-1.5 text-lg font-semibold text-slate-900">
              {activeReport.caseTitle}
            </h2>
            <p className="mt-3 text-sm text-slate-700 leading-relaxed">
              {activeReport.executiveSummary}
            </p>
          </div>

          <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6 text-xs leading-relaxed">
            <div>
              <h3 className="font-semibold text-slate-900">Chain of Custody Statement</h3>
              <p className="mt-2 text-slate-600">{activeReport.chainOfCustodyStatement}</p>
            </div>
            <div>
              <h3 className="font-semibold text-slate-900">Excel Cross-Reference Narrative</h3>
              <p className="mt-2 text-slate-600">{activeReport.crossReferenceNarrative}</p>
            </div>
          </div>

          <div className="p-6">
            <h3 className="text-sm font-semibold text-slate-900 mb-3">
              ALCOA+ International Data Integrity Assessment
            </h3>
            <div className="border border-slate-200 rounded-md overflow-hidden">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
                    <th className="py-2 px-3">Principle</th>
                    <th className="py-2 px-3">Status</th>
                    <th className="py-2 px-3">Forensic Notes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {activeReport.alcoaPlusMatrix.map((row, idx) => (
                    <tr key={idx}>
                      <td className="py-2 px-3 font-medium text-slate-900 whitespace-nowrap">
                        {row.principle}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span
                          className={`font-semibold ${
                            row.status === 'Compliant'
                              ? 'text-emerald-700'
                              : row.status === 'Partial'
                                ? 'text-amber-700'
                                : 'text-red-700'
                          }`}
                        >
                          {row.status}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-slate-600">{row.notes}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="p-6 text-xs leading-relaxed">
            <h3 className="text-sm font-semibold text-slate-900">
              Architectural &amp; Fraud Remediation Recommendations
            </h3>
            <ol className="mt-3 space-y-2 list-decimal list-inside text-slate-700">
              {activeReport.recommendations.map((rec, i) => (
                <li key={i}>{rec}</li>
              ))}
            </ol>
          </div>
        </div>
      )}

      {/* Interactive Forensic Enquiry Console */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200">
          <h2 className="text-base font-semibold text-slate-900">
            Interactive Forensic Enquiry (Gemini AI)
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Ask targeted investigative questions grounded in the encrypted audit logs, Excel reconciliation variances, and RDBMS <span className="font-mono">.bak</span> metadata.
          </p>
        </div>

        <div className="p-6 space-y-4">
          {/* Quick Enquiry Prompts */}
          <div className="flex flex-wrap gap-2">
            {PRESET_ENQUIRIES.map((preset, i) => (
              <button
                key={i}
                type="button"
                onClick={() => submitEnquiry(preset)}
                disabled={asking}
                className="text-left px-3 py-1.5 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-md text-xs text-slate-700 transition-colors"
              >
                {preset}
              </button>
            ))}
          </div>

          {/* Conversation History */}
          {messages.length > 0 && (
            <div className="border border-slate-200 rounded-md divide-y divide-slate-200 max-h-[460px] overflow-y-auto">
              {messages.map((m, idx) => (
                <div
                  key={idx}
                  className={`p-4 text-xs leading-relaxed ${
                    m.role === 'auditor' ? 'bg-slate-50' : 'bg-white'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] text-slate-500 mb-1.5">
                    <span className="font-semibold text-slate-800">
                      {m.role === 'auditor' ? 'Lead Auditor Enquiry' : 'Gemini Forensic Analysis'}
                    </span>
                    <span className="font-mono tabular-nums">
                      {m.ts.replace('T', ' ').slice(0, 19)}Z
                    </span>
                  </div>
                  <div className="whitespace-pre-wrap text-slate-800">{m.text}</div>
                </div>
              ))}
            </div>
          )}

          {/* Input Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              submitEnquiry(question);
            }}
            className="flex flex-col sm:flex-row gap-2.5"
          >
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Enter forensic enquiry (e.g. 'Trace all actions by sa between 02:45 and 03:20 UTC')..."
              className="flex-1 px-3.5 py-2.5 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
            <button
              type="submit"
              disabled={asking || !question.trim()}
              className="px-4 py-2.5 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white text-xs font-medium rounded-md transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{asking ? 'Analyzing...' : 'Run Enquiry'}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
