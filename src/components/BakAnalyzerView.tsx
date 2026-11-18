import React, { useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  FileText,
  FolderInput,
  ShieldAlert,
  Sparkles,
  Upload,
} from 'lucide-react';
import type { BakAnalysisResult, BakPiiDetection } from '../types/forensic';

interface BakAnalyzerViewProps {
  bakAnalyses: (BakAnalysisResult & { kdpaPiiDetections?: BakPiiDetection[] })[];
  token: string;
  onAnalysisComplete: (payload: {
    analysis: BakAnalysisResult;
    bakAnalyses: BakAnalysisResult[];
    evidenceItems?: unknown[];
    auditLogs?: unknown[];
    vaultStatus?: unknown;
  }) => void;
  onExportPdf: () => void;
}

const CHUNK_SIZE_BYTES = 8 * 1024 * 1024; // 8 MB chunks for unlimited multi-GB streaming uploads

export const BakAnalyzerView: React.FC<BakAnalyzerViewProps> = ({
  bakAnalyses,
  token,
  onAnalysisComplete,
  onExportPdf,
}) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(
    bakAnalyses[0]?.evidenceId || null
  );
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<{
    sentBytes: number;
    totalBytes: number;
    stage: string;
  } | null>(null);
  const [localPath, setLocalPath] = useState('/mnt/forensic_evidence/Enterprise_15GB.bak');
  const [encryptLocalCopy, setEncryptLocalCopy] = useState(false);
  const [assessingId, setAssessingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const activeAnalysis =
    bakAnalyses.find((b) => b.evidenceId === selectedId) || bakAnalyses[0] || null;

  /**
   * Unlimited-size chunked streaming upload (8 MB sequential frames).
   * Capable of ingesting 15 GB+ .bak files without exhausting browser or Node RAM.
   */
  const handleFileUpload = async (file: File) => {
    setError(null);
    setUploading(true);
    setUploadProgress({ sentBytes: 0, totalBytes: file.size, stage: 'Initializing encrypted staging stream...' });

    try {
      const initRes = await fetch('/api/evidence/chunk-init', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const initData = await initRes.json();
      if (!initRes.ok) {
        setError(initData.error || 'Failed to initialize streaming upload.');
        return;
      }

      const uploadId = initData.uploadId as string;
      let offset = 0;

      while (offset < file.size) {
        const end = Math.min(offset + CHUNK_SIZE_BYTES, file.size);
        const slice = file.slice(offset, end);
        const buf = await slice.arrayBuffer();

        const partRes = await fetch('/api/evidence/chunk-part', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/octet-stream',
            'x-upload-id': uploadId,
          },
          body: buf,
        });
        const partData = await partRes.json();
        if (!partRes.ok) {
          setError(partData.error || 'Chunk upload failed.');
          return;
        }
        offset = end;
        setUploadProgress({
          sentBytes: offset,
          totalBytes: file.size,
          stage: 'Streaming 8 MB encrypted frames to vault...',
        });
      }

      setUploadProgress({
        sentBytes: file.size,
        totalBytes: file.size,
        stage: 'Computing SHA-256 / SHA-512, AES-256-GCM sealing, and assessing schema...',
      });

      const finRes = await fetch('/api/evidence/chunk-finalize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          uploadId,
          fileName: file.name,
          runAi: true,
          encryptCopy: true,
        }),
      });
      const finData = await finRes.json();
      if (!finRes.ok) {
        setError(finData.error || 'Failed to finalize backup analysis.');
        return;
      }
      setSelectedId(finData.analysis.evidenceId);
      onAnalysisComplete(finData);
    } catch {
      setError('Network error during streaming backup upload.');
    } finally {
      setUploading(false);
      setUploadProgress(null);
    }
  };

  const handleIngestLocalPath = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!localPath.trim()) return;
    setError(null);
    setUploading(true);
    setUploadProgress({
      sentBytes: 0,
      totalBytes: 1,
      stage: `Streaming ${localPath.trim()} directly from Hyper-V / local disk...`,
    });
    try {
      const res = await fetch('/api/evidence/ingest-local-path', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          filePath: localPath.trim(),
          runAi: true,
          encryptCopy: encryptLocalCopy,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Failed to ingest local path.');
        return;
      }
      setSelectedId(data.analysis.evidenceId);
      onAnalysisComplete(data);
    } catch {
      setError('Failed to contact server for local path streaming.');
    } finally {
      setUploading(false);
      setUploadProgress(null);
    }
  };

  const handleLoadSampleBak = async () => {
    setError(null);
    setUploading(true);
    try {
      const res = await fetch('/api/evidence/load-sample-bak', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Failed to process sample .bak artifact.');
        return;
      }
      setSelectedId(data.analysis.evidenceId);
      onAnalysisComplete(data);
    } catch {
      setError('Failed to contact server for sample .bak processing.');
    } finally {
      setUploading(false);
    }
  };

  const handleReRunAssessment = async (evidenceId: string) => {
    setError(null);
    setAssessingId(evidenceId);
    try {
      const res = await fetch(`/api/evidence/assess-bak/${evidenceId}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Architectural assessment failed.');
        return;
      }
      onAnalysisComplete(data);
    } catch {
      setError('Failed to run architectural assessment.');
    } finally {
      setAssessingId(null);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    return `${bytes.toLocaleString()} B`;
  };

  return (
    <div className="space-y-6">
      {/* Intake & Multi-GB Streaming Dropzone Panel */}
      <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-slate-900">
              Enterprise RDBMS Backup (.bak) Processor — Unlimited Multi-GB Streaming
            </h1>
            <p className="mt-1 text-xs text-slate-600 max-w-3xl leading-relaxed">
              Streams multi-gigabyte (15 GB+) Microsoft SQL Server <span className="font-mono">.bak</span> (MTF), PostgreSQL <span className="font-mono">PGDMP</span>, SQLite, or <span className="font-mono">.sql</span> backups in 8 MB constant-RAM chunks. Computes full-file SHA-256/SHA-512 hashes, detects Kenya DPA 2019 regulated PII columns, and generates a complete architectural assessment.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={handleLoadSampleBak}
              disabled={uploading}
              className="px-3.5 py-2 bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-medium rounded-md transition-colors whitespace-nowrap"
            >
              {uploading ? 'Processing...' : 'Process Sample Enterprise .bak'}
            </button>
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="px-4 py-2 bg-blue-700 hover:bg-blue-800 disabled:bg-blue-400 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>{uploading ? 'Streaming File...' : 'Stream Upload .bak (No Size Limit)'}</span>
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".bak,.sql,.dump,.csv,.json,.db,.sqlite"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFileUpload(file);
                e.target.value = '';
              }}
            />
          </div>
        </div>

        {/* Direct Local / Ubuntu Hyper-V Disk Mount Path (Zero HTTP Transfer for 15 GB+ DBs) */}
        <form onSubmit={handleIngestLocalPath} className="pt-4 border-t border-slate-200 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <div className="text-xs font-semibold text-slate-900">
                Direct Local / Hyper-V Mounted File Reference (Recommended for 15 GB+ Databases)
              </div>
              <p className="text-[11px] text-slate-500">
                Read directly from your Ubuntu Hyper-V read-only evidence mount without duplicating 15 GB over HTTP.
              </p>
            </div>
            <label className="inline-flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={encryptLocalCopy}
                onChange={(e) => setEncryptLocalCopy(e.target.checked)}
                className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
              />
              <span>Create encrypted AES-256-GCM vault copy (requires +15 GB free disk)</span>
            </label>
          </div>

          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <FolderInput className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={localPath}
                onChange={(e) => setLocalPath(e.target.value)}
                placeholder="/mnt/forensic_evidence/production_15gb.bak"
                className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            <button
              type="submit"
              disabled={uploading || !localPath.trim()}
              className="px-4 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              Stream-Analyze Local Path
            </button>
          </div>
        </form>

        {uploadProgress && (
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-md space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-700">
              <span>{uploadProgress.stage}</span>
              {uploadProgress.totalBytes > 1 && (
                <span className="font-mono tabular-nums">
                  {formatBytes(uploadProgress.sentBytes)} / {formatBytes(uploadProgress.totalBytes)} (
                  {Math.round((uploadProgress.sentBytes / uploadProgress.totalBytes) * 100)}%)
                </span>
              )}
            </div>
            <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-700 transition-all duration-200"
                style={{
                  width:
                    uploadProgress.totalBytes > 1
                      ? `${Math.round((uploadProgress.sentBytes / uploadProgress.totalBytes) * 100)}%`
                      : '100%',
                }}
              />
            </div>
          </div>
        )}

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-md flex items-start gap-2.5 text-xs text-red-800">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Empty State */}
      {!activeAnalysis ? (
        <div className="bg-white border border-dashed border-slate-300 rounded-lg p-12 text-center">
          <Database className="w-10 h-10 text-slate-400 mx-auto" />
          <h2 className="mt-4 text-base font-semibold text-slate-900">
            No RDBMS Backup Processed Yet
          </h2>
          <p className="mt-1.5 text-xs text-slate-600 max-w-lg mx-auto leading-relaxed">
            Stream your multi-GB <span className="font-mono">.bak</span> file above, point directly to your mounted file path on Ubuntu Hyper-V, or click <span className="font-medium text-slate-900">Process Sample Enterprise .bak</span>.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {bakAnalyses.length > 1 && (
            <div className="flex flex-wrap items-center gap-2">
              {bakAnalyses.map((b) => (
                <button
                  key={b.evidenceId}
                  type="button"
                  onClick={() => setSelectedId(b.evidenceId)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors ${
                    b.evidenceId === activeAnalysis.evidenceId
                      ? 'bg-slate-900 text-white border-slate-900'
                      : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                  }`}
                >
                  {b.evidenceId} · {b.fileName}
                </button>
              ))}
            </div>
          )}

          {/* Extracted Technical Telemetry */}
          <div className="bg-white border border-slate-200 rounded-lg p-6">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-4 border-b border-slate-200">
              <div>
                <div className="text-xs text-slate-500 font-mono">
                  {activeAnalysis.evidenceId} · {activeAnalysis.detectedFormat}
                </div>
                <h2 className="mt-1 text-lg font-semibold text-slate-900">
                  {activeAnalysis.fileName}
                </h2>
              </div>
              <div className="flex items-center gap-2.5 shrink-0">
                <button
                  type="button"
                  onClick={() => handleReRunAssessment(activeAnalysis.evidenceId)}
                  disabled={assessingId === activeAnalysis.evidenceId}
                  className="px-3.5 py-2 bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
                >
                  <Sparkles className="w-3.5 h-3.5 text-blue-700" />
                  <span>
                    {assessingId === activeAnalysis.evidenceId
                      ? 'Generating Assessment...'
                      : 'Refresh Assessment'}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={onExportPdf}
                  className="px-3.5 py-2 bg-blue-700 hover:bg-blue-800 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Export Assessment PDF</span>
                </button>
              </div>
            </div>

            <div className="mt-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
              <div>
                <div className="text-slate-500">RDBMS Engine</div>
                <div className="mt-1 font-medium text-slate-900">{activeAnalysis.engineGuess}</div>
              </div>
              <div>
                <div className="text-slate-500">Database / Instance</div>
                <div className="mt-1 font-mono text-slate-900">
                  {activeAnalysis.databaseName} ({activeAnalysis.serverOrInstance})
                </div>
              </div>
              <div>
                <div className="text-slate-500">Size / Magic Hex</div>
                <div className="mt-1 font-mono tabular-nums text-slate-900">
                  {formatBytes(activeAnalysis.fileSizeBytes)} · {activeAnalysis.magicSignatureHex.slice(0, 16)}
                </div>
              </div>
              <div>
                <div className="text-slate-500">SHA-256 Custody Digest</div>
                <div className="mt-1 font-mono text-slate-900 truncate" title={activeAnalysis.sha256}>
                  {activeAnalysis.sha256}
                </div>
              </div>
            </div>

            {activeAnalysis.logicalFiles.length > 0 && (
              <div className="mt-4 pt-4 border-t border-slate-200 text-xs">
                <span className="text-slate-500">Recovered Physical / Logical Files: </span>
                <span className="font-mono text-slate-800">
                  {activeAnalysis.logicalFiles.join(' · ')}
                </span>
              </div>
            )}
          </div>

          {/* Kenya DPA 2019 PII Column Detections */}
          {activeAnalysis.kdpaPiiDetections && activeAnalysis.kdpaPiiDetections.length > 0 && (
            <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-700" />
                <h3 className="text-sm font-semibold text-slate-900">
                  Kenya Data Protection Act, 2019 — Regulated PII &amp; Financial Identifier Columns
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
                      <th className="py-2.5 px-4">Table</th>
                      <th className="py-2.5 px-3">Column</th>
                      <th className="py-2.5 px-3">KDPA 2019 Classification</th>
                      <th className="py-2.5 px-4">Required Safeguard (Sec. 41 / Sec. 48)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {activeAnalysis.kdpaPiiDetections.map((d, i) => (
                      <tr key={i}>
                        <td className="py-2.5 px-4 font-mono text-slate-900">{d.tableName}</td>
                        <td className="py-2.5 px-3 font-mono font-semibold text-slate-900">{d.columnName}</td>
                        <td className="py-2.5 px-3 text-amber-800 font-medium">{d.kdpaCategory}</td>
                        <td className="py-2.5 px-4 text-slate-600">{d.protectionStatus}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Architectural Assessment */}
          {activeAnalysis.architecturalAssessment && (
            <div className="bg-white border border-slate-200 rounded-lg divide-y divide-slate-200">
              <div className="p-6">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-base font-semibold text-slate-900">
                    Detailed RDBMS Architectural Assessment
                  </h3>
                  <span
                    className={`text-xs font-semibold ${
                      activeAnalysis.architecturalAssessment.overallPosture === 'Sound'
                        ? 'text-emerald-700'
                        : activeAnalysis.architecturalAssessment.overallPosture.includes('Critical')
                          ? 'text-red-700'
                          : 'text-amber-700'
                    }`}
                  >
                    Posture: {activeAnalysis.architecturalAssessment.overallPosture}
                  </span>
                </div>
                <p className="mt-3 text-sm text-slate-700 leading-relaxed">
                  {activeAnalysis.architecturalAssessment.executiveSummary}
                </p>
              </div>

              <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 text-xs leading-relaxed">
                <div>
                  <h4 className="font-semibold text-slate-900">RDBMS Topology &amp; Schema Posture</h4>
                  <p className="mt-2 text-slate-600">
                    {activeAnalysis.architecturalAssessment.rdbmsTopologySummary}
                  </p>
                </div>
                <div>
                  <h4 className="font-semibold text-slate-900">Temporal &amp; Timestamp Integrity</h4>
                  <p className="mt-2 text-slate-600">
                    {activeAnalysis.architecturalAssessment.temporalIntegrityAnalysis}
                  </p>
                </div>
                <div>
                  <h4 className="font-semibold text-slate-900">Access Control &amp; Privileges</h4>
                  <p className="mt-2 text-slate-600">
                    {activeAnalysis.architecturalAssessment.accessControlAndPrivilegeAnalysis}
                  </p>
                </div>
              </div>

              <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-sm font-semibold text-slate-900 mb-3">
                    ALCOA+ Data Integrity Evaluation
                  </h4>
                  <div className="border border-slate-200 rounded-md overflow-hidden">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
                          <th className="py-2 px-3">Principle</th>
                          <th className="py-2 px-3">Status</th>
                          <th className="py-2 px-3">Observation</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200">
                        {activeAnalysis.architecturalAssessment.alcoaPlusAssessment.map((row, idx) => (
                          <tr key={idx}>
                            <td className="py-2 px-3 font-medium text-slate-900">{row.principle}</td>
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
                            <td className="py-2 px-3 text-slate-600">{row.observation}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-slate-900 mb-3">
                    Compliance Framework Mapping (KDPA 2019 / ISO / SOX)
                  </h4>
                  <div className="space-y-3">
                    {activeAnalysis.architecturalAssessment.complianceMapping.map((c, idx) => (
                      <div key={idx} className="p-3 bg-slate-50 border border-slate-200 rounded-md text-xs">
                        <div className="flex items-center justify-between font-semibold text-slate-900">
                          <span>{c.framework}</span>
                          <span className="text-slate-600">{c.status}</span>
                        </div>
                        <p className="mt-1 text-slate-600">{c.gapSummary}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Discovered Tables & Holistic Backup Findings */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-200">
                <h3 className="text-sm font-semibold text-slate-900">
                  Discovered Schema &amp; Tables ({activeAnalysis.discoveredTables.length})
                </h3>
              </div>
              <div className="divide-y divide-slate-200">
                {activeAnalysis.discoveredTables.map((tbl, idx) => (
                  <div key={idx} className="px-6 py-3.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-semibold text-slate-900">
                        {tbl.schemaName}.{tbl.tableName}
                      </span>
                      <div className="flex items-center gap-2 text-[11px]">
                        <span className={tbl.hasAuditTimestamps ? 'text-emerald-700' : 'text-amber-700'}>
                          {tbl.hasAuditTimestamps ? 'Timestamps Present' : 'No Timestamps'}
                        </span>
                        <span className="text-slate-300">·</span>
                        <span className={tbl.hasActorColumn ? 'text-emerald-700' : 'text-amber-700'}>
                          {tbl.hasActorColumn ? 'Actor Column' : 'No Actor'}
                        </span>
                      </div>
                    </div>
                    <div className="mt-1 font-mono text-[11px] text-slate-500">
                      Columns: {tbl.estimatedColumns.join(', ')}
                    </div>
                    {tbl.riskNotes.length > 0 && (
                      <div className="mt-1.5 text-amber-800">{tbl.riskNotes.join(' ')}</div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-200">
                <h3 className="text-sm font-semibold text-slate-900">
                  Prioritized Backup Findings ({(activeAnalysis.architecturalAssessment?.prioritizedFindings || activeAnalysis.holisticFindings).length})
                </h3>
              </div>
              <div className="divide-y divide-slate-200">
                {(activeAnalysis.architecturalAssessment?.prioritizedFindings || activeAnalysis.holisticFindings).map(
                  (f, idx) => (
                    <div key={idx} className="px-6 py-3.5 text-xs">
                      <div className="flex items-center gap-2">
                        {f.severity === 'Critical' ? (
                          <AlertTriangle className="w-3.5 h-3.5 text-red-700 shrink-0" />
                        ) : (
                          <CheckCircle2 className="w-3.5 h-3.5 text-amber-700 shrink-0" />
                        )}
                        <span className="font-semibold text-slate-900">{f.title}</span>
                      </div>
                      <p className="mt-1 text-slate-600">{f.evidenceSummary}</p>
                      <div className="mt-1.5 text-slate-500">
                        Recommendation: <span className="text-slate-800">{f.recommendation}</span>
                      </div>
                    </div>
                  )
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
