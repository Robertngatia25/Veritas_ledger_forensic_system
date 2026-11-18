import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type {
  AuditEvent,
  BakAnalysisResult,
  ComprehensiveReport,
  CrossRefSummary,
  EvidenceItem,
  HolisticFinding,
  VaultStatus,
} from '../types/forensic';

function csvEscape(val: unknown): string {
  const s = val === null || val === undefined ? '' : String(val);
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function exportAuditLogsToCsv(logs: AuditEvent[], filenamePrefix = 'veritas_audit_trail') {
  const headers = [
    'SequenceID',
    'EventID',
    'BusinessTimestampUTC',
    'RecordedAtUTC',
    'Actor',
    'ActorRole',
    'SourceIP',
    'Category',
    'Action',
    'TargetObject',
    'TransactionCode',
    'Amount',
    'Currency',
    'Severity',
    'AnomalyFlags',
    'PrevHashSHA256',
    'RecordHashSHA256',
  ];

  const rows = logs.map((e) =>
    [
      e.sequenceId,
      e.id,
      e.timestampUtc,
      e.recordedAtUtc,
      e.actor,
      e.actorRole,
      e.sourceIp,
      e.category,
      e.action,
      e.targetObject,
      e.transactionCode ?? '',
      e.amount ?? '',
      e.currency ?? '',
      e.severity,
      e.anomalyFlags.join('; '),
      e.prevHash,
      e.recordHash,
    ]
      .map(csvEscape)
      .join(',')
  );

  const csv = [headers.join(','), ...rows].join('\r\n');
  triggerDownload(
    new Blob([csv], { type: 'text/csv;charset=utf-8;' }),
    `${filenamePrefix}_${new Date().toISOString().slice(0, 10)}.csv`
  );
}

export function exportCrossRefToCsv(crossRef: CrossRefSummary) {
  const headers = [
    'TransactionCode',
    'ReconciliationStatus',
    'Severity',
    'DBEventID',
    'DBTimestampUTC',
    'DBAmount',
    'DBActor',
    'ExcelRowNumber',
    'ExcelDateUTC',
    'ExcelAmount',
    'ExcelApprover',
    'VarianceAmount',
    'Details',
  ];

  const rows = crossRef.discrepancies.map((d) =>
    [
      d.transactionCode,
      d.status,
      d.severity,
      d.dbEventId ?? '',
      d.dbTimestampUtc ?? '',
      d.dbAmount ?? '',
      d.dbActor ?? '',
      d.excelRowNumber ?? '',
      d.excelDateUtc ?? '',
      d.excelAmount ?? '',
      d.excelApprover ?? '',
      d.varianceAmount ?? '',
      d.details,
    ]
      .map(csvEscape)
      .join(',')
  );

  const csv = [headers.join(','), ...rows].join('\r\n');
  triggerDownload(
    new Blob([csv], { type: 'text/csv;charset=utf-8;' }),
    `veritas_excel_crossref_${new Date().toISOString().slice(0, 10)}.csv`
  );
}

export function exportComprehensiveCompliancePdf(params: {
  report?: ComprehensiveReport | null;
  auditorName: string;
  vaultStatus: VaultStatus | null;
  holisticFindings: HolisticFinding[];
  crossRef: CrossRefSummary | null;
  bakAnalyses: BakAnalysisResult[];
  evidenceItems: EvidenceItem[];
  auditLogs: AuditEvent[];
}) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 40;
  let y = 44;

  // Header Banner
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, 84, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('VERITAS LEDGER — FORENSIC COMPLIANCE & INTEGRITY REPORT', margin, 36);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(203, 213, 225);
  const reportId = params.report?.reportId || `RPT-${Date.now()}`;
  doc.text(
    `Report ID: ${reportId}   |   Generated UTC: ${new Date().toISOString()}   |   Custodian: ${params.auditorName}`,
    margin,
    56
  );
  doc.text(
    'Standards: Kenya Data Protection Act 2019 · ISO/IEC 27037 · ALCOA+ · SOX ITGC · ACFE',
    margin,
    70
  );

  y = 108;
  doc.setTextColor(15, 23, 42);

  const addSectionTitle = (title: string) => {
    if (y > 740) {
      doc.addPage();
      y = 48;
    }
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(15, 23, 42);
    doc.text(title, margin, y);
    y += 6;
    doc.setDrawColor(203, 213, 225);
    doc.line(margin, y, pageWidth - margin, y);
    y += 14;
  };

  const addParagraph = (text: string) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(51, 65, 85);
    const lines = doc.splitTextToSize(text, pageWidth - margin * 2);
    for (const line of lines) {
      if (y > 775) {
        doc.addPage();
        y = 48;
      }
      doc.text(line, margin, y);
      y += 13;
    }
    y += 6;
  };

  // 1. Executive Summary
  addSectionTitle('1. Executive Summary & Custody Verification');
  const execText =
    params.report?.executiveSummary ||
    `Holistic forensic audit completed across ${params.auditLogs.length} sealed audit trail events, ${params.evidenceItems.length} digital evidence artifacts, and ${params.bakAnalyses.length} database backup assessment(s). Cryptographic vault chain verification status: ${params.vaultStatus?.chainIntact ? 'INTACT (Zero tampering detected in Veritas Vault)' : 'COMPROMISED'}. Identified ${params.holisticFindings.length} holistic temporal/integrity finding(s) in target RDBMS logs.`;
  addParagraph(execText);

  if (params.report?.chainOfCustodyStatement) {
    addParagraph(`Chain of Custody Attestation: ${params.report.chainOfCustodyStatement}`);
  } else if (params.vaultStatus) {
    addParagraph(
      `Vault Encryption: ${params.vaultStatus.encryptionAlgorithm} (${params.vaultStatus.keyDerivation}). Tip SHA-256: ${params.vaultStatus.tipHash}`
    );
  }

  // 2. Holistic Timestamp & Database Integrity Findings
  addSectionTitle('2. Holistic Database & Timestamp Integrity Findings');
  if (params.holisticFindings.length > 0) {
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Finding ID', 'Severity', 'Category', 'Target', 'Evidence & Standard']],
      body: params.holisticFindings.map((f) => [
        f.findingId,
        f.severity,
        f.category,
        f.affectedTarget,
        `${f.title} — ${f.evidenceSummary} [${f.standardReference}]`,
      ]),
      styles: { fontSize: 8, cellPadding: 5, textColor: [30, 41, 59] },
      headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold' },
      columnStyles: { 0: { cellWidth: 74 }, 1: { cellWidth: 48 }, 2: { cellWidth: 72 }, 3: { cellWidth: 92 } },
    });
    y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 20;
  } else {
    addParagraph('No timestamp or sequence anomalies detected.');
  }

  // 3. Excel Cross-Reference Reconciliation
  if (params.crossRef) {
    addSectionTitle('3. Master Excel Sheet Cross-Reference Reconciliation');
    addParagraph(
      `Source: ${params.crossRef.sheetSourceName} (SHA-256: ${params.crossRef.sheetSha256.slice(0, 24)}...). Matched: ${params.crossRef.matchedCount} | Discrepancies: ${params.crossRef.discrepancyCount} | Aggregate Absolute Variance: $${params.crossRef.totalVarianceValue.toLocaleString()}`
    );
    if (params.report?.crossReferenceNarrative) {
      addParagraph(params.report.crossReferenceNarrative);
    }
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Txn Code', 'Status', 'DB Amt', 'Excel Amt', 'Variance', 'Finding Details']],
      body: params.crossRef.discrepancies.map((d) => [
        d.transactionCode,
        d.status,
        d.dbAmount !== undefined ? `$${d.dbAmount.toLocaleString()}` : '—',
        d.excelAmount !== undefined ? `$${d.excelAmount.toLocaleString()}` : '—',
        d.varianceAmount !== undefined ? `$${d.varianceAmount.toLocaleString()}` : '—',
        d.details,
      ]),
      styles: { fontSize: 7.5, cellPadding: 4 },
      headStyles: { fillColor: [30, 58, 138], textColor: 255 },
      columnStyles: { 0: { cellWidth: 74 }, 1: { cellWidth: 94 }, 2: { cellWidth: 52 }, 3: { cellWidth: 52 }, 4: { cellWidth: 52 } },
    });
    y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 20;
  }

  // 4. RDBMS .bak Architectural Assessment
  if (params.bakAnalyses.length > 0) {
    addSectionTitle('4. Enterprise RDBMS (.bak) Architectural Assessment');
    for (const bak of params.bakAnalyses) {
      addParagraph(
        `Artifact: ${bak.fileName} (${bak.detectedFormat}, ${bak.engineGuess}) | Database: ${bak.databaseName} | SHA-256: ${bak.sha256}`
      );
      if (bak.architecturalAssessment) {
        addParagraph(`Overall Posture: ${bak.architecturalAssessment.overallPosture}`);
        addParagraph(`Topology: ${bak.architecturalAssessment.rdbmsTopologySummary}`);
        addParagraph(`Temporal Integrity: ${bak.architecturalAssessment.temporalIntegrityAnalysis}`);
        addParagraph(`Access & Privilege Analysis: ${bak.architecturalAssessment.accessControlAndPrivilegeAnalysis}`);
      }
    }
  } else if (params.report?.architecturalNarrative) {
    addSectionTitle('4. RDBMS Architectural Assessment');
    addParagraph(params.report.architecturalNarrative);
  }

  // 5. Chain of Custody Evidence Locker
  addSectionTitle('5. Digital Evidence Chain of Custody (ISO/IEC 27037)');
  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [['Evidence ID', 'Artifact Name', 'Type', 'SHA-256 Fingerprint', 'Encryption']],
    body: params.evidenceItems.map((e) => [
      e.evidenceId,
      e.fileName,
      e.fileType,
      `${e.sha256.slice(0, 28)}...`,
      e.encryptedAtRest ? e.cipherSuite : 'Unencrypted',
    ]),
    styles: { fontSize: 7.5, cellPadding: 4 },
    headStyles: { fillColor: [15, 23, 42], textColor: 255 },
  });
  y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 20;

  // 6. Kenya Data Protection Act, 2019 (KDPA) Compliance
  addSectionTitle('6. Kenya Data Protection Act, 2019 (KDPA) Compliance');
  addParagraph(
    params.report?.kdpa2019Narrative ||
      'Processed under KDPA 2019 Sections 25 (Data Protection Principles), 31 (DPIA & PII Column Discovery), 41 (AES-256-GCM & SHA-256 Security Safeguards), 43 (72-Hour ODPC Breach Assessment), and 48 (Cross-Border Transfer Restriction & Localhost Isolation).'
  );

  // 7. Recommendations
  if (params.report?.recommendations?.length) {
    addSectionTitle('7. Remediation & Compliance Recommendations');
    params.report.recommendations.forEach((rec, i) => {
      addParagraph(`${i + 1}. ${rec}`);
    });
  }

  doc.save(`Veritas_Compliance_Report_${new Date().toISOString().slice(0, 10)}.pdf`);
}
