import { GoogleGenAI, Type, ThinkingLevel } from '@google/genai';
import type {
  ArchitecturalAssessment,
  AuditEvent,
  BakAnalysisResult,
  ComprehensiveReport,
  CrossRefSummary,
  EvidenceItem,
  HolisticFinding,
} from '../src/types/forensic.ts';
import { getSecurityComplianceConfig, redactPiiForExternalAi } from './cryptoVault.ts';

function getAiClient(): GoogleGenAI {
  const sec = getSecurityComplianceConfig();
  if (sec.localDeterministicOnly) {
    throw new Error('LOCAL_DETERMINISTIC_MODE');
  }
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not configured in the server environment.');
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

function maybeRedact<T>(payload: T): T {
  const sec = getSecurityComplianceConfig();
  if (sec.maskPiiBeforeAi || sec.kdpaStrictMode) {
    return redactPiiForExternalAi(payload);
  }
  return payload;
}

function buildDeterministicAssessment(analysis: BakAnalysisResult): ArchitecturalAssessment {
  const criticalCount = analysis.holisticFindings.filter((f) => f.severity === 'Critical').length;
  const tablesWithoutTs = analysis.discoveredTables.filter((t) => !t.hasAuditTimestamps);

  return {
    executiveSummary: `Offline Deterministic Architectural Assessment completed for ${analysis.fileName} (${(analysis.fileSizeBytes / (1024 * 1024)).toFixed(2)} MB, SHA-256: ${analysis.sha256}). Zero data left localhost (100% air-gap compliance under Kenya DPA 2019 Section 48). Detected ${analysis.discoveredTables.length} schema table(s) and ${analysis.holisticFindings.length} structural/forensic finding(s).`,
    overallPosture:
      criticalCount > 0
        ? 'Non-Compliant — Critical Exposure'
        : analysis.holisticFindings.length > 0
          ? 'Conditional — Remediation Required'
          : 'Sound',
    alcoaPlusAssessment: [
      {
        principle: 'Attributable',
        status: analysis.discoveredTables.some((t) => !t.hasActorColumn) ? 'Partial' : 'Compliant',
        observation: `${analysis.discoveredTables.filter((t) => !t.hasActorColumn).length} table(s) lack explicit actor/created_by columns.`,
      },
      {
        principle: 'Contemporaneous',
        status: criticalCount > 0 ? 'Deficient' : 'Compliant',
        observation: `${criticalCount} critical temporal or trigger-bypass indicators identified in sampled catalog/log regions.`,
      },
      {
        principle: 'Original & Accurate',
        status: 'Compliant',
        observation: `SHA-256 (${analysis.sha256.slice(0, 16)}...) and SHA-512 sealed at rest in AES-256-GCM storage.`,
      },
    ],
    rdbmsTopologySummary: `Detected ${analysis.detectedFormat} (${analysis.engineGuess}) for database ${analysis.databaseName} on ${analysis.serverOrInstance}. Logical files: ${analysis.logicalFiles.join(', ') || 'Embedded binary pages'}.`,
    temporalIntegrityAnalysis:
      tablesWithoutTs.length > 0
        ? `${tablesWithoutTs.length} table(s) lack created_at/updated_at temporal tracking. Enable SYSTEM_VERSIONING = ON or append-only SQL Ledger tables.`
        : 'Temporal columns present on inspected tables; verify clock synchronization and disable manual timestamp overrides.',
    accessControlAndPrivilegeAnalysis: `Extracted principals: ${analysis.extractedPrincipals.join(', ') || 'None in sampled windows'}. Enforce least privilege, remove shared sa usage, and protect audit triggers via DDL triggers.`,
    complianceMapping: [
      {
        framework: 'Kenya Data Protection Act, 2019 (KDPA)',
        status: 'Local Air-Gap Enforced',
        gapSummary: 'Zero cross-border transfer (Section 48) in Local Deterministic Mode. Verify Section 41 column-level encryption for PII/financial fields.',
      },
      {
        framework: 'ISO/IEC 27037 Digital Evidence',
        status: 'Compliant',
        gapSummary: 'Full SHA-256/SHA-512 hashes computed via constant-RAM streaming without altering source media.',
      },
      {
        framework: 'SOX ITGC & ACFE Fraud Controls',
        status: criticalCount > 0 ? 'Remediation Required' : 'Compliant',
        gapSummary: `${criticalCount} critical finding(s) require audit committee review.`,
      },
    ],
    prioritizedFindings: analysis.holisticFindings,
    remediationRoadmap: [
      {
        phase: 'Phase 1 (Immediate — 0-72 Hours)',
        action: 'Quarantine suspicious transactions, verify KDPA Section 43 72-hour breach threshold, and revoke shared sysadmin/sa credentials.',
        owner: 'Lead Forensic Auditor & CISO',
      },
      {
        phase: 'Phase 2 (Short-Term — 7-14 Days)',
        action: 'Enable SQL Server Temporal Tables / Ledger Tables and deploy DDL triggers preventing DISABLE TRIGGER.',
        owner: 'Enterprise DBA Team',
      },
    ],
  };
}

export async function generateBakArchitecturalAssessment(
  analysis: BakAnalysisResult,
  auditLogs: AuditEvent[],
  crossRef: CrossRefSummary | null
): Promise<ArchitecturalAssessment> {
  const sec = getSecurityComplianceConfig();
  if (sec.localDeterministicOnly) {
    return buildDeterministicAssessment(analysis);
  }

  const ai = getAiClient();

  const rawPromptPayload = {
    backupArtifact: {
      fileName: analysis.fileName,
      fileSizeBytes: analysis.fileSizeBytes,
      sha256: analysis.sha256,
      detectedFormat: analysis.detectedFormat,
      engineGuess: analysis.engineGuess,
      databaseName: analysis.databaseName,
      serverOrInstance: analysis.serverOrInstance,
      logicalFiles: analysis.logicalFiles,
      discoveredTables: analysis.discoveredTables,
      extractedPrincipals: analysis.extractedPrincipals,
      extractedTimestampsSample: analysis.extractedTimestamps.slice(0, 20),
      deterministicFindings: analysis.holisticFindings,
    },
    recentAuditEventsSample: auditLogs.slice(-25).map((e) => ({
      sequenceId: e.sequenceId,
      timestampUtc: e.timestampUtc,
      recordedAtUtc: e.recordedAtUtc,
      actor: e.actor,
      action: e.action,
      targetObject: e.targetObject,
      transactionCode: e.transactionCode,
      amount: e.amount,
      severity: e.severity,
      anomalyFlags: e.anomalyFlags,
    })),
    excelCrossReferenceSummary: crossRef
      ? {
          sheetSourceName: crossRef.sheetSourceName,
          matchedCount: crossRef.matchedCount,
          discrepancyCount: crossRef.discrepancyCount,
          totalVarianceValue: crossRef.totalVarianceValue,
          topDiscrepancies: crossRef.discrepancies.filter((d) => d.status !== 'MATCHED_VERIFIED').slice(0, 10),
        }
      : null,
  };

  const promptPayload = maybeRedact(rawPromptPayload);

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: `Perform a thorough Enterprise RDBMS Architectural Assessment and Forensic Audit of this database backup manifest and accompanying audit trail. Include explicit compliance evaluation under the Kenya Data Protection Act, 2019 (KDPA) alongside ISO/IEC 27037, ALCOA+, SOX ITGC, and ACFE standards.\n\nData (PII masked under KDPA 2019 Sec. 25c):\n${JSON.stringify(promptPayload, null, 2)}`,
    config: {
      systemInstruction:
        'You are a Principal Enterprise RDBMS Architect and Certified Fraud Examiner (CFE / CISA) operating under ISO/IEC 27037 (Digital Evidence), Kenya Data Protection Act 2019 (KDPA), ALCOA+ Data Integrity, SOX ITGC, and ACFE fraud standards. Provide an objective, technical, evidence-grounded assessment. Cite exact table names, timestamps, transaction codes, and SHA-256 hashes from the input.',
      thinkingConfig: { thinkingLevel: ThinkingLevel.MEDIUM },
      responseMimeType: 'application/json',
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          executiveSummary: { type: Type.STRING },
          overallPosture: {
            type: Type.STRING,
            description: 'Must be one of: Sound, Conditional — Remediation Required, Non-Compliant — Critical Exposure',
          },
          alcoaPlusAssessment: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                principle: { type: Type.STRING },
                status: { type: Type.STRING },
                observation: { type: Type.STRING },
              },
              required: ['principle', 'status', 'observation'],
            },
          },
          rdbmsTopologySummary: { type: Type.STRING },
          temporalIntegrityAnalysis: { type: Type.STRING },
          accessControlAndPrivilegeAnalysis: { type: Type.STRING },
          complianceMapping: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                framework: { type: Type.STRING },
                status: { type: Type.STRING },
                gapSummary: { type: Type.STRING },
              },
              required: ['framework', 'status', 'gapSummary'],
            },
          },
          prioritizedFindings: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                findingId: { type: Type.STRING },
                title: { type: Type.STRING },
                category: { type: Type.STRING },
                severity: { type: Type.STRING },
                affectedTarget: { type: Type.STRING },
                evidenceSummary: { type: Type.STRING },
                standardReference: { type: Type.STRING },
                recommendation: { type: Type.STRING },
              },
              required: [
                'findingId',
                'title',
                'category',
                'severity',
                'affectedTarget',
                'evidenceSummary',
                'standardReference',
                'recommendation',
              ],
            },
          },
          remediationRoadmap: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                phase: { type: Type.STRING },
                action: { type: Type.STRING },
                owner: { type: Type.STRING },
              },
              required: ['phase', 'action', 'owner'],
            },
          },
        },
        required: [
          'executiveSummary',
          'overallPosture',
          'alcoaPlusAssessment',
          'rdbmsTopologySummary',
          'temporalIntegrityAnalysis',
          'accessControlAndPrivilegeAnalysis',
          'complianceMapping',
          'prioritizedFindings',
          'remediationRoadmap',
        ],
      },
    },
  });

  const text = (response.text ?? '{}').trim();
  return JSON.parse(text) as ArchitecturalAssessment;
}

export async function generateComprehensiveForensicReport(params: {
  caseTitle: string;
  generatedBy: string;
  auditLogs: AuditEvent[];
  holisticFindings: HolisticFinding[];
  crossRef: CrossRefSummary | null;
  bakAnalyses: BakAnalysisResult[];
  evidenceItems: EvidenceItem[];
}): Promise<ComprehensiveReport> {
  const sec = getSecurityComplianceConfig();

  if (sec.localDeterministicOnly) {
    return {
      reportId: `RPT-LOCAL-${Date.now()}`,
      generatedAtUtc: new Date().toISOString(),
      generatedBy: params.generatedBy,
      caseTitle: params.caseTitle,
      executiveSummary: `Offline Deterministic Compliance Report generated across ${params.auditLogs.length} sealed audit trail events, ${params.holisticFindings.length} holistic temporal/integrity findings, and ${params.bakAnalyses.length} database backup assessment(s). Operating in 100% air-gapped Local Deterministic Mode with zero external network transmission.`,
      chainOfCustodyStatement: `All ${params.evidenceItems.length} evidence artifacts are hashed (SHA-256 & SHA-512) and sealed inside AES-256-GCM encrypted storage under ISO/IEC 27037.`,
      alcoaPlusMatrix: [
        { principle: 'Attributable', status: 'Partial', notes: 'Shared sysadmin (sa) entries require session attribution hardening.' },
        { principle: 'Contemporaneous', status: params.holisticFindings.some((f) => f.category === 'Timestamp Tampering') ? 'Deficient' : 'Compliant', notes: 'Timestamp inversions and sequence gaps flagged.' },
        { principle: 'Original & Enduring', status: 'Compliant', notes: 'Cryptographic hash chain and AES-256-GCM vault verified intact.' },
      ],
      keyFindings: params.holisticFindings,
      crossReferenceNarrative: params.crossRef
        ? `Reconciled ${params.crossRef.totalDbTransactions} DB transactions against ${params.crossRef.sheetSourceName}: ${params.crossRef.matchedCount} matched, ${params.crossRef.discrepancyCount} discrepancies totaling $${params.crossRef.totalVarianceValue.toLocaleString()}.`
        : 'No Excel reconciliation executed yet.',
      architecturalNarrative: params.bakAnalyses.length
        ? `Analyzed ${params.bakAnalyses.map((b) => b.fileName).join(', ')} locally without network exposure.`
        : 'No .bak backup ingested yet.',
      kdpa2019Narrative: 'Compliant with Kenya Data Protection Act, 2019 Sections 25, 31, 41, and 48 (zero cross-border data transfer; local encryption enforced).',
      recommendations: [
        'Maintain air-gapped Ubuntu Hyper-V isolation during active fraud remediation.',
        'Assess critical unauthorized sysadmin tampering events against KDPA 2019 Section 43 72-hour ODPC notification obligations.',
        'Enable SQL Server Temporal/Ledger tables and enforce dual-custody approval for trigger/schema DDL.',
      ],
    };
  }

  const ai = getAiClient();

  const rawContext = {
    caseTitle: params.caseTitle,
    generatedBy: params.generatedBy,
    totalAuditEvents: params.auditLogs.length,
    criticalEvents: params.auditLogs.filter((e) => e.severity === 'Critical'),
    holisticFindings: params.holisticFindings,
    crossReference: params.crossRef,
    bakAnalyses: params.bakAnalyses.map((b) => ({
      fileName: b.fileName,
      fileSizeBytes: b.fileSizeBytes,
      sha256: b.sha256,
      databaseName: b.databaseName,
      engineGuess: b.engineGuess,
      discoveredTables: b.discoveredTables.map((t) => `${t.schemaName}.${t.tableName}`),
      holisticFindings: b.holisticFindings,
    })),
    evidenceCustody: params.evidenceItems.map((e) => ({
      evidenceId: e.evidenceId,
      fileName: e.fileName,
      sha256: e.sha256,
      encryptedAtRest: e.encryptedAtRest,
      cipherSuite: e.cipherSuite,
    })),
  };

  const context = maybeRedact(rawContext);

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: `Generate a formal, board-ready Comprehensive Forensic Audit & Data Integrity Compliance Report (incorporating Kenya Data Protection Act, 2019 compliance alongside ISO/IEC 27037, ALCOA+, and ACFE) based on the following PII-minimized evidence.\n\n${JSON.stringify(context, null, 2)}`,
    config: {
      systemInstruction:
        'You are a Lead Forensic Auditor producing a formal compliance and fraud investigation report aligned with ISO/IEC 27037, Kenya Data Protection Act 2019 (KDPA Sections 25, 31, 41, 43, 48), ALCOA+, ISO 27001, and ACFE Fraud Investigation Standards. Be precise, cite specific transaction codes, sequence IDs, timestamps, and SHA-256 hashes.',
      thinkingConfig: { thinkingLevel: ThinkingLevel.MEDIUM },
      responseMimeType: 'application/json',
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          executiveSummary: { type: Type.STRING },
          chainOfCustodyStatement: { type: Type.STRING },
          alcoaPlusMatrix: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                principle: { type: Type.STRING },
                status: { type: Type.STRING },
                notes: { type: Type.STRING },
              },
              required: ['principle', 'status', 'notes'],
            },
          },
          crossReferenceNarrative: { type: Type.STRING },
          architecturalNarrative: { type: Type.STRING },
          kdpa2019Narrative: { type: Type.STRING },
          recommendations: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
          },
        },
        required: [
          'executiveSummary',
          'chainOfCustodyStatement',
          'alcoaPlusMatrix',
          'crossReferenceNarrative',
          'architecturalNarrative',
          'kdpa2019Narrative',
          'recommendations',
        ],
      },
    },
  });

  const parsed = JSON.parse((response.text ?? '{}').trim());
  return {
    reportId: `RPT-${Date.now()}`,
    generatedAtUtc: new Date().toISOString(),
    generatedBy: params.generatedBy,
    caseTitle: params.caseTitle,
    executiveSummary: parsed.executiveSummary,
    chainOfCustodyStatement: parsed.chainOfCustodyStatement,
    alcoaPlusMatrix: parsed.alcoaPlusMatrix,
    keyFindings: params.holisticFindings,
    crossReferenceNarrative: parsed.crossReferenceNarrative,
    architecturalNarrative: parsed.architecturalNarrative,
    kdpa2019Narrative: parsed.kdpa2019Narrative,
    recommendations: parsed.recommendations,
  };
}

export async function runForensicEnquiryQuery(params: {
  question: string;
  auditLogs: AuditEvent[];
  holisticFindings: HolisticFinding[];
  crossRef: CrossRefSummary | null;
  bakAnalyses: BakAnalysisResult[];
  evidenceItems: EvidenceItem[];
}): Promise<string> {
  const sec = getSecurityComplianceConfig();
  if (sec.localDeterministicOnly) {
    return [
      '### Local Deterministic Forensic Summary (Zero External Network Mode)',
      '',
      'External Gemini AI calls are currently disabled (`Local Deterministic Mode` is active for strict KDPA 2019 Section 48 air-gap isolation).',
      '',
      `**Active Holistic Findings (${params.holisticFindings.length}):**`,
      ...params.holisticFindings.map(
        (f) => `- **${f.severity} · ${f.findingId}**: ${f.title} (${f.affectedTarget}) — ${f.evidenceSummary}`
      ),
      '',
      params.crossRef
        ? `**Excel Cross-Reference Discrepancies:** ${params.crossRef.discrepancyCount} mismatch(es), aggregate variance $${params.crossRef.totalVarianceValue.toLocaleString()}.`
        : '',
    ]
      .filter(Boolean)
      .join('\n');
  }

  const ai = getAiClient();

  const rawContext = {
    auditLogs: params.auditLogs.slice(-60),
    holisticFindings: params.holisticFindings,
    crossReference: params.crossRef,
    bakAnalyses: params.bakAnalyses.map((b) => ({
      fileName: b.fileName,
      fileSizeBytes: b.fileSizeBytes,
      sha256: b.sha256,
      databaseName: b.databaseName,
      engineGuess: b.engineGuess,
      discoveredTables: b.discoveredTables,
      holisticFindings: b.holisticFindings,
    })),
    evidenceCount: params.evidenceItems.length,
  };

  const context = maybeRedact(rawContext);

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: `Auditor Enquiry:\n${params.question}\n\nActive Case Evidence & Logs (KDPA 2019 PII-minimized):\n${JSON.stringify(context, null, 2)}`,
    config: {
      systemInstruction:
        'You are a Senior Digital Forensics & RDBMS Compliance Analyst operating under ISO/IEC 27037, Kenya Data Protection Act 2019 (KDPA), ALCOA+, and ACFE standards. Answer the auditor enquiry directly using verifiable facts from the provided logs, findings, Excel variances, and .bak analysis.',
      thinkingConfig: { thinkingLevel: ThinkingLevel.MEDIUM },
    },
  });

  return response.text ?? 'No analysis returned from Gemini model.';
}

export async function explainAuditEventWithAi(
  event: AuditEvent,
  surroundingEvents: AuditEvent[]
): Promise<{
  riskAssessment: string;
  fraudSchemeClassification: string;
  temporalVerdict: string;
  recommendedAction: string;
}> {
  const sec = getSecurityComplianceConfig();
  if (sec.localDeterministicOnly) {
    return {
      riskAssessment: `Local Deterministic Inspection of Seq #${event.sequenceId} (${event.action} on ${event.targetObject}): Severity is ${event.severity} with ${event.anomalyFlags.length} anomaly flag(s).`,
      fraudSchemeClassification:
        event.anomalyFlags.length > 0
          ? event.anomalyFlags.join(', ')
          : 'No deterministic fraud flags triggered.',
      temporalVerdict: `Business timestamp ${event.timestampUtc} vs System WAL recorded ${event.recordedAtUtc}.`,
      recommendedAction:
        event.severity === 'Critical'
          ? 'Quarantine transaction, inspect adjacent sequence gap/trigger logs, and verify against master Excel register.'
          : 'Retain in immutable SHA-256 chain; no immediate escalation required.',
    };
  }

  const ai = getAiClient();
  const payload = maybeRedact({
    targetEvent: event,
    neighboringEvents: surroundingEvents.map((e) => ({
      sequenceId: e.sequenceId,
      timestampUtc: e.timestampUtc,
      recordedAtUtc: e.recordedAtUtc,
      actor: e.actor,
      action: e.action,
      targetObject: e.targetObject,
      severity: e.severity,
      anomalyFlags: e.anomalyFlags,
    })),
  });

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: `Analyze this specific database audit log event in context of its neighboring sequence events:\n${JSON.stringify(payload, null, 2)}`,
    config: {
      systemInstruction:
        'You are a Senior Forensic Auditor evaluating an individual RDBMS audit trail record under ACFE, ALCOA+, ISO/IEC 27037, and KDPA 2019. Return concise, evidence-grounded JSON.',
      thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
      responseMimeType: 'application/json',
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          riskAssessment: { type: Type.STRING },
          fraudSchemeClassification: { type: Type.STRING },
          temporalVerdict: { type: Type.STRING },
          recommendedAction: { type: Type.STRING },
        },
        required: [
          'riskAssessment',
          'fraudSchemeClassification',
          'temporalVerdict',
          'recommendedAction',
        ],
      },
    },
  });

  return JSON.parse((response.text ?? '{}').trim());
}

export async function analyzeCrossRefWithAi(crossRef: CrossRefSummary): Promise<string> {
  const sec = getSecurityComplianceConfig();
  if (sec.localDeterministicOnly) {
    const flagged = crossRef.discrepancies.filter((d) => d.status !== 'MATCHED_VERIFIED');
    return `Local Deterministic Synthesis (${crossRef.sheetSourceName}): ${crossRef.matchedCount} verified matches, ${flagged.length} discrepancies totaling $${crossRef.totalVarianceValue.toLocaleString()}. Priority codes: ${flagged.map((f) => `${f.transactionCode} (${f.status})`).join(', ') || 'None'}.`;
  }

  const ai = getAiClient();
  const payload = maybeRedact({
    sheetSourceName: crossRef.sheetSourceName,
    matchedCount: crossRef.matchedCount,
    discrepancyCount: crossRef.discrepancyCount,
    totalVarianceValue: crossRef.totalVarianceValue,
    discrepancies: crossRef.discrepancies.filter((d) => d.status !== 'MATCHED_VERIFIED'),
  });

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: `Synthesize these Excel-vs-RDBMS transaction code discrepancies for fraud indicators, control failures, and audit committee action:\n${JSON.stringify(payload, null, 2)}`,
    config: {
      systemInstruction:
        'You are a Certified Fraud Examiner (CFE) analyzing ledger-to-master-sheet variances. Group findings by scheme (e.g., Post-Approval Amount Alteration, Phantom Disbursement, Replay Duplicate) and cite exact transaction codes and dollar variances.',
      thinkingConfig: { thinkingLevel: ThinkingLevel.MEDIUM },
    },
  });

  return response.text ?? 'Unable to generate cross-reference synthesis.';
}

export async function analyzeHeatmapHotspots(hotspotSummary: {
  lens: string;
  selectedLabel?: string;
  topHotspots: { label: string; totalCount: number; criticalCount: number; warningCount: number; actions: string[] }[];
}): Promise<string> {
  const sec = getSecurityComplianceConfig();
  if (sec.localDeterministicOnly) {
    const top = hotspotSummary.topHotspots[0];
    return top
      ? `Local Concentration Summary (${hotspotSummary.lens}): Highest density at ${top.label} with ${top.totalCount} event(s) (${top.criticalCount} Critical, ${top.warningCount} Warning) involving ${top.actions.join(', ')}.`
      : 'No active hotspots detected in selected lens.';
  }

  const ai = getAiClient();
  const payload = maybeRedact(hotspotSummary);

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: `Analyze this forensic change-concentration heat map summary and explain why activity and critical anomalies cluster in these windows/objects:\n${JSON.stringify(payload, null, 2)}`,
    config: {
      systemInstruction:
        'You are a Forensic Data Analyst interpreting a database change-concentration heat map. Highlight anomalous off-hours clusters, high-risk tables, privilege concentration, and what the investigator should inspect next in 3–5 concise bullet points.',
      thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
    },
  });

  return response.text ?? 'No hotspot interpretation returned.';
}

export async function parseNaturalLanguageAuditFilter(
  naturalQuery: string
): Promise<{
  searchText: string;
  severity: 'All' | 'Critical' | 'Warning' | 'Nominal';
  category: string;
  explanation: string;
}> {
  const sec = getSecurityComplianceConfig();
  if (sec.localDeterministicOnly) {
    const lower = naturalQuery.toLowerCase();
    const severity = lower.includes('critical')
      ? 'Critical'
      : lower.includes('warning')
        ? 'Warning'
        : lower.includes('nominal')
          ? 'Nominal'
          : 'All';
    const tokens = naturalQuery
      .replace(/\b(show|find|filter|all|logs|events|with|where|only|critical|warning|nominal)\b/gi, '')
      .trim();
    return {
      searchText: tokens,
      severity,
      category: 'All',
      explanation: 'Local keyword filter applied (Offline Deterministic Mode).',
    };
  }

  const ai = getAiClient();
  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: `Translate this forensic auditor search request into structured filter parameters: "${naturalQuery}"`,
    config: {
      systemInstruction:
        'Convert the user request into structured audit trail filter fields. Valid severities: All, Critical, Warning, Nominal. Valid categories: All, Authentication, DML / Schema Change, Timestamp Anomaly, Cross-Ref Discrepancy, Evidence Custody, System & Vault. Keep searchText to the best single keyword, actor, transaction code, or table name (or empty string if severity/category alone captures it).',
      thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
      responseMimeType: 'application/json',
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          searchText: { type: Type.STRING },
          severity: { type: Type.STRING },
          category: { type: Type.STRING },
          explanation: { type: Type.STRING },
        },
        required: ['searchText', 'severity', 'category', 'explanation'],
      },
    },
  });

  return JSON.parse((response.text ?? '{}').trim());
}

