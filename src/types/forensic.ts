export type UserRole = 'Lead Forensic Auditor' | 'Compliance Officer' | 'External Investigator';

export interface UserAccount {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  badgeId: string;
  createdAtUtc: string;
  lastLoginUtc?: string;
}

export type AuditSeverity = 'Nominal' | 'Warning' | 'Critical';

export type AuditCategory =
  | 'Authentication'
  | 'DML / Schema Change'
  | 'Timestamp Anomaly'
  | 'Cross-Ref Discrepancy'
  | 'Evidence Custody'
  | 'System & Vault';

export interface AuditEvent {
  id: string;
  sequenceId: number;
  timestampUtc: string;
  recordedAtUtc: string;
  actor: string;
  actorRole: string;
  sourceIp: string;
  category: AuditCategory;
  action: string;
  targetObject: string;
  transactionCode?: string;
  amount?: number;
  currency?: string;
  severity: AuditSeverity;
  anomalyFlags: string[];
  beforeState?: Record<string, unknown> | null;
  afterState?: Record<string, unknown> | null;
  sqlStatement?: string;
  prevHash: string;
  recordHash: string;
}

export interface CustodyTransferEvent {
  timestampUtc: string;
  stage: 'Acquired' | 'Hashed' | 'Encrypted' | 'Analyzed' | 'Verified' | 'Exported';
  actor: string;
  notes: string;
  digestAtStage: string;
}

export interface EvidenceItem {
  evidenceId: string;
  fileName: string;
  fileType: 'RDBMS Backup (.bak)' | 'SQL Dump (.sql)' | 'Spreadsheet (.xlsx/.csv)' | 'Audit Package (.json)';
  byteSize: number;
  sha256: string;
  sha512: string;
  encryptedAtRest: boolean;
  cipherSuite: string;
  acquiredAtUtc: string;
  acquiredBy: string;
  integrityVerified: boolean;
  lastVerifiedUtc: string;
  custodyEvents: CustodyTransferEvent[];
}

export interface ExcelTransactionRow {
  rowNumber: number;
  transactionCode: string;
  authorizedDateUtc: string;
  vendorOrCounterparty: string;
  glAccount: string;
  authorizedAmount: number;
  currency: string;
  approver: string;
  status: string;
}

export type ReconciliationStatus =
  | 'MATCHED_VERIFIED'
  | 'AMOUNT_VARIANCE'
  | 'TIMESTAMP_DISCREPANCY'
  | 'MISSING_IN_EXCEL'
  | 'MISSING_IN_DB'
  | 'DUPLICATE_TXN_CODE';

export interface CrossRefDiscrepancy {
  transactionCode: string;
  status: ReconciliationStatus;
  severity: AuditSeverity;
  dbEventId?: string;
  dbTimestampUtc?: string;
  dbAmount?: number;
  dbActor?: string;
  excelRowNumber?: number;
  excelDateUtc?: string;
  excelAmount?: number;
  excelApprover?: string;
  varianceAmount?: number;
  details: string;
}

export interface CrossRefSummary {
  sheetSourceName: string;
  sheetSha256: string;
  reconciledAtUtc: string;
  totalDbTransactions: number;
  totalExcelRows: number;
  matchedCount: number;
  discrepancyCount: number;
  totalVarianceValue: number;
  discrepancies: CrossRefDiscrepancy[];
}

export interface DiscoveredTableSchema {
  schemaName: string;
  tableName: string;
  estimatedColumns: string[];
  hasAuditTimestamps: boolean;
  hasActorColumn: boolean;
  riskNotes: string[];
}

export interface HolisticFinding {
  findingId: string;
  title: string;
  category: 'Timestamp Tampering' | 'Sequence Gap' | 'Data Integrity' | 'Access Control' | 'Architectural Gap' | 'Fraud Indicator';
  severity: AuditSeverity;
  affectedTarget: string;
  evidenceSummary: string;
  standardReference: string;
  recommendation: string;
}

export interface ArchitecturalAssessment {
  executiveSummary: string;
  overallPosture: 'Sound' | 'Conditional — Remediation Required' | 'Non-Compliant — Critical Exposure';
  alcoaPlusAssessment: {
    principle: string;
    status: 'Compliant' | 'Partial' | 'Deficient';
    observation: string;
  }[];
  rdbmsTopologySummary: string;
  temporalIntegrityAnalysis: string;
  accessControlAndPrivilegeAnalysis: string;
  complianceMapping: {
    framework: string;
    status: string;
    gapSummary: string;
  }[];
  prioritizedFindings: HolisticFinding[];
  remediationRoadmap: {
    phase: string;
    action: string;
    owner: string;
  }[];
}

export interface BakAnalysisResult {
  evidenceId: string;
  fileName: string;
  fileSizeBytes: number;
  sha256: string;
  sha512: string;
  detectedFormat: string;
  engineGuess: string;
  magicSignatureHex: string;
  databaseName: string;
  serverOrInstance: string;
  logicalFiles: string[];
  extractedStringsCount: number;
  discoveredTables: DiscoveredTableSchema[];
  extractedPrincipals: string[];
  extractedTimestamps: string[];
  parsedRecordCount: number;
  holisticFindings: HolisticFinding[];
  architecturalAssessment?: ArchitecturalAssessment;
  analyzedAtUtc: string;
}

export interface VaultStatus {
  encryptionAlgorithm: string;
  keyDerivation: string;
  storagePath: string;
  totalSealedLogEntries: number;
  totalEvidenceArtifacts: number;
  chainIntact: boolean;
  genesisHash: string;
  tipHash: string;
  lastVerifiedUtc: string;
  brokenAtSequenceId?: number;
}

export interface ComprehensiveReport {
  reportId: string;
  generatedAtUtc: string;
  generatedBy: string;
  caseTitle: string;
  executiveSummary: string;
  chainOfCustodyStatement: string;
  alcoaPlusMatrix: {
    principle: string;
    status: 'Compliant' | 'Partial' | 'Deficient';
    notes: string;
  }[];
  keyFindings: HolisticFinding[];
  crossReferenceNarrative: string;
  architecturalNarrative: string;
  kdpa2019Narrative?: string;
  recommendations: string[];
}

export interface KdpaPrincipleStatus {
  section: string;
  principle: string;
  status: 'Compliant' | 'Partial' | 'Action Required';
  detail: string;
}

export interface SecurityComplianceConfig {
  bindHost: string;
  airgapLockdown: boolean;
  localDeterministicOnly: boolean;
  kdpaStrictMode: boolean;
  maskPiiBeforeAi: boolean;
  allowedEvidenceDir: string;
  outboundNetworkBlocked: boolean;
  kdpaPrinciples: KdpaPrincipleStatus[];
}

export interface BakPiiDetection {
  tableName: string;
  columnName: string;
  kdpaCategory: 'Personal Data (Sec. 2)' | 'Sensitive Personal Data (Sec. 2 / Sec. 44)' | 'Financial Identifier';
  protectionStatus: string;
}

