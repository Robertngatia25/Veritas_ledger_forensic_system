import fs from 'node:fs';
import type {
  AuditEvent,
  BakAnalysisResult,
  BakPiiDetection,
  DiscoveredTableSchema,
  HolisticFinding,
} from '../src/types/forensic.ts';
import { hashFileStream, sha256Hex, sha512Hex } from './cryptoVault.ts';

function extractAsciiStrings(buf: Buffer, minLen = 5, maxStrings = 2400): string[] {
  const results: string[] = [];
  let current = '';
  const limit = Math.min(buf.length, 32 * 1024 * 1024);
  for (let i = 0; i < limit; i++) {
    const b = buf[i];
    if (b >= 32 && b <= 126) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= minLen) {
        results.push(current.trim());
        if (results.length >= maxStrings) break;
      }
      current = '';
    }
  }
  if (current.length >= minLen && results.length < maxStrings) {
    results.push(current.trim());
  }
  return results;
}

function extractUtf16LeStrings(buf: Buffer, minLen = 5, maxStrings = 2400): string[] {
  const results: string[] = [];
  let current = '';
  const limit = Math.min(buf.length - 1, 32 * 1024 * 1024);
  for (let i = 0; i < limit; i += 2) {
    const lo = buf[i];
    const hi = buf[i + 1];
    if (hi === 0 && lo >= 32 && lo <= 126) {
      current += String.fromCharCode(lo);
    } else {
      if (current.length >= minLen) {
        results.push(current.trim());
        if (results.length >= maxStrings) break;
      }
      current = '';
    }
  }
  if (current.length >= minLen && results.length < maxStrings) {
    results.push(current.trim());
  }
  return results;
}

function detectFormat(headerBuf: Buffer, fileName: string): { format: string; engine: string; magicHex: string } {
  const header = headerBuf.subarray(0, 16);
  const magicHex = header.toString('hex').toUpperCase();
  const asciiHead = header.toString('ascii');

  if (asciiHead.startsWith('TAPE')) {
    return {
      format: 'Microsoft Tape Format (MTF / SQL Server .bak)',
      engine: 'Microsoft SQL Server (MSSQL)',
      magicHex,
    };
  }
  if (asciiHead.startsWith('PGDMP')) {
    return {
      format: 'PostgreSQL Custom Dump Archive (PGDMP)',
      engine: 'PostgreSQL',
      magicHex,
    };
  }
  if (asciiHead.startsWith('SQLite format 3')) {
    return {
      format: 'SQLite 3 Binary Database',
      engine: 'SQLite 3',
      magicHex,
    };
  }
  if (header[0] === 0x50 && header[1] === 0x4b && header[2] === 0x03 && header[3] === 0x04) {
    return {
      format: 'ZIP / BACPAC / Compressed Archive',
      engine: 'SQL Server BACPAC / Archive',
      magicHex,
    };
  }

  const headText = headerBuf.subarray(0, Math.min(headerBuf.length, 4096)).toString('utf8');
  if (/CREATE\s+TABLE|INSERT\s+INTO|BEGIN\s+TRANSACTION|SET\s+ANSI_NULLS/i.test(headText)) {
    return {
      format: fileName.endsWith('.bak') ? 'SQL Text Backup (.bak / T-SQL)' : 'Plaintext SQL Dump (.sql)',
      engine: /GO\b|dbo\.|NVARCHAR|IDENTITY/i.test(headText) ? 'Microsoft SQL Server (T-SQL)' : 'ANSI / PostgreSQL / MySQL',
      magicHex,
    };
  }

  if (fileName.toLowerCase().endsWith('.csv')) {
    return {
      format: 'Delimited Audit Export (.csv)',
      engine: 'RDBMS Export / CSV',
      magicHex,
    };
  }

  if (fileName.toLowerCase().endsWith('.json')) {
    return {
      format: 'Structured Audit Dump (.json)',
      engine: 'RDBMS JSON Export',
      magicHex,
    };
  }

  return {
    format: fileName.toLowerCase().endsWith('.bak')
      ? 'Binary RDBMS Backup Container (.bak)'
      : 'Unclassified Binary / Data Artifact',
    engine: 'Enterprise RDBMS',
    magicHex,
  };
}

function inspectExtractedWindows(
  sampleBuffers: Buffer[],
  fileName: string,
  totalByteSize: number,
  sha256: string,
  sha512: string,
  evidenceId: string
): {
  analysis: BakAnalysisResult & { kdpaPiiDetections?: BakPiiDetection[] };
  extractedAuditEvents: Omit<AuditEvent, 'prevHash' | 'recordHash'>[];
} {
  const headBuf = sampleBuffers[0] || Buffer.alloc(0);
  const { format, engine, magicHex } = detectFormat(headBuf, fileName);

  const stringSet = new Set<string>();
  for (const buf of sampleBuffers) {
    for (const s of extractAsciiStrings(buf, 5, 1600)) stringSet.add(s);
    for (const s of extractUtf16LeStrings(buf, 5, 1600)) stringSet.add(s);
  }
  const combinedStrings = Array.from(stringSet);
  const fullInspectableText = combinedStrings.join('\n');

  let databaseName = 'Unknown / Embedded Catalog';
  let serverOrInstance = 'Unknown Host';

  const dbMatch =
    fullInspectableText.match(/DATABASE\s+\[?([A-Za-z0-9_.-]+)\]?/i) ||
    fullInspectableText.match(/DatabaseName[:=]\s*([A-Za-z0-9_.-]+)/i) ||
    fullInspectableText.match(/DB_NAME[:=]\s*([A-Za-z0-9_.-]+)/i);
  if (dbMatch?.[1]) databaseName = dbMatch[1];

  const srvMatch =
    fullInspectableText.match(/ServerName[:=]\s*([A-Za-z0-9_\\.-]+)/i) ||
    fullInspectableText.match(/Instance[:=]\s*([A-Za-z0-9_\\.-]+)/i) ||
    fullInspectableText.match(/HOST[:=]\s*([A-Za-z0-9_.-]+)/i);
  if (srvMatch?.[1]) serverOrInstance = srvMatch[1];

  const logicalFiles = Array.from(
    new Set(
      combinedStrings
        .filter((s) => /\.(mdf|ldf|ndf)\b/i.test(s))
        .map((s) => s.slice(0, 120))
    )
  ).slice(0, 16);

  const discoveredTables: DiscoveredTableSchema[] = [];
  const kdpaPiiDetections: BakPiiDetection[] = [];
  const seenTables = new Set<string>();

  const createTableRegex = /CREATE\s+TABLE\s+(?:\[?([A-Za-z0-9_]+)\]?\.)?\[?([A-Za-z0-9_]+)\]?\s*\(([\s\S]{10,1400}?)\)/gi;
  let match: RegExpExecArray | null;
  while ((match = createTableRegex.exec(fullInspectableText)) !== null) {
    const schemaName = match[1] || 'dbo';
    const tableName = match[2];
    const body = match[3];
    const key = `${schemaName}.${tableName}`;
    if (seenTables.has(key)) continue;
    seenTables.add(key);

    const cols = body
      .split(',')
      .map((line) => line.trim().split(/\s+/)[0]?.replace(/[\[\]`"]/g, ''))
      .filter((c) => c && !/^(PRIMARY|FOREIGN|CONSTRAINT|UNIQUE|INDEX|CHECK)$/i.test(c))
      .slice(0, 24);

    const hasAuditTimestamps = cols.some((c) => /created_at|updated_at|timestamp|event_time|modified_at/i.test(c));
    const hasActorColumn = cols.some((c) => /created_by|updated_by|actor|user_id|modified_by/i.test(c));
    const riskNotes: string[] = [];
    if (!hasAuditTimestamps) riskNotes.push('Missing immutable temporal audit columns (created_at/updated_at).');
    if (!hasActorColumn) riskNotes.push('Missing user attribution column (actor/modified_by) violating ALCOA+ Attributable rule.');

    for (const col of cols) {
      if (/national_id|id_number|kra_pin|passport|biometric|health|hiv|ethnic/i.test(col)) {
        kdpaPiiDetections.push({
          tableName: key,
          columnName: col,
          kdpaCategory: 'Sensitive Personal Data (Sec. 2 / Sec. 44)',
          protectionStatus: 'Verify column-level encryption & KDPA Sec. 41 safeguards',
        });
      } else if (/iban|bank_acc|account_no|tax_id|salary|mpesa/i.test(col)) {
        kdpaPiiDetections.push({
          tableName: key,
          columnName: col,
          kdpaCategory: 'Financial Identifier',
          protectionStatus: 'Requires RBAC masking & encrypted at-rest storage',
        });
      } else if (/email|phone|msisdn|address|full_name|dob|birth/i.test(col)) {
        kdpaPiiDetections.push({
          tableName: key,
          columnName: col,
          kdpaCategory: 'Personal Data (Sec. 2)',
          protectionStatus: 'Subject to KDPA Sec. 25 Data Minimization & Purpose Limitation',
        });
      }
    }

    if (cols.some((c) => /password|ssn|card|secret|token|iban|tax_id|national_id|kra_pin/i.test(c))) {
      riskNotes.push('Contains regulated personal/financial identifier under Kenya Data Protection Act, 2019 (Sec. 41) — verify TDE / Always Encrypted.');
    }

    discoveredTables.push({
      schemaName,
      tableName,
      estimatedColumns: cols,
      hasAuditTimestamps,
      hasActorColumn,
      riskNotes,
    });
  }

  const refRegex = /\b(dbo|audit|fin|sec|core|public)\.([a-zA-Z0-9_]{3,40})\b/g;
  let refMatch: RegExpExecArray | null;
  while ((refMatch = refRegex.exec(fullInspectableText)) !== null && discoveredTables.length < 24) {
    const schemaName = refMatch[1];
    const tableName = refMatch[2];
    const key = `${schemaName}.${tableName}`;
    if (!seenTables.has(key)) {
      seenTables.add(key);
      discoveredTables.push({
        schemaName,
        tableName,
        estimatedColumns: ['Inferred from binary catalog / SQL references'],
        hasAuditTimestamps: /audit|log|history|ledger/i.test(tableName),
        hasActorColumn: /audit|log|user/i.test(tableName),
        riskNotes: ['Schema inferred from sampled binary windows; inspect full catalog DDL if TDE/compressed.'],
      });
    }
  }

  const tsMatches = fullInspectableText.match(/\b20\d{2}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b/g) || [];
  const extractedTimestamps = Array.from(new Set(tsMatches)).slice(0, 60);

  const principalMatches =
    fullInspectableText.match(/\b(?:sa|dbo|NT AUTHORITY\\SYSTEM|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g) || [];
  const extractedPrincipals = Array.from(new Set(principalMatches)).slice(0, 25);

  const extractedAuditEvents: Omit<AuditEvent, 'prevHash' | 'recordHash'>[] = [];
  const txnMatches = fullInspectableText.match(/TXN-[0-9]{4}-[0-9]{3,6}/g) || [];
  const uniqueTxns = Array.from(new Set(txnMatches));

  const holisticFindings: HolisticFinding[] = [];

  if (uniqueTxns.length === 0 && discoveredTables.length === 0) {
    holisticFindings.push({
      findingId: `FND-BAK-BIN-${Date.now()}`,
      title: 'Compressed or Encrypted Binary Backup Pages Detected',
      category: 'Architectural Gap',
      severity: 'Warning',
      affectedTarget: fileName,
      evidenceSummary: `Container detected as ${format} (${(totalByteSize / (1024 * 1024)).toFixed(1)} MB). Sampled windows extracted ${combinedStrings.length} metadata strings; table pages may use SQL Server backup compression or TDE.`,
      standardReference: 'ISO/IEC 27037 Digital Evidence Acquisition',
      recommendation: 'Verify backup encryption certificate custody and restore into an isolated Hyper-V forensic SQL instance for full page-level row queries.',
    });
  }

  const parsedTs = extractedTimestamps
    .map((ts) => ({ raw: ts, ms: Date.parse(ts) }))
    .filter((x) => !Number.isNaN(x.ms));
  const futureEntries = parsedTs.filter((x) => x.ms > Date.now() + 86400000);
  if (futureEntries.length > 0) {
    holisticFindings.push({
      findingId: `FND-BAK-FUT-${Date.now()}`,
      title: `Future-Dated Timestamps Found in Backup (${futureEntries.length})`,
      category: 'Timestamp Tampering',
      severity: 'Critical',
      affectedTarget: fileName,
      evidenceSummary: `Extracted timestamps include future-dated values such as ${futureEntries[0].raw}, violating chronological plausibility.`,
      standardReference: 'ALCOA+ Contemporaneous Integrity Standard',
      recommendation: 'Investigate clock skew or manual timestamp manipulation prior to backup generation.',
    });
  }

  if (/DISABLE\s+TRIGGER/i.test(fullInspectableText)) {
    holisticFindings.push({
      findingId: `FND-BAK-TRG-${Date.now()}`,
      title: 'Trigger Bypass Directive Found Inside Backup Artifact',
      category: 'Access Control',
      severity: 'Critical',
      affectedTarget: fileName,
      evidenceSummary: 'Sampled SQL/log fragments contain DISABLE TRIGGER statements, indicating potential suppression of automated audit trail capture.',
      standardReference: 'SOX ITGC & ACFE Fraud Prevention Controls',
      recommendation: 'Audit all DML executed between DISABLE TRIGGER and ENABLE TRIGGER timestamps.',
    });
  }

  if (/SET\s+IDENTITY_INSERT\s+[^\n]+ON/i.test(fullInspectableText)) {
    holisticFindings.push({
      findingId: `FND-BAK-ID-${Date.now()}`,
      title: 'IDENTITY_INSERT Override Detected in Backup Stream',
      category: 'Sequence Gap',
      severity: 'Critical',
      affectedTarget: fileName,
      evidenceSummary: 'Backup contains explicit IDENTITY_INSERT ON commands enabling manual insertion of out-of-order or backdated primary key IDs.',
      standardReference: 'ISO/IEC 27037 Sequence Continuity',
      recommendation: 'Restrict ALTER/IDENTITY_INSERT permissions to emergency break-glass change tickets only.',
    });
  }

  if (kdpaPiiDetections.length > 0) {
    holisticFindings.push({
      findingId: `FND-KDPA-PII-${Date.now()}`,
      title: `Kenya DPA 2019: ${kdpaPiiDetections.length} Personal / Financial Identifier Column(s) Detected`,
      category: 'Data Integrity',
      severity: 'Warning',
      affectedTarget: Array.from(new Set(kdpaPiiDetections.map((d) => d.tableName))).join(', '),
      evidenceSummary: `Detected regulated columns (${kdpaPiiDetections.map((d) => d.columnName).slice(0, 6).join(', ')}) requiring Section 41 technical safeguards and Section 48 cross-border transfer restrictions.`,
      standardReference: 'Kenya Data Protection Act, 2019 (Sections 25, 31, 41 & 48)',
      recommendation: 'Keep raw database isolated inside local Ubuntu Hyper-V vault; ensure PII masking is active before any external reporting.',
    });
  }

  const tablesWithoutTimestamps = discoveredTables.filter((t) => !t.hasAuditTimestamps);
  if (tablesWithoutTimestamps.length > 0) {
    holisticFindings.push({
      findingId: `FND-BAK-ARCH-${Date.now()}`,
      title: `${tablesWithoutTimestamps.length} Discovered Table(s) Lack Temporal Audit Columns`,
      category: 'Architectural Gap',
      severity: 'Warning',
      affectedTarget: tablesWithoutTimestamps.map((t) => `${t.schemaName}.${t.tableName}`).join(', '),
      evidenceSummary: 'Tables lack created_at / updated_at or SQL Server Temporal History columns, preventing deterministic timeline reconstruction.',
      standardReference: 'Enterprise RDBMS System-Versioned Temporal Tables Standard',
      recommendation: 'Enable SYSTEM_VERSIONING = ON (SQL Server Temporal Tables) or immutable append-only SQL Ledger tables.',
    });
  }

  const analysis: BakAnalysisResult & { kdpaPiiDetections?: BakPiiDetection[] } = {
    evidenceId,
    fileName,
    fileSizeBytes: totalByteSize,
    sha256,
    sha512,
    detectedFormat: format,
    engineGuess: engine,
    magicSignatureHex: magicHex,
    databaseName,
    serverOrInstance,
    logicalFiles,
    extractedStringsCount: combinedStrings.length,
    discoveredTables,
    extractedPrincipals,
    extractedTimestamps,
    parsedRecordCount: uniqueTxns.length,
    holisticFindings,
    kdpaPiiDetections,
    analyzedAtUtc: new Date().toISOString(),
  };

  return { analysis, extractedAuditEvents };
}

export function analyzeBackupBuffer(
  buffer: Buffer,
  fileName: string,
  evidenceId: string
): { analysis: BakAnalysisResult; extractedAuditEvents: Omit<AuditEvent, 'prevHash' | 'recordHash'>[] } {
  const sha256 = sha256Hex(buffer);
  const sha512 = sha512Hex(buffer);
  return inspectExtractedWindows([buffer], fileName, buffer.length, sha256, sha512, evidenceId);
}

/**
 * Multi-GB Streaming .bak Analyzer (supports 15 GB+ databases in constant ~48MB RAM).
 * Computes full-file SHA-256 & SHA-512 in 16MB chunks, then reads header, spaced
 * catalog/page windows across the file, and tail blocks without buffering 15GB in RAM.
 */
export async function analyzeBackupFileStream(
  filePath: string,
  fileName: string,
  evidenceId: string,
  precomputedHashes?: { byteSize: number; sha256: string; sha512: string }
): Promise<{ analysis: BakAnalysisResult; extractedAuditEvents: Omit<AuditEvent, 'prevHash' | 'recordHash'>[] }> {
  const hashes = precomputedHashes || (await hashFileStream(filePath));
  const totalSize = hashes.byteSize;
  const fh = await fs.promises.open(filePath, 'r');

  const windows: Buffer[] = [];
  try {
    // 1. Head window (up to 16 MB for MTF TAPE header + primary catalog pages)
    const headLen = Math.min(totalSize, 16 * 1024 * 1024);
    if (headLen > 0) {
      const headBuf = Buffer.allocUnsafe(headLen);
      const { bytesRead } = await fh.read(headBuf, 0, headLen, 0);
      windows.push(headBuf.subarray(0, bytesRead));
    }

    // 2. Evenly spaced 4 MB windows across multi-GB files (up to 6 windows)
    if (totalSize > 32 * 1024 * 1024) {
      const sampleCount = 6;
      const windowSize = 4 * 1024 * 1024;
      for (let i = 1; i <= sampleCount; i++) {
        const offset = Math.floor((totalSize / (sampleCount + 1)) * i);
        const readLen = Math.min(windowSize, totalSize - offset);
        if (readLen > 0) {
          const buf = Buffer.allocUnsafe(readLen);
          const { bytesRead } = await fh.read(buf, 0, readLen, offset);
          windows.push(buf.subarray(0, bytesRead));
        }
      }
    }

    // 3. Tail window (last 8 MB for backup set trailer / MTF EOT / catalog summary)
    if (totalSize > 24 * 1024 * 1024) {
      const tailLen = Math.min(8 * 1024 * 1024, totalSize - headLen);
      const tailOffset = totalSize - tailLen;
      const tailBuf = Buffer.allocUnsafe(tailLen);
      const { bytesRead } = await fh.read(tailBuf, 0, tailLen, tailOffset);
      windows.push(tailBuf.subarray(0, bytesRead));
    }
  } finally {
    await fh.close();
  }

  return inspectExtractedWindows(windows, fileName, totalSize, hashes.sha256, hashes.sha512, evidenceId);
}

export function buildSampleEnterpriseBakBuffer(): Buffer {
  const header = Buffer.alloc(512, 0);
  header.write('TAPE', 0, 'ascii');
  header.write('SQLBACKUP_MTF_16.0', 32, 'ascii');

  const catalogSql = `
DatabaseName=EnterpriseERP_Financials_Prod
ServerName=SQL-PROD-CLUSTER01\\FINANCE
BackupType=FULL_DATABASE_BACKUP
LogicalFile=EnterpriseERP_Data.mdf
LogicalFile=EnterpriseERP_Log.ldf

CREATE TABLE dbo.ap_ledger_entries (
  entry_id BIGINT IDENTITY(1,1) PRIMARY KEY,
  txn_code VARCHAR(32) NOT NULL,
  vendor_id INT NOT NULL,
  amount DECIMAL(18,2) NOT NULL,
  gl_code VARCHAR(32) NOT NULL,
  created_at DATETIME2 NOT NULL,
  updated_at DATETIME2 NULL,
  created_by NVARCHAR(128) NOT NULL
);

CREATE TABLE dbo.vendor_master (
  vendor_id INT PRIMARY KEY,
  vendor_name NVARCHAR(200) NOT NULL,
  iban_account VARCHAR(64) NOT NULL,
  kra_pin VARCHAR(32) NOT NULL,
  national_id VARCHAR(32) NOT NULL
);

CREATE TABLE dbo.wire_settlements (
  settlement_id BIGINT IDENTITY(1,1) PRIMARY KEY,
  txn_code VARCHAR(32) NOT NULL,
  batch_ref VARCHAR(64) NOT NULL,
  status VARCHAR(24) NOT NULL,
  settled_at DATETIME2 NULL
);

CREATE TABLE dbo.sys_session_audit (
  session_id UNIQUEIDENTIFIER PRIMARY KEY,
  login_name NVARCHAR(128) NOT NULL,
  client_ip VARCHAR(45) NOT NULL,
  login_time DATETIME2 NOT NULL
);

-- Embedded transaction log fragments recovered from backup pages:
-- 2026-11-12T09:14:22.000Z | m.henderson@corp-erp.internal | TXN-2026-8835 | 12450.00
-- 2026-11-14T10:05:11.000Z | r.okonkwo@corp-erp.internal | TXN-2026-8838 | 48500.00
-- 2026-10-29T08:15:00.000Z | sa | TXN-2026-8840 | 31800.00 | SET IDENTITY_INSERT dbo.ap_ledger_entries ON
-- 2026-11-15T03:11:44.000Z | sa | DISABLE TRIGGER dbo.trg_ap_ledger_audit ON dbo.ap_ledger_entries
-- 2026-11-15T03:14:02.000Z | sa | TXN-2026-8836 | 8900.00 | updated_at=2026-11-12T10:00:00Z
`;

  const utf16Catalog = Buffer.from(
    'EnterpriseERP_Financials_Prod\0SQL-PROD-CLUSTER01\\FINANCE\0D:\\SQLData\\EnterpriseERP_Data.mdf\0E:\\SQLLogs\\EnterpriseERP_Log.ldf\0',
    'utf16le'
  );
  const asciiBody = Buffer.from(catalogSql, 'utf8');
  return Buffer.concat([header, utf16Catalog, asciiBody]);
}
