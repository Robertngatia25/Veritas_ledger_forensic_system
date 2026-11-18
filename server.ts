import 'dotenv/config';
import express, { type NextFunction, type Request, type Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import * as XLSX from 'xlsx';
import { createServer as createViteServer } from 'vite';
import {
  appendAuditLog,
  authenticateUser,
  encryptEvidenceArtifact,
  encryptEvidenceStream,
  getSecurityComplianceConfig,
  getStagingFilePath,
  hashFileStream,
  loadVaultState,
  reconcileTransactions,
  registerUserAccount,
  resetVaultToSeededCase,
  runHolisticTimestampScan,
  saveVaultState,
  sha256Hex,
  sha512Hex,
  updateSecurityComplianceConfig,
  verifyAuditChain,
  verifySessionToken,
} from './server/cryptoVault.ts';
import {
  analyzeBackupBuffer,
  analyzeBackupFileStream,
  buildSampleEnterpriseBakBuffer,
} from './server/bakAnalyzer.ts';
import {
  analyzeCrossRefWithAi,
  analyzeHeatmapHotspots,
  explainAuditEventWithAi,
  generateBakArchitecturalAssessment,
  generateComprehensiveForensicReport,
  parseNaturalLanguageAuditFilter,
  runForensicEnquiryQuery,
} from './server/geminiService.ts';
import type { BakAnalysisResult, EvidenceItem, ExcelTransactionRow, UserAccount, UserRole } from './src/types/forensic.ts';

interface AuthRequest extends Request {
  user?: UserAccount;
}

function getClientIp(req: Request): string {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length > 0) {
    return fwd.split(',')[0].trim();
  }
  return req.socket.remoteAddress || '127.0.0.1';
}

function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required. Please sign in.' });
    return;
  }
  const token = authHeader.slice('Bearer '.length).trim();
  const user = verifySessionToken(token);
  if (!user) {
    res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
    return;
  }
  req.user = user;
  next();
}

function normalizeSpreadsheetUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  const gsMatch = trimmed.match(/https:\/\/docs\.google\.com\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
  if (gsMatch?.[1]) {
    const gidMatch = trimmed.match(/gid=(\d+)/);
    const gidPart = gidMatch?.[1] ? `&gid=${gidMatch[1]}` : '';
    return `https://docs.google.com/spreadsheets/d/${gsMatch[1]}/export?format=csv${gidPart}`;
  }
  return trimmed;
}

function parseWorkbookBufferToRows(buf: Buffer): ExcelTransactionRow[] {
  const workbook = XLSX.read(buf, { type: 'buffer', cellDates: true });
  const firstSheetName = workbook.SheetNames[0];
  if (!firstSheetName) {
    throw new Error('Spreadsheet contains no worksheets.');
  }
  const sheet = workbook.Sheets[firstSheetName];
  const rawObjects = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: '' });

  if (rawObjects.length === 0) {
    throw new Error('Spreadsheet worksheet is empty.');
  }

  const pick = (obj: Record<string, unknown>, candidates: string[]): unknown => {
    const entries = Object.entries(obj);
    for (const c of candidates) {
      const hit = entries.find(([k]) => k.toLowerCase().replace(/[^a-z0-9]/g, '') === c);
      if (hit && hit[1] !== '') return hit[1];
    }
    for (const c of candidates) {
      const hit = entries.find(([k]) => k.toLowerCase().replace(/[^a-z0-9]/g, '').includes(c));
      if (hit && hit[1] !== '') return hit[1];
    }
    return undefined;
  };

  const rows: ExcelTransactionRow[] = [];
  rawObjects.forEach((obj, idx) => {
    const codeRaw = pick(obj, ['transactioncode', 'txncode', 'code', 'reference', 'txnid', 'id']);
    const txnCode = String(codeRaw ?? '').trim();
    if (!txnCode) return;

    const amtRaw = pick(obj, ['authorizedamount', 'amount', 'value', 'total', 'debit', 'credit']);
    const parsedAmt =
      typeof amtRaw === 'number'
        ? amtRaw
        : Number(String(amtRaw ?? '0').replace(/[^0-9.-]/g, '')) || 0;

    const dateRaw = pick(obj, ['authorizeddateutc', 'authorizeddate', 'date', 'timestamp', 'createdat', 'txndate']);
    let isoDate = new Date().toISOString();
    if (dateRaw instanceof Date && !Number.isNaN(dateRaw.getTime())) {
      isoDate = dateRaw.toISOString();
    } else if (dateRaw) {
      const d = new Date(String(dateRaw));
      isoDate = Number.isNaN(d.getTime()) ? String(dateRaw) : d.toISOString();
    }

    rows.push({
      rowNumber: idx + 2,
      transactionCode: txnCode,
      authorizedDateUtc: isoDate,
      vendorOrCounterparty: String(
        pick(obj, ['vendororcounterparty', 'vendor', 'counterparty', 'payee', 'merchant', 'description']) ?? 'Unspecified'
      ),
      glAccount: String(pick(obj, ['glaccount', 'glcode', 'account', 'gl', 'category']) ?? 'GL-UNMAPPED'),
      authorizedAmount: parsedAmt,
      currency: String(pick(obj, ['currency', 'ccy']) ?? 'USD'),
      approver: String(pick(obj, ['approver', 'approvedby', 'authorizer', 'manager']) ?? 'Treasury Sheet'),
      status: String(pick(obj, ['status', 'state']) ?? 'Authorized'),
    });
  });

  if (rows.length === 0) {
    throw new Error('No rows with a recognizable transaction code column (e.g. transactionCode, txn_code, code) were found.');
  }
  return rows;
}

function formatGeminiError(err: unknown): { status: number; message: string } {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.includes('GEMINI_API_KEY')) {
    return { status: 500, message: 'Server GEMINI_API_KEY is missing. Configure it in Settings > Secrets.' };
  }
  if (msg.includes('403') || msg.includes('PERMISSION_DENIED') || msg.includes('API_KEY_INVALID')) {
    return { status: 403, message: 'Gemini API key rejected (403/400). Please check your API key in Settings > Secrets.' };
  }
  if (msg.includes('429') || msg.includes('RESOURCE_EXHAUSTED')) {
    return { status: 429, message: 'Gemini API quota exceeded (429). Please retry shortly or check your API quota.' };
  }
  return { status: 500, message: `Gemini AI request failed: ${msg}` };
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Initialize encrypted vault at boot
  loadVaultState();

  // Air-Gap / Loopback Network Isolation Guard
  app.use((req, res, next) => {
    const sec = getSecurityComplianceConfig();
    if (sec.airgapLockdown) {
      const remoteAddr = req.socket.remoteAddress || '';
      const isLoopback =
        remoteAddr === '127.0.0.1' ||
        remoteAddr === '::1' ||
        remoteAddr === '::ffff:127.0.0.1';
      if (!isLoopback) {
        res.status(403).json({
          error: 'Air-Gap Network Lockdown active: non-loopback network connections are blocked.',
        });
        return;
      }
    }
    next();
  });

  app.use(express.json({ limit: '50mb' }));
  app.use('/api/evidence/upload-bak-raw', express.raw({ type: 'application/octet-stream', limit: '250mb' }));
  app.use('/api/evidence/chunk-part', express.raw({ type: 'application/octet-stream', limit: '32mb' }));
  app.use('/api/crossref/upload-sheet-raw', express.raw({ type: 'application/octet-stream', limit: '100mb' }));

  // --- Health ---
  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, timestampUtc: new Date().toISOString() });
  });

  // --- Auth Routes ---
  app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
      res.status(400).json({ error: 'Email and password are required.' });
      return;
    }
    const result = authenticateUser(String(email), String(password), getClientIp(req));
    if ('error' in result) {
      res.status(401).json({ error: result.error });
      return;
    }
    res.json(result);
  });

  app.post('/api/auth/register', (req, res) => {
    const { email, password, fullName, role } = req.body || {};
    if (!email || !password || !fullName) {
      res.status(400).json({ error: 'Full name, email, and password are required.' });
      return;
    }
    if (String(password).length < 8) {
      res.status(400).json({ error: 'Password must be at least 8 characters for compliance.' });
      return;
    }
    const allowedRoles: UserRole[] = ['Lead Forensic Auditor', 'Compliance Officer', 'External Investigator'];
    const safeRole: UserRole = allowedRoles.includes(role) ? role : 'External Investigator';
    const result = registerUserAccount({
      email: String(email),
      password: String(password),
      fullName: String(fullName),
      role: safeRole,
    });
    if ('error' in result) {
      res.status(409).json({ error: result.error });
      return;
    }
    res.status(201).json(result);
  });

  app.get('/api/auth/me', requireAuth, (req: AuthRequest, res) => {
    res.json({ user: req.user });
  });

  app.post('/api/auth/logout', requireAuth, (req: AuthRequest, res) => {
    appendAuditLog({
      actor: req.user!.email,
      actorRole: req.user!.role,
      sourceIp: getClientIp(req),
      category: 'Authentication',
      action: 'AUTH_LOGOUT',
      targetObject: 'vault.session',
      severity: 'Nominal',
    });
    res.json({ ok: true });
  });

  // --- Dashboard & Audit Trail ---
  app.get('/api/dashboard/state', requireAuth, (_req, res) => {
    const state = loadVaultState();
    const vaultStatus = verifyAuditChain();
    res.json({
      auditLogs: state.auditLogs,
      holisticFindings: state.holisticFindings,
      evidenceItems: state.evidenceItems,
      excelRegister: state.excelRegister,
      lastCrossRef: state.lastCrossRef,
      bakAnalyses: state.bakAnalyses,
      vaultStatus,
      securityConfig: getSecurityComplianceConfig(),
    });
  });

  // --- Security, Air-Gap & KDPA 2019 Compliance ---
  app.get('/api/security/config', requireAuth, (_req, res) => {
    res.json({ securityConfig: getSecurityComplianceConfig() });
  });

  app.patch('/api/security/config', requireAuth, (req: AuthRequest, res) => {
    const { airgapLockdown, localDeterministicOnly, kdpaStrictMode, maskPiiBeforeAi } = req.body || {};
    const updated = updateSecurityComplianceConfig({
      ...(typeof airgapLockdown === 'boolean' ? { airgapLockdown } : {}),
      ...(typeof localDeterministicOnly === 'boolean' ? { localDeterministicOnly } : {}),
      ...(typeof kdpaStrictMode === 'boolean' ? { kdpaStrictMode } : {}),
      ...(typeof maskPiiBeforeAi === 'boolean' ? { maskPiiBeforeAi } : {}),
    });

    appendAuditLog({
      actor: req.user!.email,
      actorRole: req.user!.role,
      sourceIp: getClientIp(req),
      category: 'System & Vault',
      action: 'SECURITY_KDPA_POSTURE_UPDATED',
      targetObject: 'vault.securitySettings',
      severity: 'Nominal',
      afterState: {
        airgapLockdown: updated.airgapLockdown,
        localDeterministicOnly: updated.localDeterministicOnly,
        kdpaStrictMode: updated.kdpaStrictMode,
        maskPiiBeforeAi: updated.maskPiiBeforeAi,
      },
    });

    res.json({ securityConfig: updated, auditLogs: loadVaultState().auditLogs });
  });

  app.post('/api/audit/verify', requireAuth, (req: AuthRequest, res) => {
    const status = verifyAuditChain();
    appendAuditLog({
      actor: req.user!.email,
      actorRole: req.user!.role,
      sourceIp: getClientIp(req),
      category: 'System & Vault',
      action: 'CRYPTOGRAPHIC_CHAIN_VERIFICATION',
      targetObject: 'vault.audit_chain',
      severity: status.chainIntact ? 'Nominal' : 'Critical',
      afterState: { chainIntact: status.chainIntact, totalRecords: status.totalSealedLogEntries, tipHash: status.tipHash },
    });
    res.json({ vaultStatus: verifyAuditChain() });
  });

  app.post('/api/audit/holistic-scan', requireAuth, (req: AuthRequest, res) => {
    const state = loadVaultState();
    const findings = runHolisticTimestampScan(state.auditLogs);
    state.holisticFindings = findings;
    saveVaultState(state);

    appendAuditLog({
      actor: req.user!.email,
      actorRole: req.user!.role,
      sourceIp: getClientIp(req),
      category: 'Timestamp Anomaly',
      action: 'HOLISTIC_DATABASE_TIMESTAMP_SCAN',
      targetObject: 'all.audit_events',
      severity: findings.some((f) => f.severity === 'Critical') ? 'Warning' : 'Nominal',
      afterState: { findingsDetected: findings.length },
    });

    res.json({ holisticFindings: findings, auditLogs: loadVaultState().auditLogs });
  });

  app.post('/api/audit/log-export', requireAuth, (req: AuthRequest, res) => {
    const { format, scope, recordCount } = req.body || {};
    appendAuditLog({
      actor: req.user!.email,
      actorRole: req.user!.role,
      sourceIp: getClientIp(req),
      category: 'Evidence Custody',
      action: `COMPLIANCE_EXPORT_${String(format || 'PDF').toUpperCase()}`,
      targetObject: String(scope || 'Forensic Audit Package'),
      severity: 'Nominal',
      afterState: { format, scope, recordCount },
    });
    res.json({ ok: true, auditLogs: loadVaultState().auditLogs });
  });

  app.post('/api/vault/reset-demo', requireAuth, (req: AuthRequest, res) => {
    const fresh = resetVaultToSeededCase();
    appendAuditLog({
      actor: req.user!.email,
      actorRole: req.user!.role,
      sourceIp: getClientIp(req),
      category: 'System & Vault',
      action: 'CASE_BASELINE_RESET',
      targetObject: 'vault.state',
      severity: 'Nominal',
    });
    res.json({
      auditLogs: fresh.auditLogs,
      holisticFindings: fresh.holisticFindings,
      evidenceItems: fresh.evidenceItems,
      excelRegister: fresh.excelRegister,
      lastCrossRef: fresh.lastCrossRef,
      bakAnalyses: fresh.bakAnalyses,
      vaultStatus: verifyAuditChain(),
    });
  });

  // --- .bak & RDBMS Evidence Processing ---
  async function processBackupArtifact(buffer: Buffer, fileName: string, user: UserAccount, ip: string, runAi: boolean) {
    const state = loadVaultState();
    const evidenceId = `EVD-${new Date().getFullYear()}-${String(state.evidenceItems.length + 1).padStart(3, '0')}`;
    const sha256 = sha256Hex(buffer);
    const sha512 = sha512Hex(buffer);

    // Encrypt raw evidence artifact at rest using AES-256-GCM
    encryptEvidenceArtifact(evidenceId, buffer);

    const { analysis } = analyzeBackupBuffer(buffer, fileName, evidenceId);

    if (runAi) {
      const assessment = await generateBakArchitecturalAssessment(analysis, state.auditLogs, state.lastCrossRef);
      analysis.architecturalAssessment = assessment;
    }

    const lower = fileName.toLowerCase();
    const fileType: EvidenceItem['fileType'] = lower.endsWith('.bak')
      ? 'RDBMS Backup (.bak)'
      : lower.endsWith('.sql')
        ? 'SQL Dump (.sql)'
        : lower.endsWith('.json')
          ? 'Audit Package (.json)'
          : 'Spreadsheet (.xlsx/.csv)';

    const nowUtc = new Date().toISOString();
    const evidenceItem: EvidenceItem = {
      evidenceId,
      fileName,
      fileType,
      byteSize: buffer.length,
      sha256,
      sha512,
      encryptedAtRest: true,
      cipherSuite: 'AES-256-GCM (scrypt-SHA256)',
      acquiredAtUtc: nowUtc,
      acquiredBy: user.fullName,
      integrityVerified: true,
      lastVerifiedUtc: nowUtc,
      custodyEvents: [
        {
          timestampUtc: nowUtc,
          stage: 'Acquired',
          actor: user.fullName,
          notes: `Ingested ${fileName} (${buffer.length.toLocaleString()} bytes).`,
          digestAtStage: sha256,
        },
        {
          timestampUtc: nowUtc,
          stage: 'Hashed',
          actor: 'Veritas Custody Engine',
          notes: `Computed immutable SHA-256 (${sha256.slice(0, 16)}...) and SHA-512 fingerprints.`,
          digestAtStage: sha256,
        },
        {
          timestampUtc: nowUtc,
          stage: 'Encrypted',
          actor: 'Veritas Custody Engine',
          notes: 'Sealed artifact at rest with AES-256-GCM.',
          digestAtStage: sha256,
        },
        {
          timestampUtc: nowUtc,
          stage: 'Analyzed',
          actor: runAi ? 'Veritas Parser + Gemini AI' : 'Veritas Binary Parser',
          notes: `Detected ${analysis.detectedFormat}; ${analysis.discoveredTables.length} tables, ${analysis.holisticFindings.length} structural findings.`,
          digestAtStage: sha256,
        },
      ],
    };

    state.evidenceItems.unshift(evidenceItem);
    state.bakAnalyses.unshift(analysis);
    saveVaultState(state);

    appendAuditLog({
      actor: user.email,
      actorRole: user.role,
      sourceIp: ip,
      category: 'Evidence Custody',
      action: 'INGEST_AND_ANALYZE_BACKUP',
      targetObject: fileName,
      severity: analysis.holisticFindings.some((f) => f.severity === 'Critical') ? 'Warning' : 'Nominal',
      afterState: {
        evidenceId,
        sha256,
        detectedFormat: analysis.detectedFormat,
        tablesDiscovered: analysis.discoveredTables.length,
      },
    });

    return {
      analysis,
      evidenceItem,
      evidenceItems: loadVaultState().evidenceItems,
      bakAnalyses: loadVaultState().bakAnalyses,
      auditLogs: loadVaultState().auditLogs,
      vaultStatus: verifyAuditChain(),
    };
  }

  app.post('/api/evidence/upload-bak-raw', requireAuth, async (req: AuthRequest, res) => {
    try {
      const buffer = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
      if (!buffer.length) {
        res.status(400).json({ error: 'Uploaded backup file is empty.' });
        return;
      }
      const fileName = decodeURIComponent(String(req.headers['x-file-name'] || 'database_backup.bak'));
      const runAi = String(req.headers['x-run-ai'] ?? 'true') !== 'false';
      const result = await processBackupArtifact(buffer, fileName, req.user!, getClientIp(req), runAi);
      res.json(result);
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  app.post('/api/evidence/load-sample-bak', requireAuth, async (req: AuthRequest, res) => {
    try {
      const sampleBuffer = buildSampleEnterpriseBakBuffer();
      const result = await processBackupArtifact(
        sampleBuffer,
        'EnterpriseERP_Financials_Prod_20261116.bak',
        req.user!,
        getClientIp(req),
        true
      );
      res.json(result);
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  app.post('/api/evidence/assess-bak/:evidenceId', requireAuth, async (req: AuthRequest, res) => {
    try {
      const state = loadVaultState();
      const target = state.bakAnalyses.find((b) => b.evidenceId === req.params.evidenceId);
      if (!target) {
        res.status(404).json({ error: 'Backup analysis record not found.' });
        return;
      }
      target.architecturalAssessment = await generateBakArchitecturalAssessment(
        target,
        state.auditLogs,
        state.lastCrossRef
      );
      saveVaultState(state);
      res.json({ analysis: target, bakAnalyses: state.bakAnalyses });
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  // Helper to persist streaming analysis result (used by both Chunked Multi-GB Upload and Local Hyper-V Path Ingestion)
  async function finalizeStreamedBackup(params: {
    sourcePath: string;
    fileName: string;
    user: UserAccount;
    ip: string;
    runAi: boolean;
    encryptCopy: boolean;
    cleanupSource: boolean;
  }) {
    const state = loadVaultState();
    const evidenceId = `EVD-${new Date().getFullYear()}-${String(state.evidenceItems.length + 1).padStart(3, '0')}`;

    let byteSize = 0;
    let sha256 = '';
    let sha512 = '';

    if (params.encryptCopy) {
      const encRes = await encryptEvidenceStream(params.sourcePath, evidenceId);
      byteSize = encRes.byteSize;
      sha256 = encRes.sha256;
      sha512 = encRes.sha512;
    } else {
      const hashRes = await hashFileStream(params.sourcePath);
      byteSize = hashRes.byteSize;
      sha256 = hashRes.sha256;
      sha512 = hashRes.sha512;
    }

    const { analysis } = await analyzeBackupFileStream(params.sourcePath, params.fileName, evidenceId, {
      byteSize,
      sha256,
      sha512,
    });

    if (params.cleanupSource && fs.existsSync(params.sourcePath)) {
      fs.unlinkSync(params.sourcePath);
    }

    if (params.runAi) {
      const assessment: BakAnalysisResult['architecturalAssessment'] =
        await generateBakArchitecturalAssessment(analysis, state.auditLogs, state.lastCrossRef);
      analysis.architecturalAssessment = assessment;
    }

    const lower = params.fileName.toLowerCase();
    const fileType: EvidenceItem['fileType'] = lower.endsWith('.bak')
      ? 'RDBMS Backup (.bak)'
      : lower.endsWith('.sql')
        ? 'SQL Dump (.sql)'
        : lower.endsWith('.json')
          ? 'Audit Package (.json)'
          : 'Spreadsheet (.xlsx/.csv)';

    const nowUtc = new Date().toISOString();
    const evidenceItem: EvidenceItem = {
      evidenceId,
      fileName: params.fileName,
      fileType,
      byteSize,
      sha256,
      sha512,
      encryptedAtRest: params.encryptCopy,
      cipherSuite: params.encryptCopy
        ? 'AES-256-GCM Chunked Stream (scrypt-SHA256)'
        : 'Read-Only Local Mount Reference (Zero-Copy)',
      acquiredAtUtc: nowUtc,
      acquiredBy: params.user.fullName,
      integrityVerified: true,
      lastVerifiedUtc: nowUtc,
      custodyEvents: [
        {
          timestampUtc: nowUtc,
          stage: 'Acquired',
          actor: params.user.fullName,
          notes: `Stream-ingested ${params.fileName} (${(byteSize / (1024 * 1024)).toFixed(2)} MB).`,
          digestAtStage: sha256,
        },
        {
          timestampUtc: nowUtc,
          stage: 'Hashed',
          actor: 'Veritas Streaming Engine',
          notes: `Full-stream SHA-256 (${sha256.slice(0, 16)}...) & SHA-512 verified.`,
          digestAtStage: sha256,
        },
        {
          timestampUtc: nowUtc,
          stage: 'Encrypted',
          actor: 'Veritas Custody Engine',
          notes: params.encryptCopy
            ? 'Sealed into chunked AES-256-GCM encrypted vault.'
            : 'Referenced in-place from read-only Hyper-V evidence mount (zero duplication).',
          digestAtStage: sha256,
        },
        {
          timestampUtc: nowUtc,
          stage: 'Analyzed',
          actor: params.runAi ? 'Veritas Stream Parser + Assessment Engine' : 'Veritas Stream Parser',
          notes: `Detected ${analysis.detectedFormat}; ${analysis.discoveredTables.length} tables, ${analysis.holisticFindings.length} findings.`,
          digestAtStage: sha256,
        },
      ],
    };

    state.evidenceItems.unshift(evidenceItem);
    state.bakAnalyses.unshift(analysis);
    saveVaultState(state);

    appendAuditLog({
      actor: params.user.email,
      actorRole: params.user.role,
      sourceIp: params.ip,
      category: 'Evidence Custody',
      action: 'INGEST_MULTI_GB_BACKUP_STREAM',
      targetObject: params.fileName,
      severity: analysis.holisticFindings.some((f) => f.severity === 'Critical') ? 'Warning' : 'Nominal',
      afterState: {
        evidenceId,
        byteSize,
        sha256,
        detectedFormat: analysis.detectedFormat,
        tablesDiscovered: analysis.discoveredTables.length,
      },
    });

    return {
      analysis,
      evidenceItem,
      evidenceItems: loadVaultState().evidenceItems,
      bakAnalyses: loadVaultState().bakAnalyses,
      auditLogs: loadVaultState().auditLogs,
      vaultStatus: verifyAuditChain(),
    };
  }

  // --- Unlimited-Size Chunked Streaming Upload (Supports 15 GB+ .bak files) ---
  app.post('/api/evidence/chunk-init', requireAuth, (req: AuthRequest, res) => {
    const uploadId = `upl_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const stagingPath = getStagingFilePath(uploadId);
    fs.writeFileSync(stagingPath, Buffer.alloc(0), { mode: 0o600 });
    res.json({ uploadId });
  });

  app.post('/api/evidence/chunk-part', requireAuth, async (req: AuthRequest, res) => {
    try {
      const uploadId = String(req.headers['x-upload-id'] || '');
      if (!uploadId) {
        res.status(400).json({ error: 'Missing x-upload-id header.' });
        return;
      }
      const stagingPath = getStagingFilePath(uploadId);
      if (!fs.existsSync(stagingPath)) {
        res.status(404).json({ error: 'Upload session not found.' });
        return;
      }
      const chunk = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
      await fs.promises.appendFile(stagingPath, chunk);
      res.json({ ok: true, appendedBytes: chunk.length });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Chunk append failed.' });
    }
  });

  app.post('/api/evidence/chunk-finalize', requireAuth, async (req: AuthRequest, res) => {
    try {
      const { uploadId, fileName, runAi = true, encryptCopy = true } = req.body || {};
      if (!uploadId || !fileName) {
        res.status(400).json({ error: 'uploadId and fileName are required.' });
        return;
      }
      const stagingPath = getStagingFilePath(String(uploadId));
      if (!fs.existsSync(stagingPath)) {
        res.status(404).json({ error: 'Staged upload file not found.' });
        return;
      }
      const result = await finalizeStreamedBackup({
        sourcePath: stagingPath,
        fileName: String(fileName),
        user: req.user!,
        ip: getClientIp(req),
        runAi: Boolean(runAi),
        encryptCopy: Boolean(encryptCopy),
        cleanupSource: true,
      });
      res.json(result);
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  // --- Direct Local / Hyper-V Mounted File Path Ingestion (Zero HTTP Upload Overhead for 15GB+) ---
  app.post('/api/evidence/ingest-local-path', requireAuth, async (req: AuthRequest, res) => {
    try {
      const { filePath, runAi = true, encryptCopy = false } = req.body || {};
      if (!filePath || typeof filePath !== 'string') {
        res.status(400).json({ error: 'A valid local file path on the host/VM is required.' });
        return;
      }
      const resolvedPath = path.resolve(filePath.trim());
      if (!fs.existsSync(resolvedPath)) {
        res.status(404).json({ error: `File not found at ${resolvedPath}. Verify mount path inside your Ubuntu Hyper-V VM.` });
        return;
      }
      const stat = fs.statSync(resolvedPath);
      if (!stat.isFile()) {
        res.status(400).json({ error: 'Target path is not a regular file.' });
        return;
      }
      const result = await finalizeStreamedBackup({
        sourcePath: resolvedPath,
        fileName: path.basename(resolvedPath),
        user: req.user!,
        ip: getClientIp(req),
        runAi: Boolean(runAi),
        encryptCopy: Boolean(encryptCopy),
        cleanupSource: false,
      });
      res.json(result);
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  // --- Online Excel Sheet Cross-Reference ---
  app.post('/api/crossref/fetch-url', requireAuth, async (req: AuthRequest, res) => {
    try {
      const sec = getSecurityComplianceConfig();
      if (sec.outboundNetworkBlocked) {
        res.status(403).json({
          error: 'Outbound URL fetching is blocked while Air-Gap Lockdown or Local Deterministic Mode is active. Upload the .xlsx/.csv file locally instead.',
        });
        return;
      }
      const { url } = req.body || {};
      if (!url || typeof url !== 'string') {
        res.status(400).json({ error: 'Please provide a valid spreadsheet URL.' });
        return;
      }
      const fetchUrl = normalizeSpreadsheetUrl(url);
      const response = await fetch(fetchUrl);
      if (!response.ok) {
        res.status(400).json({
          error: `Unable to fetch online spreadsheet (HTTP ${response.status}). Ensure the link is publicly readable or download as .xlsx/.csv and upload directly.`,
        });
        return;
      }
      const arrayBuf = await response.arrayBuffer();
      const buf = Buffer.from(arrayBuf);
      const rows = parseWorkbookBufferToRows(buf);
      const sheetSha256 = sha256Hex(buf);
      const sheetName = `Online Sheet (${new URL(fetchUrl).hostname})`;

      const state = loadVaultState();
      state.excelRegister = {
        sheetName,
        sheetSha256,
        loadedAtUtc: new Date().toISOString(),
        rows,
      };
      const crossRef = reconcileTransactions(state.auditLogs, rows, sheetName, sheetSha256);
      state.lastCrossRef = crossRef;
      saveVaultState(state);

      appendAuditLog({
        actor: req.user!.email,
        actorRole: req.user!.role,
        sourceIp: getClientIp(req),
        category: 'Cross-Ref Discrepancy',
        action: 'ONLINE_EXCEL_CROSSREF_RUN',
        targetObject: sheetName,
        severity: crossRef.discrepancyCount > 0 ? 'Warning' : 'Nominal',
        afterState: {
          matchedCount: crossRef.matchedCount,
          discrepancyCount: crossRef.discrepancyCount,
          totalVarianceValue: crossRef.totalVarianceValue,
        },
      });

      res.json({
        excelRegister: state.excelRegister,
        lastCrossRef: crossRef,
        auditLogs: loadVaultState().auditLogs,
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Failed to fetch or parse online spreadsheet.',
      });
    }
  });

  app.post('/api/crossref/upload-sheet-raw', requireAuth, async (req: AuthRequest, res) => {
    try {
      const buf = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
      if (!buf.length) {
        res.status(400).json({ error: 'Uploaded spreadsheet is empty.' });
        return;
      }
      const fileName = decodeURIComponent(String(req.headers['x-file-name'] || 'transactions.xlsx'));
      const rows = parseWorkbookBufferToRows(buf);
      const sheetSha256 = sha256Hex(buf);
      const sheetSha512 = sha512Hex(buf);

      const state = loadVaultState();
      const evidenceId = `EVD-${new Date().getFullYear()}-${String(state.evidenceItems.length + 1).padStart(3, '0')}`;
      encryptEvidenceArtifact(evidenceId, buf);
      const nowUtc = new Date().toISOString();

      state.evidenceItems.unshift({
        evidenceId,
        fileName,
        fileType: 'Spreadsheet (.xlsx/.csv)',
        byteSize: buf.length,
        sha256: sheetSha256,
        sha512: sheetSha512,
        encryptedAtRest: true,
        cipherSuite: 'AES-256-GCM (scrypt-SHA256)',
        acquiredAtUtc: nowUtc,
        acquiredBy: req.user!.fullName,
        integrityVerified: true,
        lastVerifiedUtc: nowUtc,
        custodyEvents: [
          {
            timestampUtc: nowUtc,
            stage: 'Acquired',
            actor: req.user!.fullName,
            notes: `Uploaded reference workbook ${fileName} (${rows.length} transaction rows).`,
            digestAtStage: sheetSha256,
          },
          {
            timestampUtc: nowUtc,
            stage: 'Encrypted',
            actor: 'Veritas Custody Engine',
            notes: 'Sealed workbook in AES-256-GCM vault.',
            digestAtStage: sheetSha256,
          },
        ],
      });

      state.excelRegister = {
        sheetName: fileName,
        sheetSha256,
        loadedAtUtc: nowUtc,
        rows,
      };
      const crossRef = reconcileTransactions(state.auditLogs, rows, fileName, sheetSha256);
      state.lastCrossRef = crossRef;
      saveVaultState(state);

      appendAuditLog({
        actor: req.user!.email,
        actorRole: req.user!.role,
        sourceIp: getClientIp(req),
        category: 'Cross-Ref Discrepancy',
        action: 'EXCEL_WORKBOOK_CROSSREF_RUN',
        targetObject: fileName,
        severity: crossRef.discrepancyCount > 0 ? 'Warning' : 'Nominal',
        afterState: {
          rowsParsed: rows.length,
          matchedCount: crossRef.matchedCount,
          discrepancyCount: crossRef.discrepancyCount,
        },
      });

      res.json({
        excelRegister: state.excelRegister,
        lastCrossRef: crossRef,
        evidenceItems: state.evidenceItems,
        auditLogs: loadVaultState().auditLogs,
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Failed to parse uploaded workbook.',
      });
    }
  });

  app.post('/api/crossref/reconcile', requireAuth, (req: AuthRequest, res) => {
    const state = loadVaultState();
    const crossRef = reconcileTransactions(
      state.auditLogs,
      state.excelRegister.rows,
      state.excelRegister.sheetName,
      state.excelRegister.sheetSha256
    );
    state.lastCrossRef = crossRef;
    saveVaultState(state);

    appendAuditLog({
      actor: req.user!.email,
      actorRole: req.user!.role,
      sourceIp: getClientIp(req),
      category: 'Cross-Ref Discrepancy',
      action: 'RECONCILE_MASTER_REGISTER',
      targetObject: state.excelRegister.sheetName,
      severity: crossRef.discrepancyCount > 0 ? 'Warning' : 'Nominal',
      afterState: { matched: crossRef.matchedCount, discrepancies: crossRef.discrepancyCount },
    });

    res.json({ lastCrossRef: crossRef, auditLogs: loadVaultState().auditLogs });
  });

  // --- Gemini AI Forensic Enquiry & Comprehensive Report ---
  app.post('/api/ai/enquiry', requireAuth, async (req: AuthRequest, res) => {
    try {
      const { question } = req.body || {};
      if (!question || typeof question !== 'string') {
        res.status(400).json({ error: 'Enquiry question is required.' });
        return;
      }
      const state = loadVaultState();
      const answer = await runForensicEnquiryQuery({
        question,
        auditLogs: state.auditLogs,
        holisticFindings: state.holisticFindings,
        crossRef: state.lastCrossRef,
        bakAnalyses: state.bakAnalyses,
        evidenceItems: state.evidenceItems,
      });

      appendAuditLog({
        actor: req.user!.email,
        actorRole: req.user!.role,
        sourceIp: getClientIp(req),
        category: 'System & Vault',
        action: 'AI_FORENSIC_ENQUIRY',
        targetObject: 'gemini-4-hydrogen',
        severity: 'Nominal',
        afterState: { questionPreview: question.slice(0, 100) },
      });

      res.json({ answer, auditLogs: loadVaultState().auditLogs });
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  app.post('/api/ai/comprehensive-report', requireAuth, async (req: AuthRequest, res) => {
    try {
      const { caseTitle } = req.body || {};
      const state = loadVaultState();
      const report = await generateComprehensiveForensicReport({
        caseTitle: caseTitle || 'Enterprise ERP Financial Ledger & Backup Forensic Audit',
        generatedBy: `${req.user!.fullName} (${req.user!.badgeId})`,
        auditLogs: state.auditLogs,
        holisticFindings: state.holisticFindings,
        crossRef: state.lastCrossRef,
        bakAnalyses: state.bakAnalyses,
        evidenceItems: state.evidenceItems,
      });

      appendAuditLog({
        actor: req.user!.email,
        actorRole: req.user!.role,
        sourceIp: getClientIp(req),
        category: 'Evidence Custody',
        action: 'COMPREHENSIVE_REPORT_GENERATED',
        targetObject: report.reportId,
        severity: 'Nominal',
        afterState: { reportId: report.reportId, findingsCount: report.keyFindings.length },
      });

      res.json({ report, auditLogs: loadVaultState().auditLogs });
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  app.post('/api/ai/explain-event', requireAuth, async (req: AuthRequest, res) => {
    try {
      const { eventId } = req.body || {};
      const state = loadVaultState();
      const idx = state.auditLogs.findIndex((e) => e.id === eventId);
      if (idx === -1) {
        res.status(404).json({ error: 'Audit event not found.' });
        return;
      }
      const target = state.auditLogs[idx];
      const surrounding = state.auditLogs.slice(Math.max(0, idx - 2), Math.min(state.auditLogs.length, idx + 3));
      const explanation = await explainAuditEventWithAi(target, surrounding);

      appendAuditLog({
        actor: req.user!.email,
        actorRole: req.user!.role,
        sourceIp: getClientIp(req),
        category: 'System & Vault',
        action: 'AI_EVENT_EXPLANATION',
        targetObject: target.id,
        severity: 'Nominal',
      });

      res.json({ explanation, auditLogs: loadVaultState().auditLogs });
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  app.post('/api/ai/crossref-synthesis', requireAuth, async (req: AuthRequest, res) => {
    try {
      const state = loadVaultState();
      if (!state.lastCrossRef) {
        res.status(400).json({ error: 'No Excel cross-reference reconciliation available yet.' });
        return;
      }
      const synthesis = await analyzeCrossRefWithAi(state.lastCrossRef);

      appendAuditLog({
        actor: req.user!.email,
        actorRole: req.user!.role,
        sourceIp: getClientIp(req),
        category: 'Cross-Ref Discrepancy',
        action: 'AI_CROSSREF_FRAUD_SYNTHESIS',
        targetObject: state.lastCrossRef.sheetSourceName,
        severity: 'Nominal',
      });

      res.json({ synthesis, auditLogs: loadVaultState().auditLogs });
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  app.post('/api/ai/heatmap-insight', requireAuth, async (req: AuthRequest, res) => {
    try {
      const { lens, selectedLabel, topHotspots } = req.body || {};
      const insight = await analyzeHeatmapHotspots({
        lens: String(lens || 'Temporal'),
        selectedLabel,
        topHotspots: Array.isArray(topHotspots) ? topHotspots : [],
      });
      res.json({ insight });
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  app.post('/api/ai/nl-filter', requireAuth, async (req: AuthRequest, res) => {
    try {
      const { query } = req.body || {};
      if (!query || typeof query !== 'string') {
        res.status(400).json({ error: 'Natural-language filter query is required.' });
        return;
      }
      const filter = await parseNaturalLanguageAuditFilter(query);
      res.json({ filter });
    } catch (err) {
      const formatted = formatGeminiError(err);
      res.status(formatted.status).json({ error: formatted.message });
    }
  });

  // --- Vite Middleware (Dev) or Static Assets (Prod) ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const bindHost = process.env.BIND_HOST || '0.0.0.0';
  app.listen(PORT, bindHost, () => {
    console.log(`Veritas Ledger Forensic Server listening on http://${bindHost}:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
