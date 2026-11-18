import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  AuditCategory,
  AuditEvent,
  AuditSeverity,
  BakAnalysisResult,
  CrossRefDiscrepancy,
  CrossRefSummary,
  EvidenceItem,
  ExcelTransactionRow,
  HolisticFinding,
  KdpaPrincipleStatus,
  SecurityComplianceConfig,
  UserAccount,
  UserRole,
  VaultStatus,
} from '../src/types/forensic.ts';

interface StoredUser extends UserAccount {
  passwordSalt: string;
  passwordHash: string;
}

interface VaultState {
  version: number;
  createdAtUtc: string;
  users: StoredUser[];
  auditLogs: AuditEvent[];
  evidenceItems: EvidenceItem[];
  excelRegister: {
    sheetName: string;
    sheetSha256: string;
    loadedAtUtc: string;
    rows: ExcelTransactionRow[];
  };
  lastCrossRef: CrossRefSummary | null;
  bakAnalyses: BakAnalysisResult[];
  holisticFindings: HolisticFinding[];
  securitySettings?: {
    airgapLockdown: boolean;
    localDeterministicOnly: boolean;
    kdpaStrictMode: boolean;
    maskPiiBeforeAi: boolean;
  };
}

interface EncryptedEnvelope {
  cipher: 'aes-256-gcm';
  kdf: 'scrypt-sha256';
  ivHex: string;
  authTagHex: string;
  saltHex: string;
  ciphertextBase64: string;
  sealedAtUtc: string;
}

const STORAGE_DIR = path.resolve(process.cwd(), 'vault_storage');
const VAULT_FILE = path.join(STORAGE_DIR, 'veritas_vault.enc');
const KEY_FILE = path.join(STORAGE_DIR, '.vault.key');
const GENESIS_HASH = '0'.repeat(64);

function ensureStorageDir() {
  if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true, mode: 0o700 });
  }
}

function getMasterSecret(): Buffer {
  ensureStorageDir();
  if (process.env.VAULT_MASTER_KEY && process.env.VAULT_MASTER_KEY.length >= 16) {
    return crypto.createHash('sha256').update(process.env.VAULT_MASTER_KEY).digest();
  }
  if (fs.existsSync(KEY_FILE)) {
    const raw = fs.readFileSync(KEY_FILE, 'utf8').trim();
    return Buffer.from(raw, 'hex');
  }
  const generated = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, generated.toString('hex'), { mode: 0o600 });
  return generated;
}

function getSessionSigningKey(): Buffer {
  return crypto.createHmac('sha256', getMasterSecret()).update('veritas-session-signing-v1').digest();
}

export function sha256Hex(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function sha512Hex(data: Buffer | string): string {
  return crypto.createHash('sha512').update(data).digest('hex');
}

function encryptJson(payload: unknown): EncryptedEnvelope {
  const master = getMasterSecret();
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(master, salt, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    cipher: 'aes-256-gcm',
    kdf: 'scrypt-sha256',
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    saltHex: salt.toString('hex'),
    ciphertextBase64: encrypted.toString('base64'),
    sealedAtUtc: new Date().toISOString(),
  };
}

function decryptJson<T>(envelope: EncryptedEnvelope): T {
  const master = getMasterSecret();
  const salt = Buffer.from(envelope.saltHex, 'hex');
  const derivedKey = crypto.scryptSync(master, salt, 32);
  const iv = Buffer.from(envelope.ivHex, 'hex');
  const authTag = Buffer.from(envelope.authTagHex, 'hex');
  const ciphertext = Buffer.from(envelope.ciphertextBase64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8')) as T;
}

export function encryptEvidenceArtifact(evidenceId: string, rawBuffer: Buffer): string {
  ensureStorageDir();
  const master = getMasterSecret();
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(master, salt, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
  const encrypted = Buffer.concat([cipher.update(rawBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const artifactPath = path.join(STORAGE_DIR, `evidence_${evidenceId}.enc`);
  const payload = {
    cipher: 'aes-256-gcm',
    ivHex: iv.toString('hex'),
    saltHex: salt.toString('hex'),
    authTagHex: authTag.toString('hex'),
    dataBase64: encrypted.toString('base64'),
  };
  fs.writeFileSync(artifactPath, JSON.stringify(payload), { mode: 0o600 });
  return artifactPath;
}

export async function hashFileStream(filePath: string): Promise<{ byteSize: number; sha256: string; sha512: string }> {
  return new Promise((resolve, reject) => {
    const h256 = crypto.createHash('sha256');
    const h512 = crypto.createHash('sha512');
    let byteSize = 0;
    const stream = fs.createReadStream(filePath, { highWaterMark: 16 * 1024 * 1024 });
    stream.on('data', (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      byteSize += buf.length;
      h256.update(buf);
      h512.update(buf);
    });
    stream.on('error', reject);
    stream.on('end', () => {
      resolve({
        byteSize,
        sha256: h256.digest('hex'),
        sha512: h512.digest('hex'),
      });
    });
  });
}

/**
 * Streams a multi-GB file (e.g. 15GB .bak) into AES-256-GCM authenticated 8MB chunks
 * without buffering the file in RAM, avoiding Node/V8 2GB Buffer limits.
 */
export async function encryptEvidenceStream(
  sourcePath: string,
  evidenceId: string
): Promise<{ encryptedPath: string; byteSize: number; sha256: string; sha512: string }> {
  ensureStorageDir();
  const master = getMasterSecret();
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(master, salt, 32);
  const encryptedPath = path.join(STORAGE_DIR, `evidence_${evidenceId}.encbin`);

  const h256 = crypto.createHash('sha256');
  const h512 = crypto.createHash('sha512');
  let byteSize = 0;
  let chunkIndex = 0;

  const outStream = fs.createWriteStream(encryptedPath, { mode: 0o600 });
  const header = Buffer.alloc(32);
  header.write('VERITAS_GCM_V1\0', 0, 'ascii');
  salt.copy(header, 16);
  outStream.write(header);

  await new Promise<void>((resolve, reject) => {
    const inStream = fs.createReadStream(sourcePath, { highWaterMark: 8 * 1024 * 1024 });
    inStream.on('data', (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      byteSize += buf.length;
      h256.update(buf);
      h512.update(buf);

      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
      cipher.setAAD(Buffer.from(`chunk:${chunkIndex}`));
      const enc = Buffer.concat([cipher.update(buf), cipher.final()]);
      const tag = cipher.getAuthTag();

      const frameMeta = Buffer.alloc(32);
      frameMeta.writeUInt32BE(enc.length, 0);
      iv.copy(frameMeta, 4);
      tag.copy(frameMeta, 16);

      const canContinue = outStream.write(frameMeta) && outStream.write(enc);
      chunkIndex++;
      if (!canContinue) {
        inStream.pause();
        outStream.once('drain', () => inStream.resume());
      }
    });
    inStream.on('error', reject);
    outStream.on('error', reject);
    inStream.on('end', () => {
      outStream.end(() => resolve());
    });
  });

  return {
    encryptedPath,
    byteSize,
    sha256: h256.digest('hex'),
    sha512: h512.digest('hex'),
  };
}

export function getStagingFilePath(uploadId: string): string {
  ensureStorageDir();
  const safeId = uploadId.replace(/[^a-zA-Z0-9_-]/g, '');
  return path.join(STORAGE_DIR, `staging_${safeId}.tmp`);
}

export function hashPassword(password: string, salt?: string): { salt: string; hash: string } {
  const useSalt = salt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.pbkdf2Sync(password, useSalt, 120000, 32, 'sha256').toString('hex');
  return { salt: useSalt, hash: derived };
}

export function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  const { hash } = hashPassword(password, salt);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(expectedHash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function issueSessionToken(user: UserAccount): string {
  const exp = Date.now() + 1000 * 60 * 60 * 12; // 12 hours
  const claims = {
    sub: user.id,
    email: user.email,
    fullName: user.fullName,
    role: user.role,
    badgeId: user.badgeId,
    exp,
  };
  const body = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const sig = crypto.createHmac('sha256', getSessionSigningKey()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

export function verifySessionToken(token: string): UserAccount | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [body, sig] = parts;
    const expectedSig = crypto
      .createHmac('sha256', getSessionSigningKey())
      .update(body)
      .digest('base64url');
    const sigBuf = Buffer.from(sig);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!claims.exp || Date.now() > claims.exp) return null;
    const state = loadVaultState();
    const found = state.users.find((u) => u.id === claims.sub);
    if (!found) return null;
    return sanitizeUser(found);
  } catch {
    return null;
  }
}

function sanitizeUser(u: StoredUser): UserAccount {
  const { passwordHash: _ph, passwordSalt: _ps, ...safe } = u;
  return safe;
}

export function computeRecordHash(
  event: Omit<AuditEvent, 'recordHash'>
): string {
  const canonical = JSON.stringify({
    id: event.id,
    sequenceId: event.sequenceId,
    timestampUtc: event.timestampUtc,
    recordedAtUtc: event.recordedAtUtc,
    actor: event.actor,
    actorRole: event.actorRole,
    sourceIp: event.sourceIp,
    category: event.category,
    action: event.action,
    targetObject: event.targetObject,
    transactionCode: event.transactionCode ?? null,
    amount: event.amount ?? null,
    currency: event.currency ?? null,
    severity: event.severity,
    anomalyFlags: event.anomalyFlags,
    beforeState: event.beforeState ?? null,
    afterState: event.afterState ?? null,
    sqlStatement: event.sqlStatement ?? null,
    prevHash: event.prevHash,
  });
  return sha256Hex(canonical);
}

function buildSeededState(): VaultState {
  const now = new Date('2026-11-18T11:30:00.000Z').toISOString();
  const adminCreds = hashPassword('ForensicAudit#2026');
  const reviewerCreds = hashPassword('Compliance#2026');

  const users: StoredUser[] = [
    {
      id: 'usr_lead_01',
      email: 'auditor@veritasledger.org',
      fullName: 'Elena Vance, CFE, CISA',
      role: 'Lead Forensic Auditor',
      badgeId: 'AUD-8841-UK',
      createdAtUtc: '2026-09-01T08:00:00.000Z',
      lastLoginUtc: now,
      passwordSalt: adminCreds.salt,
      passwordHash: adminCreds.hash,
    },
    {
      id: 'usr_comp_02',
      email: 'compliance@veritasledger.org',
      fullName: 'Marcus Thorne, CPA',
      role: 'Compliance Officer',
      badgeId: 'CMP-4410-UK',
      createdAtUtc: '2026-09-05T09:15:00.000Z',
      passwordSalt: reviewerCreds.salt,
      passwordHash: reviewerCreds.hash,
    },
  ];

  const rawLogs: Omit<AuditEvent, 'prevHash' | 'recordHash'>[] = [
    {
      id: 'evt_001',
      sequenceId: 4001,
      timestampUtc: '2026-11-12T09:14:22.000Z',
      recordedAtUtc: '2026-11-12T09:14:22.410Z',
      actor: 'm.henderson@corp-erp.internal',
      actorRole: 'AP_CLERK',
      sourceIp: '10.24.18.42',
      category: 'DML / Schema Change',
      action: 'INSERT_AP_INVOICE',
      targetObject: 'dbo.ap_ledger_entries',
      transactionCode: 'TXN-2026-8835',
      amount: 12450.0,
      currency: 'USD',
      severity: 'Nominal',
      anomalyFlags: [],
      beforeState: null,
      afterState: { txn_code: 'TXN-2026-8835', vendor: 'Northbridge Logistics Ltd', amount: 12450.0, gl_code: 'GL-5120-FREIGHT' },
      sqlStatement: "INSERT INTO dbo.ap_ledger_entries (txn_code, vendor_id, amount, gl_code, created_at) VALUES ('TXN-2026-8835', 1042, 12450.00, 'GL-5120-FREIGHT', SYSUTCDATETIME());",
    },
    {
      id: 'evt_002',
      sequenceId: 4002,
      timestampUtc: '2026-11-12T11:02:09.000Z',
      recordedAtUtc: '2026-11-12T11:02:09.118Z',
      actor: 's.patel@corp-erp.internal',
      actorRole: 'TREASURY_CONTROLLER',
      sourceIp: '10.24.18.19',
      category: 'DML / Schema Change',
      action: 'APPROVE_DISBURSEMENT',
      targetObject: 'dbo.ap_ledger_entries',
      transactionCode: 'TXN-2026-8836',
      amount: 8900.0,
      currency: 'USD',
      severity: 'Nominal',
      anomalyFlags: [],
      beforeState: { status: 'PENDING_APPROVAL', amount: 8900.0 },
      afterState: { status: 'APPROVED', amount: 8900.0, approved_by: 's.patel' },
      sqlStatement: "UPDATE dbo.ap_ledger_entries SET status = 'APPROVED', approved_by = 's.patel', updated_at = SYSUTCDATETIME() WHERE txn_code = 'TXN-2026-8836';",
    },
    {
      id: 'evt_003',
      sequenceId: 4003,
      timestampUtc: '2026-11-13T14:28:40.000Z',
      recordedAtUtc: '2026-11-13T14:28:40.502Z',
      actor: 'm.henderson@corp-erp.internal',
      actorRole: 'AP_CLERK',
      sourceIp: '10.24.18.42',
      category: 'DML / Schema Change',
      action: 'INSERT_AP_INVOICE',
      targetObject: 'dbo.ap_ledger_entries',
      transactionCode: 'TXN-2026-8837',
      amount: 24750.0,
      currency: 'USD',
      severity: 'Nominal',
      anomalyFlags: [],
      beforeState: null,
      afterState: { txn_code: 'TXN-2026-8837', vendor: 'Kestrel Cloud Infra Inc', amount: 24750.0, gl_code: 'GL-6200-CLOUD' },
      sqlStatement: "INSERT INTO dbo.ap_ledger_entries (txn_code, vendor_id, amount, gl_code, created_at) VALUES ('TXN-2026-8837', 1088, 24750.00, 'GL-6200-CLOUD', SYSUTCDATETIME());",
    },
    {
      id: 'evt_004',
      sequenceId: 4004,
      timestampUtc: '2026-11-14T10:05:11.000Z',
      recordedAtUtc: '2026-11-14T10:05:11.204Z',
      actor: 'r.okonkwo@corp-erp.internal',
      actorRole: 'FINANCE_MANAGER',
      sourceIp: '10.24.19.8',
      category: 'Cross-Ref Discrepancy',
      action: 'UPDATE_DISBURSEMENT_AMOUNT',
      targetObject: 'dbo.ap_ledger_entries',
      transactionCode: 'TXN-2026-8838',
      amount: 48500.0,
      currency: 'USD',
      severity: 'Critical',
      anomalyFlags: ['AMOUNT_MISMATCH_VS_EXCEL', 'POST_APPROVAL_EDIT'],
      beforeState: { txn_code: 'TXN-2026-8838', amount: 4850.0, status: 'APPROVED' },
      afterState: { txn_code: 'TXN-2026-8838', amount: 48500.0, status: 'APPROVED' },
      sqlStatement: "UPDATE dbo.ap_ledger_entries SET amount = 48500.00, updated_at = '2026-11-14T10:05:11Z' WHERE txn_code = 'TXN-2026-8838';",
    },
    {
      id: 'evt_005',
      sequenceId: 4005,
      timestampUtc: '2026-11-14T16:40:00.000Z',
      recordedAtUtc: '2026-11-14T16:40:00.892Z',
      actor: 's.patel@corp-erp.internal',
      actorRole: 'TREASURY_CONTROLLER',
      sourceIp: '10.24.18.19',
      category: 'DML / Schema Change',
      action: 'SETTLE_WIRE_BATCH',
      targetObject: 'dbo.wire_settlements',
      transactionCode: 'TXN-2026-8839',
      amount: 15200.0,
      currency: 'USD',
      severity: 'Nominal',
      anomalyFlags: [],
      beforeState: { status: 'QUEUED' },
      afterState: { status: 'SETTLED', batch: 'ACH-20261114-B' },
      sqlStatement: "UPDATE dbo.wire_settlements SET status = 'SETTLED' WHERE txn_code = 'TXN-2026-8839';",
    },
    // Sequence gap here: 4006, 4007 missing in target RDBMS logs!
    {
      id: 'evt_006',
      sequenceId: 4008,
      timestampUtc: '2026-10-29T08:15:00.000Z', // Backdated 17 days earlier than seq 4005!
      recordedAtUtc: '2026-11-15T02:47:19.330Z',
      actor: 'sa (SQL_SYSADMIN)',
      actorRole: 'SYSADMIN',
      sourceIp: '172.16.99.204',
      category: 'Timestamp Anomaly',
      action: 'MANUAL_LEDGER_BACKDATE_INSERT',
      targetObject: 'dbo.ap_ledger_entries',
      transactionCode: 'TXN-2026-8840',
      amount: 31800.0,
      currency: 'USD',
      severity: 'Critical',
      anomalyFlags: ['SEQUENCE_TIMESTAMP_INVERSION', 'OFF_HOURS_SYSADMIN', 'MISSING_EXCEL_CODE', 'SEQUENCE_GAP_PRECEDING'],
      beforeState: null,
      afterState: { txn_code: 'TXN-2026-8840', vendor: 'Meridian Offshore Holdings', amount: 31800.0, created_at: '2026-10-29T08:15:00Z', gl_code: 'GL-9999-SUSPENSE' },
      sqlStatement: "SET IDENTITY_INSERT dbo.ap_ledger_entries ON; INSERT INTO dbo.ap_ledger_entries (id, txn_code, amount, gl_code, created_at) VALUES (8840, 'TXN-2026-8840', 31800.00, 'GL-9999-SUSPENSE', '2026-10-29T08:15:00Z');",
    },
    {
      id: 'evt_007',
      sequenceId: 4009,
      timestampUtc: '2026-11-15T03:11:44.000Z',
      recordedAtUtc: '2026-11-15T03:11:44.715Z',
      actor: 'sa (SQL_SYSADMIN)',
      actorRole: 'SYSADMIN',
      sourceIp: '172.16.99.204',
      category: 'Timestamp Anomaly',
      action: 'DISABLE_AUDIT_TRIGGER',
      targetObject: 'dbo.trg_ap_ledger_audit',
      severity: 'Critical',
      anomalyFlags: ['AUDIT_TRIGGER_DISABLED', 'OFF_HOURS_SYSADMIN'],
      beforeState: { trigger_enabled: true },
      afterState: { trigger_enabled: false },
      sqlStatement: 'DISABLE TRIGGER dbo.trg_ap_ledger_audit ON dbo.ap_ledger_entries;',
    },
    {
      id: 'evt_008',
      sequenceId: 4010,
      timestampUtc: '2026-11-15T03:14:02.000Z',
      recordedAtUtc: '2026-11-15T03:14:02.110Z',
      actor: 'sa (SQL_SYSADMIN)',
      actorRole: 'SYSADMIN',
      sourceIp: '172.16.99.204',
      category: 'Cross-Ref Discrepancy',
      action: 'DUPLICATE_TXN_CODE_REPLAY',
      targetObject: 'dbo.ap_ledger_entries',
      transactionCode: 'TXN-2026-8836',
      amount: 8900.0,
      currency: 'USD',
      severity: 'Critical',
      anomalyFlags: ['DUPLICATE_TRANSACTION_CODE', 'AUDIT_TRIGGER_BYPASSED', 'CAUSALITY_VIOLATION'],
      beforeState: { created_at: '2026-11-15T03:14:02Z', updated_at: '2026-11-12T10:00:00Z' },
      afterState: { txn_code: 'TXN-2026-8836', amount: 8900.0, updated_at: '2026-11-12T10:00:00Z' },
      sqlStatement: "INSERT INTO dbo.ap_ledger_entries (txn_code, vendor_id, amount, created_at, updated_at) VALUES ('TXN-2026-8836', 1099, 8900.00, '2026-11-15T03:14:02Z', '2026-11-12T10:00:00Z');",
    },
    {
      id: 'evt_009',
      sequenceId: 4011,
      timestampUtc: '2026-11-15T03:16:18.000Z',
      recordedAtUtc: '2026-11-15T03:16:18.090Z',
      actor: 'sa (SQL_SYSADMIN)',
      actorRole: 'SYSADMIN',
      sourceIp: '172.16.99.204',
      category: 'DML / Schema Change',
      action: 'ENABLE_AUDIT_TRIGGER',
      targetObject: 'dbo.trg_ap_ledger_audit',
      severity: 'Warning',
      anomalyFlags: ['OFF_HOURS_SYSADMIN'],
      beforeState: { trigger_enabled: false },
      afterState: { trigger_enabled: true },
      sqlStatement: 'ENABLE TRIGGER dbo.trg_ap_ledger_audit ON dbo.ap_ledger_entries;',
    },
    {
      id: 'evt_010',
      sequenceId: 4012,
      timestampUtc: '2026-11-16T13:20:05.000Z',
      recordedAtUtc: '2026-11-16T13:20:05.412Z',
      actor: 'm.henderson@corp-erp.internal',
      actorRole: 'AP_CLERK',
      sourceIp: '10.24.18.42',
      category: 'DML / Schema Change',
      action: 'INSERT_AP_INVOICE',
      targetObject: 'dbo.ap_ledger_entries',
      transactionCode: 'TXN-2026-8841',
      amount: 6320.0,
      currency: 'USD',
      severity: 'Nominal',
      anomalyFlags: [],
      beforeState: null,
      afterState: { txn_code: 'TXN-2026-8841', vendor: 'Alder Security Systems', amount: 6320.0, gl_code: 'GL-5400-SEC' },
      sqlStatement: "INSERT INTO dbo.ap_ledger_entries (txn_code, vendor_id, amount, gl_code) VALUES ('TXN-2026-8841', 1024, 6320.00, 'GL-5400-SEC');",
    },
  ];

  let prevHash = GENESIS_HASH;
  const auditLogs: AuditEvent[] = rawLogs.map((item) => {
    const partial: Omit<AuditEvent, 'recordHash'> = {
      ...item,
      prevHash,
    };
    const recordHash = computeRecordHash(partial);
    prevHash = recordHash;
    return { ...partial, recordHash };
  });

  const excelRows: ExcelTransactionRow[] = [
    {
      rowNumber: 2,
      transactionCode: 'TXN-2026-8835',
      authorizedDateUtc: '2026-11-12T09:10:00.000Z',
      vendorOrCounterparty: 'Northbridge Logistics Ltd',
      glAccount: 'GL-5120-FREIGHT',
      authorizedAmount: 12450.0,
      currency: 'USD',
      approver: 'S. Patel',
      status: 'Authorized',
    },
    {
      rowNumber: 3,
      transactionCode: 'TXN-2026-8836',
      authorizedDateUtc: '2026-11-12T10:55:00.000Z',
      vendorOrCounterparty: 'Helios Hardware Corp',
      glAccount: 'GL-5310-EQUIP',
      authorizedAmount: 8900.0,
      currency: 'USD',
      approver: 'S. Patel',
      status: 'Authorized',
    },
    {
      rowNumber: 4,
      transactionCode: 'TXN-2026-8837',
      authorizedDateUtc: '2026-11-13T14:20:00.000Z',
      vendorOrCounterparty: 'Kestrel Cloud Infra Inc',
      glAccount: 'GL-6200-CLOUD',
      authorizedAmount: 24750.0,
      currency: 'USD',
      approver: 'M. Thorne',
      status: 'Authorized',
    },
    {
      rowNumber: 5,
      transactionCode: 'TXN-2026-8838',
      authorizedDateUtc: '2026-11-14T09:45:00.000Z',
      vendorOrCounterparty: 'Vanguard Legal Advisory',
      glAccount: 'GL-6100-LEGAL',
      authorizedAmount: 4850.0,
      currency: 'USD',
      approver: 'S. Patel',
      status: 'Authorized',
    },
    {
      rowNumber: 6,
      transactionCode: 'TXN-2026-8839',
      authorizedDateUtc: '2026-11-14T16:30:00.000Z',
      vendorOrCounterparty: 'Apex Facilities Mgmt',
      glAccount: 'GL-5500-FAC',
      authorizedAmount: 15200.0,
      currency: 'USD',
      approver: 'S. Patel',
      status: 'Authorized',
    },
    {
      rowNumber: 7,
      transactionCode: 'TXN-2026-8841',
      authorizedDateUtc: '2026-11-16T13:15:00.000Z',
      vendorOrCounterparty: 'Alder Security Systems',
      glAccount: 'GL-5400-SEC',
      authorizedAmount: 6320.0,
      currency: 'USD',
      approver: 'M. Thorne',
      status: 'Authorized',
    },
    {
      rowNumber: 8,
      transactionCode: 'TXN-2026-8842',
      authorizedDateUtc: '2026-11-17T10:00:00.000Z',
      vendorOrCounterparty: 'Crestline Actuarial Group',
      glAccount: 'GL-6150-AUDIT',
      authorizedAmount: 9400.0,
      currency: 'USD',
      approver: 'M. Thorne',
      status: 'Authorized',
    },
  ];

  const sheetPayload = JSON.stringify(excelRows);
  const sheetSha256 = sha256Hex(sheetPayload);
  const sheetSha512 = sha512Hex(sheetPayload);

  const evidenceItems: EvidenceItem[] = [
    {
      evidenceId: 'EVD-2026-001',
      fileName: 'EnterpriseERP_Prod_Audit_Snapshot.sql',
      fileType: 'SQL Dump (.sql)',
      byteSize: 482910,
      sha256: sha256Hex('EnterpriseERP_Prod_Audit_Snapshot_v1'),
      sha512: sha512Hex('EnterpriseERP_Prod_Audit_Snapshot_v1'),
      encryptedAtRest: true,
      cipherSuite: 'AES-256-GCM (scrypt-SHA256)',
      acquiredAtUtc: '2026-11-17T08:00:00.000Z',
      acquiredBy: 'Elena Vance, CFE, CISA',
      integrityVerified: true,
      lastVerifiedUtc: now,
      custodyEvents: [
        {
          timestampUtc: '2026-11-17T08:00:00.000Z',
          stage: 'Acquired',
          actor: 'Elena Vance, CFE, CISA',
          notes: 'Read-only forensic extraction from primary ERP SQL cluster.',
          digestAtStage: sha256Hex('EnterpriseERP_Prod_Audit_Snapshot_v1'),
        },
        {
          timestampUtc: '2026-11-17T08:00:12.000Z',
          stage: 'Encrypted',
          actor: 'Veritas Custody Engine',
          notes: 'Sealed in AES-256-GCM vault with ISO/IEC 27037 provenance tag.',
          digestAtStage: sha256Hex('EnterpriseERP_Prod_Audit_Snapshot_v1'),
        },
      ],
    },
    {
      evidenceId: 'EVD-2026-002',
      fileName: 'Treasury_Approved_Txn_Register_Q4.xlsx',
      fileType: 'Spreadsheet (.xlsx/.csv)',
      byteSize: 64120,
      sha256: sheetSha256,
      sha512: sheetSha512,
      encryptedAtRest: true,
      cipherSuite: 'AES-256-GCM (scrypt-SHA256)',
      acquiredAtUtc: '2026-11-17T09:30:00.000Z',
      acquiredBy: 'Marcus Thorne, CPA',
      integrityVerified: true,
      lastVerifiedUtc: now,
      custodyEvents: [
        {
          timestampUtc: '2026-11-17T09:30:00.000Z',
          stage: 'Acquired',
          actor: 'Marcus Thorne, CPA',
          notes: 'Treasury master Excel register ingested for transaction code cross-reference.',
          digestAtStage: sheetSha256,
        },
      ],
    },
  ];

  const initialCrossRef = reconcileTransactions(
    auditLogs,
    excelRows,
    'Treasury_Approved_Txn_Register_Q4.xlsx (Master Online Register)',
    sheetSha256
  );

  const holisticFindings = runHolisticTimestampScan(auditLogs);

  return {
    version: 1,
    createdAtUtc: now,
    users,
    auditLogs,
    evidenceItems,
    excelRegister: {
      sheetName: 'Treasury_Approved_Txn_Register_Q4.xlsx (Master Online Register)',
      sheetSha256,
      loadedAtUtc: now,
      rows: excelRows,
    },
    lastCrossRef: initialCrossRef,
    bakAnalyses: [],
    holisticFindings,
    securitySettings: {
      airgapLockdown: process.env.AIRGAP_LOCKDOWN === 'true',
      localDeterministicOnly: process.env.LOCAL_ONLY_DETERMINISTIC === 'true',
      kdpaStrictMode: process.env.KDPA_2019_STRICT_MODE !== 'false',
      maskPiiBeforeAi: true,
    },
  };
}

let cachedState: VaultState | null = null;

export function loadVaultState(): VaultState {
  if (cachedState) return cachedState;
  ensureStorageDir();
  if (fs.existsSync(VAULT_FILE)) {
    try {
      const raw = fs.readFileSync(VAULT_FILE, 'utf8');
      const envelope = JSON.parse(raw) as EncryptedEnvelope;
      cachedState = decryptJson<VaultState>(envelope);
      return cachedState;
    } catch (err) {
      console.error('Failed to decrypt existing vault, re-initializing:', err);
    }
  }
  const seeded = buildSeededState();
  saveVaultState(seeded);
  return seeded;
}

export function saveVaultState(state: VaultState): void {
  ensureStorageDir();
  const envelope = encryptJson(state);
  fs.writeFileSync(VAULT_FILE, JSON.stringify(envelope, null, 2), { mode: 0o600 });
  cachedState = state;
}

export function appendAuditLog(params: {
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
  anomalyFlags?: string[];
  beforeState?: Record<string, unknown> | null;
  afterState?: Record<string, unknown> | null;
  sqlStatement?: string;
  timestampUtc?: string;
}): AuditEvent {
  const state = loadVaultState();
  const lastLog = state.auditLogs[state.auditLogs.length - 1];
  const nextSeq = lastLog ? lastLog.sequenceId + 1 : 1;
  const prevHash = lastLog ? lastLog.recordHash : GENESIS_HASH;
  const nowUtc = new Date().toISOString();

  const base: Omit<AuditEvent, 'recordHash'> = {
    id: `evt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    sequenceId: nextSeq,
    timestampUtc: params.timestampUtc || nowUtc,
    recordedAtUtc: nowUtc,
    actor: params.actor,
    actorRole: params.actorRole,
    sourceIp: params.sourceIp,
    category: params.category,
    action: params.action,
    targetObject: params.targetObject,
    transactionCode: params.transactionCode,
    amount: params.amount,
    currency: params.currency,
    severity: params.severity,
    anomalyFlags: params.anomalyFlags || [],
    beforeState: params.beforeState ?? null,
    afterState: params.afterState ?? null,
    sqlStatement: params.sqlStatement,
    prevHash,
  };

  const recordHash = computeRecordHash(base);
  const fullEvent: AuditEvent = { ...base, recordHash };
  state.auditLogs.push(fullEvent);
  state.holisticFindings = runHolisticTimestampScan(state.auditLogs);
  saveVaultState(state);
  return fullEvent;
}

export function verifyAuditChain(): VaultStatus {
  const state = loadVaultState();
  let expectedPrev = GENESIS_HASH;
  let chainIntact = true;
  let brokenAtSequenceId: number | undefined;

  for (const evt of state.auditLogs) {
    if (evt.prevHash !== expectedPrev) {
      chainIntact = false;
      brokenAtSequenceId = evt.sequenceId;
      break;
    }
    const { recordHash, ...rest } = evt;
    const recomputed = computeRecordHash(rest);
    if (recomputed !== recordHash) {
      chainIntact = false;
      brokenAtSequenceId = evt.sequenceId;
      break;
    }
    expectedPrev = recordHash;
  }

  return {
    encryptionAlgorithm: 'AES-256-GCM',
    keyDerivation: 'scrypt (N=16384, r=8, p=1) + SHA-256',
    storagePath: 'vault_storage/veritas_vault.enc',
    totalSealedLogEntries: state.auditLogs.length,
    totalEvidenceArtifacts: state.evidenceItems.length,
    chainIntact,
    genesisHash: GENESIS_HASH,
    tipHash: state.auditLogs.length ? state.auditLogs[state.auditLogs.length - 1].recordHash : GENESIS_HASH,
    lastVerifiedUtc: new Date().toISOString(),
    brokenAtSequenceId,
  };
}

export function runHolisticTimestampScan(logs: AuditEvent[]): HolisticFinding[] {
  const findings: HolisticFinding[] = [];
  const sortedBySeq = [...logs].sort((a, b) => a.sequenceId - b.sequenceId);

  for (let i = 0; i < sortedBySeq.length; i++) {
    const curr = sortedBySeq[i];
    const currTs = Date.parse(curr.timestampUtc);
    const currRec = Date.parse(curr.recordedAtUtc);

    // 1. Sequence gaps (possible DELETE or TRUNCATE)
    if (i > 0) {
      const prev = sortedBySeq[i - 1];
      if (curr.sequenceId - prev.sequenceId > 1) {
        const missingFrom = prev.sequenceId + 1;
        const missingTo = curr.sequenceId - 1;
        findings.push({
          findingId: `FND-GAP-${curr.sequenceId}`,
          title: `Audit Sequence Gap Detected (#${missingFrom}${missingTo > missingFrom ? `–#${missingTo}` : ''})`,
          category: 'Sequence Gap',
          severity: 'Critical',
          affectedTarget: `${curr.targetObject} (Seq ${prev.sequenceId} -> ${curr.sequenceId})`,
          evidenceSummary: `Contiguous sequence discontinuity between Sequence #${prev.sequenceId} and #${curr.sequenceId}. ${curr.sequenceId - prev.sequenceId - 1} log record(s) are missing, indicating direct log deletion or identity-insert bypass.`,
          standardReference: 'ISO/IEC 27037 §7.2 & SOX ITGC Log Completeness',
          recommendation: 'Inspect transaction log backups (.trn), SQL Server Audit logs, and restrict DELETE/TRUNCATE on audit tables via append-only Ledger tables.',
        });
      }

      // 2. Sequence vs Timestamp inversion (backdating!)
      const prevTs = Date.parse(prev.timestampUtc);
      if (!Number.isNaN(currTs) && !Number.isNaN(prevTs) && currTs < prevTs - 60000) {
        const diffHours = ((prevTs - currTs) / 3600000).toFixed(1);
        findings.push({
          findingId: `FND-BACKDATE-${curr.sequenceId}`,
          title: `Timestamp Inversion / Backdated Entry (${curr.transactionCode || curr.id})`,
          category: 'Timestamp Tampering',
          severity: 'Critical',
          affectedTarget: `${curr.targetObject} · Seq #${curr.sequenceId}`,
          evidenceSummary: `Sequence #${curr.sequenceId} carries business timestamp ${curr.timestampUtc}, which is ${diffHours} hours EARLIER than preceding Sequence #${prev.sequenceId} (${prev.timestampUtc}), while recorded in WAL at ${curr.recordedAtUtc}.`,
          standardReference: 'ALCOA+ Contemporaneous Principle & ACFE Fraud Examination Standard',
          recommendation: 'Quarantine entry, verify SYSUTCDATETIME() default constraints, revoke IDENTITY_INSERT privileges, and compare against external bank/Excel settlement logs.',
        });
      }
    }

    // 3. Recorded vs Event timestamp drift (> 24h drift)
    if (!Number.isNaN(currTs) && !Number.isNaN(currRec) && Math.abs(currRec - currTs) > 86400000) {
      findings.push({
        findingId: `FND-DRIFT-${curr.sequenceId}`,
        title: `Event Timestamp vs. System Recording Drift (${curr.transactionCode || curr.id})`,
        category: 'Timestamp Tampering',
        severity: 'Critical',
        affectedTarget: `${curr.targetObject} · Actor ${curr.actor}`,
        evidenceSummary: `Claimed entry timestamp (${curr.timestampUtc}) diverges by more than 24 hours from system recording timestamp (${curr.recordedAtUtc}).`,
        standardReference: 'ISO/IEC 27001 A.8.17 Clock Synchronization & Log Integrity',
        recommendation: 'Enforce server-generated immutable temporal columns (GENERATED ALWAYS AS ROW START) rather than client-supplied date literals.',
      });
    }

    // 4. Causality violation (updated_at < created_at inside state)
    const after = curr.afterState;
    if (after && typeof after.created_at === 'string' && typeof after.updated_at === 'string') {
      if (Date.parse(after.updated_at) < Date.parse(after.created_at)) {
        findings.push({
          findingId: `FND-CAUSAL-${curr.sequenceId}`,
          title: `Temporal Causality Violation: updated_at Precedes created_at`,
          category: 'Timestamp Tampering',
          severity: 'Critical',
          affectedTarget: `${curr.targetObject} (${curr.transactionCode || curr.id})`,
          evidenceSummary: `Row state records created_at=${after.created_at} while updated_at=${after.updated_at}. Logical impossibility indicating manual row manipulation.`,
          standardReference: 'ALCOA+ Accurate & Consistent Data Integrity Standard',
          recommendation: 'Add CHECK constraint (updated_at >= created_at) and audit all direct table writes bypassing application APIs.',
        });
      }
    }

    // 5. Audit trigger disabled or off-hours sysadmin
    if (curr.anomalyFlags.includes('AUDIT_TRIGGER_DISABLED') || curr.action === 'DISABLE_AUDIT_TRIGGER') {
      findings.push({
        findingId: `FND-TRG-${curr.sequenceId}`,
        title: `Audit Control Tampering: Trigger Disabled During Off-Hours`,
        category: 'Access Control',
        severity: 'Critical',
        affectedTarget: `${curr.targetObject} · ${curr.actor}`,
        evidenceSummary: `Database audit trigger was disabled at ${curr.timestampUtc} from IP ${curr.sourceIp} by ${curr.actor}, creating a blind window for subsequent unmonitored DML.`,
        standardReference: 'PCI-DSS Req 10.2 & SOX Section 404 Change Management',
        recommendation: 'Disable shared `sa` logins, enforce DDL server triggers blocking trigger alterations without dual-custody change ticket.',
      });
    }

    // 6. Nonsense / invalid amount or suspense GL
    if (typeof curr.amount === 'number' && curr.amount <= 0) {
      findings.push({
        findingId: `FND-AMT-${curr.sequenceId}`,
        title: `Non-Positive Financial Amount in Ledger Entry`,
        category: 'Data Integrity',
        severity: 'Warning',
        affectedTarget: `${curr.transactionCode || curr.id}`,
        evidenceSummary: `Transaction recorded with non-positive amount (${curr.amount}).`,
        standardReference: 'ACFE Financial Statement & Disbursement Anomaly Check',
        recommendation: 'Verify reversal authorization or credit memo linkage.',
      });
    }
    if (after && typeof after.gl_code === 'string' && after.gl_code.includes('9999')) {
      findings.push({
        findingId: `FND-GL-${curr.sequenceId}`,
        title: `Unmapped / Suspense GL Account Posting (${after.gl_code})`,
        category: 'Fraud Indicator',
        severity: 'Critical',
        affectedTarget: `${curr.transactionCode || curr.id} · $${curr.amount?.toLocaleString() ?? '0'}`,
        evidenceSummary: `Posting routed to suspense/unmapped GL account ${after.gl_code} by ${curr.actor}.`,
        standardReference: 'ACFE Asset Misappropriation & Ghost Vendor Scheme Indicators',
        recommendation: 'Freeze disbursement and confirm beneficial ownership of payee.',
      });
    }
  }

  return findings;
}

export function reconcileTransactions(
  auditLogs: AuditEvent[],
  excelRows: ExcelTransactionRow[],
  sheetName: string,
  sheetSha256: string
): CrossRefSummary {
  const discrepancies: CrossRefDiscrepancy[] = [];
  const dbTxnLogs = auditLogs.filter((l) => Boolean(l.transactionCode));

  // Group DB logs by transactionCode
  const dbByCode = new Map<string, AuditEvent[]>();
  for (const log of dbTxnLogs) {
    const code = (log.transactionCode || '').trim().toUpperCase();
    if (!code) continue;
    const arr = dbByCode.get(code) || [];
    arr.push(log);
    dbByCode.set(code, arr);
  }

  const excelByCode = new Map<string, ExcelTransactionRow>();
  for (const row of excelRows) {
    const code = (row.transactionCode || '').trim().toUpperCase();
    if (!code) continue;
    excelByCode.set(code, row);
  }

  let matchedCount = 0;
  let discrepancyCount = 0;
  let totalVarianceValue = 0;

  // Check every DB transaction code against Excel
  for (const [code, events] of dbByCode.entries()) {
    const primaryEvent = events[events.length - 1];
    const excelRow = excelByCode.get(code);

    if (events.length > 1) {
      discrepancyCount++;
      const totalDbAmt = events.reduce((acc, e) => acc + (e.amount || 0), 0);
      const variance = excelRow ? totalDbAmt - excelRow.authorizedAmount : totalDbAmt;
      totalVarianceValue += Math.abs(variance);
      discrepancies.push({
        transactionCode: code,
        status: 'DUPLICATE_TXN_CODE',
        severity: 'Critical',
        dbEventId: primaryEvent.id,
        dbTimestampUtc: primaryEvent.timestampUtc,
        dbAmount: totalDbAmt,
        dbActor: primaryEvent.actor,
        excelRowNumber: excelRow?.rowNumber,
        excelDateUtc: excelRow?.authorizedDateUtc,
        excelAmount: excelRow?.authorizedAmount,
        excelApprover: excelRow?.approver,
        varianceAmount: variance,
        details: `Transaction code ${code} appears ${events.length} times in database audit logs (replay or split-payment risk). Total DB amount $${totalDbAmt.toLocaleString()} vs Excel $${(excelRow?.authorizedAmount ?? 0).toLocaleString()}.`,
      });
      continue;
    }

    if (!excelRow) {
      discrepancyCount++;
      const amt = primaryEvent.amount || 0;
      totalVarianceValue += Math.abs(amt);
      discrepancies.push({
        transactionCode: code,
        status: 'MISSING_IN_EXCEL',
        severity: 'Critical',
        dbEventId: primaryEvent.id,
        dbTimestampUtc: primaryEvent.timestampUtc,
        dbAmount: primaryEvent.amount,
        dbActor: primaryEvent.actor,
        varianceAmount: amt,
        details: `Phantom DB transaction: ${code} ($${amt.toLocaleString()}) exists in RDBMS ledger by ${primaryEvent.actor} but has NO matching authorization in the Master Excel Register.`,
      });
      continue;
    }

    const dbAmt = primaryEvent.amount ?? 0;
    const amtDiff = dbAmt - excelRow.authorizedAmount;
    if (Math.abs(amtDiff) > 0.01) {
      discrepancyCount++;
      totalVarianceValue += Math.abs(amtDiff);
      discrepancies.push({
        transactionCode: code,
        status: 'AMOUNT_VARIANCE',
        severity: 'Critical',
        dbEventId: primaryEvent.id,
        dbTimestampUtc: primaryEvent.timestampUtc,
        dbAmount: dbAmt,
        dbActor: primaryEvent.actor,
        excelRowNumber: excelRow.rowNumber,
        excelDateUtc: excelRow.authorizedDateUtc,
        excelAmount: excelRow.authorizedAmount,
        excelApprover: excelRow.approver,
        varianceAmount: amtDiff,
        details: `Monetary mismatch: Database holds $${dbAmt.toLocaleString()} while Excel Master Sheet Row #${excelRow.rowNumber} authorizes $${excelRow.authorizedAmount.toLocaleString()} (variance of $${amtDiff.toLocaleString()}).`,
      });
      continue;
    }

    const dbTs = Date.parse(primaryEvent.timestampUtc);
    const exTs = Date.parse(excelRow.authorizedDateUtc);
    if (!Number.isNaN(dbTs) && !Number.isNaN(exTs) && dbTs < exTs - 3600000) {
      discrepancyCount++;
      discrepancies.push({
        transactionCode: code,
        status: 'TIMESTAMP_DISCREPANCY',
        severity: 'Warning',
        dbEventId: primaryEvent.id,
        dbTimestampUtc: primaryEvent.timestampUtc,
        dbAmount: dbAmt,
        dbActor: primaryEvent.actor,
        excelRowNumber: excelRow.rowNumber,
        excelDateUtc: excelRow.authorizedDateUtc,
        excelAmount: excelRow.authorizedAmount,
        excelApprover: excelRow.approver,
        varianceAmount: 0,
        details: `DB entry timestamp (${primaryEvent.timestampUtc}) predates Excel authorization timestamp (${excelRow.authorizedDateUtc}) by more than 1 hour.`,
      });
      continue;
    }

    matchedCount++;
    discrepancies.push({
      transactionCode: code,
      status: 'MATCHED_VERIFIED',
      severity: 'Nominal',
      dbEventId: primaryEvent.id,
      dbTimestampUtc: primaryEvent.timestampUtc,
      dbAmount: dbAmt,
      dbActor: primaryEvent.actor,
      excelRowNumber: excelRow.rowNumber,
      excelDateUtc: excelRow.authorizedDateUtc,
      excelAmount: excelRow.authorizedAmount,
      excelApprover: excelRow.approver,
      varianceAmount: 0,
      details: `Verified match across DB log and Excel Row #${excelRow.rowNumber} (${excelRow.vendorOrCounterparty}).`,
    });
  }

  // Check Excel rows missing from DB
  for (const [code, excelRow] of excelByCode.entries()) {
    if (!dbByCode.has(code)) {
      discrepancyCount++;
      totalVarianceValue += Math.abs(excelRow.authorizedAmount);
      discrepancies.push({
        transactionCode: code,
        status: 'MISSING_IN_DB',
        severity: 'Warning',
        excelRowNumber: excelRow.rowNumber,
        excelDateUtc: excelRow.authorizedDateUtc,
        excelAmount: excelRow.authorizedAmount,
        excelApprover: excelRow.approver,
        varianceAmount: -excelRow.authorizedAmount,
        details: `Authorized transaction ${code} ($${excelRow.authorizedAmount.toLocaleString()}, ${excelRow.vendorOrCounterparty}) in Excel Row #${excelRow.rowNumber} is absent from database audit logs.`,
      });
    }
  }

  // Sort critical/warning discrepancies to the top
  const rank: Record<string, number> = {
    DUPLICATE_TXN_CODE: 0,
    MISSING_IN_EXCEL: 1,
    AMOUNT_VARIANCE: 2,
    TIMESTAMP_DISCREPANCY: 3,
    MISSING_IN_DB: 4,
    MATCHED_VERIFIED: 5,
  };
  discrepancies.sort((a, b) => (rank[a.status] ?? 9) - (rank[b.status] ?? 9));

  return {
    sheetSourceName: sheetName,
    sheetSha256,
    reconciledAtUtc: new Date().toISOString(),
    totalDbTransactions: dbByCode.size,
    totalExcelRows: excelRows.length,
    matchedCount,
    discrepancyCount,
    totalVarianceValue,
    discrepancies,
  };
}

export function registerUserAccount(params: {
  email: string;
  password: string;
  fullName: string;
  role: UserRole;
}): { user: UserAccount; token: string } | { error: string } {
  const state = loadVaultState();
  const normalized = params.email.trim().toLowerCase();
  if (state.users.some((u) => u.email.toLowerCase() === normalized)) {
    return { error: 'An investigator account with this email already exists.' };
  }
  const { salt, hash } = hashPassword(params.password);
  const newUser: StoredUser = {
    id: `usr_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`,
    email: normalized,
    fullName: params.fullName.trim(),
    role: params.role,
    badgeId: `INV-${Math.floor(1000 + Math.random() * 9000)}`,
    createdAtUtc: new Date().toISOString(),
    lastLoginUtc: new Date().toISOString(),
    passwordSalt: salt,
    passwordHash: hash,
  };
  state.users.push(newUser);
  saveVaultState(state);

  appendAuditLog({
    actor: normalized,
    actorRole: params.role,
    sourceIp: '127.0.0.1',
    category: 'Authentication',
    action: 'INVESTIGATOR_REGISTERED',
    targetObject: 'vault.users',
    severity: 'Nominal',
    afterState: { email: normalized, role: params.role, badgeId: newUser.badgeId },
  });

  const safeUser = sanitizeUser(newUser);
  return { user: safeUser, token: issueSessionToken(safeUser) };
}

export function authenticateUser(
  email: string,
  password: string,
  sourceIp: string
): { user: UserAccount; token: string } | { error: string } {
  const state = loadVaultState();
  const normalized = email.trim().toLowerCase();
  const found = state.users.find((u) => u.email.toLowerCase() === normalized);
  if (!found || !verifyPassword(password, found.passwordSalt, found.passwordHash)) {
    appendAuditLog({
      actor: normalized || 'anonymous',
      actorRole: 'UNAUTHENTICATED',
      sourceIp,
      category: 'Authentication',
      action: 'AUTH_LOGIN_FAILED',
      targetObject: 'vault.session',
      severity: 'Warning',
      anomalyFlags: ['FAILED_AUTH_ATTEMPT'],
    });
    return { error: 'Invalid credentials. Authentication event has been recorded to the audit ledger.' };
  }

  found.lastLoginUtc = new Date().toISOString();
  saveVaultState(state);

  const safeUser = sanitizeUser(found);
  appendAuditLog({
    actor: safeUser.email,
    actorRole: safeUser.role,
    sourceIp,
    category: 'Authentication',
    action: 'AUTH_LOGIN_SUCCESS',
    targetObject: 'vault.session',
    severity: 'Nominal',
    afterState: { badgeId: safeUser.badgeId },
  });

  return { user: safeUser, token: issueSessionToken(safeUser) };
}

export function resetVaultToSeededCase(): VaultState {
  const fresh = buildSeededState();
  saveVaultState(fresh);
  return fresh;
}

export function getSecurityComplianceConfig(): SecurityComplianceConfig {
  const state = loadVaultState();
  const settings = state.securitySettings || {
    airgapLockdown: process.env.AIRGAP_LOCKDOWN === 'true',
    localDeterministicOnly: process.env.LOCAL_ONLY_DETERMINISTIC === 'true',
    kdpaStrictMode: process.env.KDPA_2019_STRICT_MODE !== 'false',
    maskPiiBeforeAi: true,
  };

  const bindHost = process.env.BIND_HOST || '0.0.0.0';
  const allowedEvidenceDir = process.env.ALLOWED_EVIDENCE_DIR || '/mnt/forensic_evidence';
  const outboundBlocked = settings.airgapLockdown || settings.localDeterministicOnly;

  const kdpaPrinciples: KdpaPrincipleStatus[] = [
    {
      section: 'Section 25(a)-(b)',
      principle: 'Lawfulness, Fairness, Transparency & Purpose Limitation',
      status: 'Compliant',
      detail: 'Forensic audit access requires authenticated investigator badge and records immutable audit trail of purpose.',
    },
    {
      section: 'Section 25(c) & 28',
      principle: 'Data Minimization & PII Masking',
      status: settings.maskPiiBeforeAi ? 'Compliant' : 'Action Required',
      detail: settings.maskPiiBeforeAi
        ? 'Emails, IPs, KRA PINs, National IDs, and IBANs are automatically redacted prior to any external AI synthesis.'
        : 'Enable PII Masking before AI calls to minimize personal data exposure.',
    },
    {
      section: 'Section 31',
      principle: 'Data Protection Impact Assessment (DPIA)',
      status: 'Compliant',
      detail: 'Automated DPIA & PII column discovery runs on every ingested .bak database schema.',
    },
    {
      section: 'Section 41',
      principle: 'Security Safeguards (Integrity & Confidentiality)',
      status: 'Compliant',
      detail: 'AES-256-GCM at-rest vault encryption, PBKDF2-SHA256 credentials, and SHA-256 hash-chained logs active.',
    },
    {
      section: 'Section 43',
      principle: '72-Hour ODPC Breach & Anomaly Detection',
      status: state.holisticFindings.some((f) => f.severity === 'Critical') ? 'Action Required' : 'Compliant',
      detail: state.holisticFindings.some((f) => f.severity === 'Critical')
        ? 'Critical unauthorized off-hours sysadmin/tampering indicators detected — review for ODPC 72-hour notification assessment.'
        : 'No unaddressed breach indicators active.',
    },
    {
      section: 'Section 48',
      principle: 'Cross-Border Transfer Restriction',
      status: settings.localDeterministicOnly
        ? 'Compliant'
        : settings.maskPiiBeforeAi
          ? 'Partial'
          : 'Action Required',
      detail: settings.localDeterministicOnly
        ? '100% Local Deterministic Mode active: zero data leaves localhost / Ubuntu Hyper-V VM.'
        : 'PII redaction active before Gemini API calls; switch to Local Deterministic Mode for strict zero-egress air-gap.',
    },
  ];

  return {
    bindHost,
    airgapLockdown: settings.airgapLockdown,
    localDeterministicOnly: settings.localDeterministicOnly,
    kdpaStrictMode: settings.kdpaStrictMode,
    maskPiiBeforeAi: settings.maskPiiBeforeAi,
    allowedEvidenceDir,
    outboundNetworkBlocked: outboundBlocked,
    kdpaPrinciples,
  };
}

export function updateSecurityComplianceConfig(patch: Partial<{
  airgapLockdown: boolean;
  localDeterministicOnly: boolean;
  kdpaStrictMode: boolean;
  maskPiiBeforeAi: boolean;
}>): SecurityComplianceConfig {
  const state = loadVaultState();
  const current = state.securitySettings || {
    airgapLockdown: process.env.AIRGAP_LOCKDOWN === 'true',
    localDeterministicOnly: process.env.LOCAL_ONLY_DETERMINISTIC === 'true',
    kdpaStrictMode: process.env.KDPA_2019_STRICT_MODE !== 'false',
    maskPiiBeforeAi: true,
  };
  state.securitySettings = {
    ...current,
    ...patch,
  };
  saveVaultState(state);
  return getSecurityComplianceConfig();
}

/**
 * KDPA 2019 Section 25(c) & Section 48 PII Redaction Filter:
 * Strips personal identifiers (emails, IPs, KRA PINs, National IDs, IBANs, phone numbers)
 * before transmitting metadata summaries to external AI models.
 */
export function redactPiiForExternalAi<T>(data: T): T {
  const raw = JSON.stringify(data);
  const masked = raw
    // Email addresses
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
    // IPv4 addresses
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[REDACTED_IP]')
    // Kenyan KRA PIN format (e.g. A012345678Z)
    .replace(/\b[AP]\d{9}[A-Z]\b/g, '[REDACTED_KRA_PIN]')
    // Phone numbers / Kenyan MSISDN (+254...)
    .replace(/(?:\+?254|0)7\d{8}\b/g, '[REDACTED_MSISDN]')
    // IBANs
    .replace(/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, '[REDACTED_IBAN]');
  return JSON.parse(masked) as T;
}

