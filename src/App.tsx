import React, { useCallback, useEffect, useState } from 'react';
import {
  Database,
  FileSpreadsheet,
  FileText,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  RotateCcw,
  ScrollText,
  Search,
  ShieldCheck,
  X,
} from 'lucide-react';
import { AuditTrailExplorer } from './components/AuditTrailExplorer';
import { BakAnalyzerView } from './components/BakAnalyzerView';
import { ChainOfCustodyView } from './components/ChainOfCustodyView';
import { DeploymentSecurityView } from './components/DeploymentSecurityView';
import { ExcelCrossRefView } from './components/ExcelCrossRefView';
import { ForensicEnquiryView } from './components/ForensicEnquiryView';
import { LoginView } from './components/LoginView';
import { OverviewDashboard, type NavSection } from './components/OverviewDashboard';
import type {
  AuditEvent,
  BakAnalysisResult,
  ComprehensiveReport,
  CrossRefSummary,
  EvidenceItem,
  ExcelTransactionRow,
  HolisticFinding,
  SecurityComplianceConfig,
  UserAccount,
  VaultStatus,
} from './types/forensic';
import {
  exportAuditLogsToCsv,
  exportComprehensiveCompliancePdf,
  exportCrossRefToCsv,
} from './utils/exportReports';

const SESSION_KEY = 'veritas_session_token';

const NAV_ITEMS: { id: NavSection; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'overview', label: 'Audit Overview', icon: LayoutDashboard },
  { id: 'audit-trail', label: 'Audit Trail Logs', icon: ScrollText },
  { id: 'bak-analyzer', label: 'RDBMS .bak Assessment', icon: Database },
  { id: 'excel-crossref', label: 'Excel Cross-Reference', icon: FileSpreadsheet },
  { id: 'chain-of-custody', label: 'Chain of Custody', icon: Lock },
  { id: 'forensic-enquiry', label: 'Forensic AI Enquiry', icon: Search },
  { id: 'deployment-security', label: 'KDPA 2019 & Hyper-V', icon: ShieldCheck },
];

export default function App() {
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem(SESSION_KEY));
  const [user, setUser] = useState<UserAccount | null>(null);
  const [authChecking, setAuthChecking] = useState(Boolean(sessionStorage.getItem(SESSION_KEY)));
  const [activeSection, setActiveSection] = useState<NavSection>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);
  const [holisticFindings, setHolisticFindings] = useState<HolisticFinding[]>([]);
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>([]);
  const [excelRegister, setExcelRegister] = useState<{
    sheetName: string;
    sheetSha256: string;
    loadedAtUtc: string;
    rows: ExcelTransactionRow[];
  }>({
    sheetName: '',
    sheetSha256: '',
    loadedAtUtc: '',
    rows: [],
  });
  const [lastCrossRef, setLastCrossRef] = useState<CrossRefSummary | null>(null);
  const [bakAnalyses, setBakAnalyses] = useState<BakAnalysisResult[]>([]);
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null);
  const [securityConfig, setSecurityConfig] = useState<SecurityComplianceConfig | null>(null);
  const [activeReport, setActiveReport] = useState<ComprehensiveReport | null>(null);

  const [loadingState, setLoadingState] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [verifying, setVerifying] = useState(false);

  const loadDashboardData = useCallback(async (authToken: string) => {
    setLoadingState(true);
    try {
      const res = await fetch('/api/dashboard/state', {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (res.status === 401) {
        sessionStorage.removeItem(SESSION_KEY);
        setToken(null);
        setUser(null);
        return;
      }
      const data = await res.json();
      setAuditLogs(data.auditLogs || []);
      setHolisticFindings(data.holisticFindings || []);
      setEvidenceItems(data.evidenceItems || []);
      if (data.excelRegister) setExcelRegister(data.excelRegister);
      setLastCrossRef(data.lastCrossRef || null);
      setBakAnalyses(data.bakAnalyses || []);
      setVaultStatus(data.vaultStatus || null);
      setSecurityConfig(data.securityConfig || null);
    } finally {
      setLoadingState(false);
    }
  }, []);

  useEffect(() => {
    if (!token) {
      setAuthChecking(false);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/api/auth/me', {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) {
          sessionStorage.removeItem(SESSION_KEY);
          if (!cancelled) {
            setToken(null);
            setUser(null);
          }
          return;
        }
        const data = await res.json();
        if (!cancelled) {
          setUser(data.user);
          await loadDashboardData(token);
        }
      } finally {
        if (!cancelled) setAuthChecking(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token, loadDashboardData]);

  const handleAuthenticated = (authedUser: UserAccount, newToken: string) => {
    sessionStorage.setItem(SESSION_KEY, newToken);
    setToken(newToken);
    setUser(authedUser);
  };

  const handleLogout = async () => {
    if (token) {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => undefined);
    }
    sessionStorage.removeItem(SESSION_KEY);
    setToken(null);
    setUser(null);
  };

  const handleRunHolisticScan = async () => {
    if (!token) return;
    setScanning(true);
    try {
      const res = await fetch('/api/audit/holistic-scan', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) {
        setHolisticFindings(data.holisticFindings || []);
        if (data.auditLogs) setAuditLogs(data.auditLogs);
      }
    } finally {
      setScanning(false);
    }
  };

  const handleVerifyChain = async () => {
    if (!token) return;
    setVerifying(true);
    try {
      const res = await fetch('/api/audit/verify', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) {
        setVaultStatus(data.vaultStatus);
        await loadDashboardData(token);
      }
    } finally {
      setVerifying(false);
    }
  };

  const logComplianceExport = async (format: 'PDF' | 'CSV', scope: string, recordCount: number) => {
    if (!token) return;
    const res = await fetch('/api/audit/log-export', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ format, scope, recordCount }),
    });
    const data = await res.json().catch(() => null);
    if (res.ok && data?.auditLogs) {
      setAuditLogs(data.auditLogs);
    }
  };

  const handleExportPdf = (reportOverride?: ComprehensiveReport | null) => {
    exportComprehensiveCompliancePdf({
      report: reportOverride ?? activeReport,
      auditorName: user ? `${user.fullName} (${user.badgeId})` : 'Forensic Auditor',
      vaultStatus,
      holisticFindings,
      crossRef: lastCrossRef,
      bakAnalyses,
      evidenceItems,
      auditLogs,
    });
    logComplianceExport('PDF', 'Full Forensic & Architectural Report', auditLogs.length);
  };

  const handleExportAuditCsv = (filteredLogs: AuditEvent[]) => {
    exportAuditLogsToCsv(filteredLogs);
    logComplianceExport('CSV', 'Audit Trail Export', filteredLogs.length);
  };

  const handleExportCrossRefCsv = () => {
    if (!lastCrossRef) return;
    exportCrossRefToCsv(lastCrossRef);
    logComplianceExport('CSV', 'Excel Cross-Reference Reconciliation', lastCrossRef.discrepancies.length);
  };

  const handleResetBaseline = async () => {
    if (!token) return;
    setLoadingState(true);
    try {
      const res = await fetch('/api/vault/reset-demo', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) {
        setAuditLogs(data.auditLogs || []);
        setHolisticFindings(data.holisticFindings || []);
        setEvidenceItems(data.evidenceItems || []);
        if (data.excelRegister) setExcelRegister(data.excelRegister);
        setLastCrossRef(data.lastCrossRef || null);
        setBakAnalyses(data.bakAnalyses || []);
        setVaultStatus(data.vaultStatus || null);
        setActiveReport(null);
      }
    } finally {
      setLoadingState(false);
    }
  };

  if (authChecking) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center text-sm text-slate-600">
        Verifying encrypted vault session...
      </div>
    );
  }

  if (!token || !user) {
    return <LoginView onAuthenticated={handleAuthenticated} />;
  }

  const currentNavItem = NAV_ITEMS.find((n) => n.id === activeSection) || NAV_ITEMS[0];

  return (
    <div className="min-h-screen bg-slate-50 flex">
      {/* Desktop Sidebar (256px) */}
      <aside className="hidden lg:flex lg:w-64 lg:flex-col lg:fixed lg:inset-y-0 bg-slate-900 text-slate-200 border-r border-slate-800">
        <div className="h-16 px-6 flex items-center gap-2.5 border-b border-slate-800">
          <ShieldCheck className="w-5 h-5 text-blue-400 shrink-0" />
          <span className="font-semibold text-base tracking-tight text-white whitespace-nowrap">
            Veritas Ledger
          </span>
        </div>

        <nav className="flex-1 px-3 py-5 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveSection(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-blue-700 text-white'
                    : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800 space-y-3">
          <div className="text-xs">
            <div className="font-medium text-white truncate">{user.fullName}</div>
            <div className="text-[11px] text-slate-400 truncate">
              {user.role} · {user.badgeId}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleResetBaseline}
              title="Reset case baseline"
              className="flex-1 py-1.5 px-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium rounded flex items-center justify-center gap-1.5 whitespace-nowrap transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset Case</span>
            </button>
            <button
              type="button"
              onClick={handleLogout}
              className="flex-1 py-1.5 px-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium rounded flex items-center justify-center gap-1.5 whitespace-nowrap transition-colors"
            >
              <LogOut className="w-3 h-3" />
              <span>Sign Out</span>
            </button>
          </div>
        </div>
      </aside>

      {/* Mobile Navigation Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-slate-900/60"
            onClick={() => setMobileMenuOpen(false)}
          />
          <aside className="relative w-64 max-w-full bg-slate-900 text-slate-200 flex flex-col h-full z-10">
            <div className="h-14 px-5 flex items-center justify-between border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-blue-400" />
                <span className="font-semibold text-sm text-white">Veritas Ledger</span>
              </div>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="p-1 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <nav className="flex-1 p-3 space-y-1">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const active = activeSection === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveSection(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 text-xs font-medium rounded-md ${
                      active ? 'bg-blue-700 text-white' : 'text-slate-300 hover:bg-slate-800'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
            <div className="p-4 border-t border-slate-800">
              <button
                type="button"
                onClick={handleLogout}
                className="w-full py-2 px-3 bg-slate-800 text-slate-200 text-xs font-medium rounded flex items-center justify-center gap-2"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign Out</span>
              </button>
            </div>
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0">
        {/* Clean Top Bar (Breadcrumb + Primary Compliance Export CTA) */}
        <header className="h-16 bg-white border-b border-slate-200 px-4 sm:px-8 flex items-center justify-between gap-4 sticky top-0 z-20">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 -ml-2 text-slate-600 hover:text-slate-900"
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2 text-xs text-slate-500 truncate">
              <span className="hidden sm:inline">Cases</span>
              <span className="hidden sm:inline" aria-hidden="true">/</span>
              <span className="hidden sm:inline font-mono">ERP-FIN-2026-Q4</span>
              <span className="hidden sm:inline" aria-hidden="true">/</span>
              <span className="font-semibold text-slate-900 truncate">
                {currentNavItem.label}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => handleExportPdf()}
              className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export Compliance PDF</span>
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-8 max-w-[1440px] w-full mx-auto">
          {loadingState && auditLogs.length === 0 ? (
            <div className="bg-white border border-slate-200 rounded-lg p-12 text-center text-sm text-slate-500">
              Decrypting AES-256-GCM forensic vault...
            </div>
          ) : (
            <>
              {activeSection === 'overview' && (
                <OverviewDashboard
                  token={token}
                  auditLogs={auditLogs}
                  holisticFindings={holisticFindings}
                  crossRef={lastCrossRef}
                  bakAnalyses={bakAnalyses}
                  evidenceItems={evidenceItems}
                  vaultStatus={vaultStatus}
                  onNavigate={setActiveSection}
                  onRunHolisticScan={handleRunHolisticScan}
                  scanning={scanning}
                />
              )}

              {activeSection === 'audit-trail' && (
                <AuditTrailExplorer
                  token={token}
                  auditLogs={auditLogs}
                  onRunHolisticScan={handleRunHolisticScan}
                  scanning={scanning}
                  onExportCsv={handleExportAuditCsv}
                  onExportPdf={() => handleExportPdf()}
                  onAuditLogsUpdated={(logs) => setAuditLogs(logs)}
                />
              )}

              {activeSection === 'bak-analyzer' && (
                <BakAnalyzerView
                  bakAnalyses={bakAnalyses}
                  token={token}
                  onAnalysisComplete={(payload) => {
                    if (payload.bakAnalyses) setBakAnalyses(payload.bakAnalyses);
                    if (payload.evidenceItems) setEvidenceItems(payload.evidenceItems as EvidenceItem[]);
                    if (payload.auditLogs) setAuditLogs(payload.auditLogs as AuditEvent[]);
                    if (payload.vaultStatus) setVaultStatus(payload.vaultStatus as VaultStatus);
                  }}
                  onExportPdf={() => handleExportPdf()}
                />
              )}

              {activeSection === 'excel-crossref' && (
                <ExcelCrossRefView
                  token={token}
                  excelRegister={excelRegister}
                  lastCrossRef={lastCrossRef}
                  onCrossRefUpdated={(payload) => {
                    if (payload.excelRegister) setExcelRegister(payload.excelRegister);
                    if (payload.lastCrossRef) setLastCrossRef(payload.lastCrossRef);
                    if (payload.evidenceItems) setEvidenceItems(payload.evidenceItems as EvidenceItem[]);
                    if (payload.auditLogs) setAuditLogs(payload.auditLogs as AuditEvent[]);
                  }}
                  onExportCrossRefCsv={handleExportCrossRefCsv}
                />
              )}

              {activeSection === 'chain-of-custody' && (
                <ChainOfCustodyView
                  evidenceItems={evidenceItems}
                  vaultStatus={vaultStatus}
                  onVerifyChain={handleVerifyChain}
                  verifying={verifying}
                />
              )}

              {activeSection === 'forensic-enquiry' && (
                <ForensicEnquiryView
                  token={token}
                  activeReport={activeReport}
                  onReportGenerated={(report, updatedLogs) => {
                    setActiveReport(report);
                    if (updatedLogs) setAuditLogs(updatedLogs as AuditEvent[]);
                  }}
                  onExportPdf={(rpt) => handleExportPdf(rpt)}
                />
              )}

              {activeSection === 'deployment-security' && (
                <DeploymentSecurityView
                  token={token}
                  securityConfig={securityConfig}
                  onSecurityConfigUpdated={(cfg, updatedLogs) => {
                    setSecurityConfig(cfg);
                    if (updatedLogs) setAuditLogs(updatedLogs as AuditEvent[]);
                  }}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
