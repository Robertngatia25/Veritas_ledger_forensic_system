import React, { useState } from 'react';
import { Lock, ShieldCheck, KeyRound, UserPlus, AlertTriangle } from 'lucide-react';
import type { UserAccount, UserRole } from '../types/forensic';

interface LoginViewProps {
  onAuthenticated: (user: UserAccount, token: string) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onAuthenticated }) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('auditor@veritasledger.org');
  const [password, setPassword] = useState('ForensicAudit#2026');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState<UserRole>('External Investigator');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const endpoint = mode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const body =
        mode === 'login'
          ? { email, password }
          : { email, password, fullName, role };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Authentication failed.');
        return;
      }
      onAuthenticated(data.user, data.token);
    } catch {
      setError('Unable to reach forensic authentication server.');
    } finally {
      setLoading(false);
    }
  };

  const fillDemoAccount = (demoEmail: string, demoPassword: string) => {
    setMode('login');
    setEmail(demoEmail);
    setPassword(demoPassword);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col lg:flex-row">
      {/* Left Institutional Brief Panel */}
      <div className="lg:w-1/2 bg-slate-900 text-slate-100 p-8 lg:p-16 flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-3 text-slate-100 font-semibold text-lg tracking-tight">
            <ShieldCheck className="w-6 h-6 text-blue-400" />
            <span>Veritas Ledger</span>
          </div>

          <div className="mt-14 max-w-xl">
            <p className="text-xs font-medium text-blue-300 tracking-wide">
              Digital Forensics &amp; Compliance Platform
            </p>
            <h1 className="mt-3 text-3xl lg:text-4xl font-semibold tracking-tight text-white leading-tight [text-wrap:balance]">
              Cryptographic Audit Trail &amp; Enterprise RDBMS Integrity Workbench
            </h1>
            <p className="mt-4 text-sm lg:text-base text-slate-300 leading-relaxed">
              Every authentication attempt, database backup intake, timestamp verification, and compliance export is sealed in an AES-256-GCM encrypted vault with a continuous SHA-256 hash chain aligned to ISO/IEC 27037 and ALCOA+ standards.
            </p>
          </div>

          <div className="mt-12 grid grid-cols-1 sm:grid-cols-2 gap-6 max-w-xl border-t border-slate-800 pt-8">
            <div>
              <h3 className="text-sm font-semibold text-white">Holistic Timestamp Audit</h3>
              <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                Detects backdated entries, sequence-vs-clock inversions, deleted log gaps, and trigger bypasses.
              </p>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">RDBMS .bak Assessment</h3>
              <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                Inspects SQL Server MTF (.bak) and SQL dumps for schema posture, privilege leaks, and recovery risks.
              </p>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">Excel Cross-Referencing</h3>
              <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                Reconciles database transaction codes against online spreadsheets to expose amount or phantom variances.
              </p>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">ISO/IEC 27037 Custody</h3>
              <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                SHA-256 &amp; SHA-512 evidence fingerprinting, encrypted rest storage, and PDF/CSV audit packages.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-12 pt-6 border-t border-slate-800 text-xs text-slate-400 flex flex-wrap items-center gap-3">
          <span>AES-256-GCM Vault</span>
          <span aria-hidden="true">·</span>
          <span>PBKDF2-SHA256 Authentication</span>
          <span aria-hidden="true">·</span>
          <span>Gemini AI Forensic Enquiry</span>
        </div>
      </div>

      {/* Right Authentication Form */}
      <div className="lg:w-1/2 flex items-center justify-center p-6 sm:p-12">
        <div className="w-full max-w-md bg-white border border-slate-200 rounded-lg p-8">
          <div className="flex items-center justify-between border-b border-slate-200 pb-4">
            <div>
              <h2 className="text-xl font-semibold text-slate-900">
                {mode === 'login' ? 'Auditor Sign In' : 'Register Investigator'}
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Access is logged to the immutable chain of custody.
              </p>
            </div>
            <Lock className="w-5 h-5 text-slate-400" />
          </div>

          <div className="mt-5 flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError(null);
              }}
              className={`flex-1 py-2 px-3 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                mode === 'login'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError(null);
              }}
              className={`flex-1 py-2 px-3 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                mode === 'register'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              New Investigator
            </button>
          </div>

          {error && (
            <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md flex items-start gap-2.5 text-xs text-red-800">
              <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="mt-5 space-y-4">
            {mode === 'register' && (
              <>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1.5">
                    Full Name &amp; Credentials
                  </label>
                  <input
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="e.g. Jordan Mercer, CFE"
                    className="w-full px-3 py-2.5 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1.5">
                    Assigned Role
                  </label>
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value as UserRole)}
                    className="w-full px-3 py-2.5 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  >
                    <option value="Lead Forensic Auditor">Lead Forensic Auditor</option>
                    <option value="Compliance Officer">Compliance Officer</option>
                    <option value="External Investigator">External Investigator</option>
                  </select>
                </div>
              </>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Institutional Email
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="auditor@veritasledger.org"
                className="w-full px-3 py-2.5 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Passphrase
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Minimum 8 characters"
                className="w-full px-3 py-2.5 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 disabled:bg-blue-400 text-white text-sm font-medium rounded-md transition-colors flex items-center justify-center gap-2 whitespace-nowrap"
            >
              {mode === 'login' ? <KeyRound className="w-4 h-4" /> : <UserPlus className="w-4 h-4" />}
              <span>
                {loading
                  ? 'Verifying Credentials...'
                  : mode === 'login'
                    ? 'Sign In to Forensic Vault'
                    : 'Create Audited Account'}
              </span>
            </button>
          </form>

          {/* Authorized Evaluation Credentials */}
          <div className="mt-6 pt-5 border-t border-slate-200">
            <p className="text-xs font-medium text-slate-600">
              Pre-Provisioned Investigator Credentials
            </p>
            <div className="mt-2.5 grid grid-cols-1 gap-2">
              <button
                type="button"
                onClick={() => fillDemoAccount('auditor@veritasledger.org', 'ForensicAudit#2026')}
                className="text-left px-3 py-2 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-md transition-colors"
              >
                <div className="flex items-center justify-between text-xs font-medium text-slate-900">
                  <span>Lead Forensic Auditor</span>
                  <span className="font-mono text-slate-500">AUD-8841-UK</span>
                </div>
                <div className="mt-0.5 font-mono text-[11px] text-slate-500">
                  auditor@veritasledger.org · ForensicAudit#2026
                </div>
              </button>
              <button
                type="button"
                onClick={() => fillDemoAccount('compliance@veritasledger.org', 'Compliance#2026')}
                className="text-left px-3 py-2 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-md transition-colors"
              >
                <div className="flex items-center justify-between text-xs font-medium text-slate-900">
                  <span>Compliance Officer</span>
                  <span className="font-mono text-slate-500">CMP-4410-UK</span>
                </div>
                <div className="mt-0.5 font-mono text-[11px] text-slate-500">
                  compliance@veritasledger.org · Compliance#2026
                </div>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
