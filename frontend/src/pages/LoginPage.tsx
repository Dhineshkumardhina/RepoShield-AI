import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [email, setEmail] = useState('sarah.jenkins@xerova.com');
  const [password, setPassword] = useState('••••••••••••');
  const [role, setRole] = useState<'SecOps Lead' | 'Security Analyst' | 'Staff Engineer'>('SecOps Lead');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setIsLoading(true);

    try {
      const res = await login(email, role);
      if (res.success) {
        navigate('/dashboard');
      } else {
        setErrorMessage(res.error || 'Failed to authenticate.');
      }
    } catch {
      setErrorMessage('An unexpected error occurred during authentication.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleUseDemoAccount = (demoEmail: string, demoRole: 'SecOps Lead' | 'Security Analyst' | 'Staff Engineer') => {
    setEmail(demoEmail);
    setRole(demoRole);
    setErrorMessage(null);
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans">
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
        <Link to="/" className="inline-flex items-center gap-2 mb-4">
          <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-xs">
            <span className="material-symbols-outlined text-2xl">shield</span>
          </div>
          <span className="font-headline-md text-xl font-bold text-slate-900 tracking-tight">
            RepoShield AI
          </span>
        </Link>
        <h2 className="font-headline-lg text-2xl font-bold text-slate-900 tracking-tight">
          Enterprise Security Sign-In
        </h2>
        <p className="mt-1.5 text-xs text-slate-500 max-w-sm mx-auto">
          Sign in with your Xerova IAM SSO or operator access credentials.
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-6 sm:px-10 shadow-sm rounded-2xl border border-slate-200">
          {/* Security Notice Pill */}
          <div className="mb-6 p-3 rounded-lg bg-blue-50/70 border border-blue-200 text-xs text-blue-800 flex items-start gap-2">
            <span className="material-symbols-outlined text-base text-blue-600 shrink-0 mt-0.5">info</span>
            <div>
              <p className="font-semibold">Enterprise Session</p>
              <p className="mt-0.5 text-[11px] text-blue-700">
                Credentials are kept securely in memory for this session and are not stored in browser storage.
              </p>
            </div>
          </div>

          {errorMessage && (
            <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700 flex items-center gap-2">
              <span className="material-symbols-outlined text-base text-red-600">error</span>
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                Corporate Email
              </label>
              <div className="mt-1 relative">
                <input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-50 border border-slate-300 rounded-lg text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 focus:bg-white transition-all font-mono-md"
                  placeholder="analyst@xerova.com"
                />
              </div>
            </div>

            <div>
              <label htmlFor="role" className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                Authorized Role
              </label>
              <select
                id="role"
                value={role}
                onChange={e => setRole(e.target.value as any)}
                className="mt-1 w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-sm text-slate-900 focus:outline-none focus:border-blue-600 focus:bg-white transition-all"
              >
                <option value="SecOps Lead">SecOps Lead (Approval &amp; Auto-Merge)</option>
                <option value="Security Analyst">Security Analyst (Triage &amp; Verify)</option>
                <option value="Staff Engineer">Staff Engineer (View &amp; Sandbox Inspect)</option>
              </select>
            </div>

            <div>
              <label htmlFor="pass" className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                SSO Password / Token
              </label>
              <input
                id="pass"
                type="password"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="mt-1 w-full px-3.5 py-2 bg-slate-50 border border-slate-300 rounded-lg text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 focus:bg-white transition-all font-mono-md"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-2 py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm rounded-lg shadow-xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isLoading && <span className="material-symbols-outlined text-base animate-spin">progress_activity</span>}
              <span>{isLoading ? 'Verifying Session...' : 'Authenticate to Console'}</span>
            </button>
          </form>

          {/* Quick Demo Credentials */}
          <div className="mt-6 pt-5 border-t border-slate-200">
            <span className="font-mono-sm text-[10px] text-slate-500 uppercase tracking-wider block text-center mb-2.5 font-semibold">
              Quick Role Presets
            </span>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => handleUseDemoAccount('sarah.jenkins@xerova.com', 'SecOps Lead')}
                className="p-2 rounded border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors"
              >
                <span className="font-semibold text-xs text-slate-800 block truncate">Dr. S. Jenkins</span>
                <span className="text-[10px] text-slate-500 font-mono-sm">SecOps Lead</span>
              </button>
              <button
                type="button"
                onClick={() => handleUseDemoAccount('marcus.vance@xerova.com', 'Security Analyst')}
                className="p-2 rounded border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors"
              >
                <span className="font-semibold text-xs text-slate-800 block truncate">M. Vance</span>
                <span className="text-[10px] text-slate-500 font-mono-sm">Security Analyst</span>
              </button>
            </div>
          </div>

          <div className="mt-6 text-center text-xs text-slate-500">
            Don't have an enterprise workspace yet?{' '}
            <Link to="/register" className="font-semibold text-blue-600 hover:underline">
              Register Organization
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
